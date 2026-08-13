# WP-FORGE — WordPress / PHP grep signature guardrail (Layer 0)

**Purpose.** A fast, dependency-free hot-spot finder for **WordPress plugins**.
These are `ripgrep` patterns for *dangerous PHP sinks*, *untrusted sources*, and
*WordPress authorization markers*. They **do not prove a vulnerability** — they
tell an agent **where to look**. The agent then confirms whether a source reaches
a sink without adequate sanitization/escaping/authorization (taint +
reachability). **grep = audit recall; the agent supplies the taint.**

**Reachability first.** We only care about sinks reachable **from a real
WordPress entry point** — a registered hook in `model.json`: shortcode,
`wp_ajax_*` / `wp_ajax_nopriv_*`, `admin_post_*`, `register_rest_route`, admin
page, block `render_callback`, widget, cron consumer, or an `init` /
`template_redirect` handler that reads request data. A sink in dead code, tests,
or a **vendored/third-party library** (`vendor/`, bundled libs) that no plugin
entry point reaches is **discarded — not reported**.

**Scope: PHP only.** Report only vulnerabilities in the plugin's PHP. Match with
`-g '*.php'`. Skip `vendor/`, `node_modules/`, and minified assets unless a plugin
handler actually calls into them.

## How the workflow uses this file
1. From the plugin shape, confirm PHP (nearly always) and note the framework
   (plain WP hooks, sometimes a bundled framework).
2. Run each relevant **sink** pattern over the scope (whole plugin on baseline;
   changed files + neighbours on incremental):
   ```
   rg -n --no-heading -e '<pattern>' target/wordpress.org/plugins/<slug>/ -g '*.php'
   ```
3. For each hit, grep the **sources** nearby to see if attacker input feeds it.
4. **Drop every hit not user-reachable** from a `model.json` entry point.
5. Hand survivors to `code-analyzer` / `authz-analyzer` as *candidates to confirm
   or dismiss*. **Never** store a raw grep hit as a finding.

---

## Untrusted sources (taint origins)
```
-e '\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b'
-e 'file_get_contents\(\s*["'"'"']php://input'
-e '\$HTTP_RAW_POST_DATA'
-e '\$request->get_(param|json_params|body_params|query_params|url_params|file_params)\('   # REST
-e '(shortcode_atts|\$atts)\b'                          # shortcode attributes
-e '\$_SERVER\[["'"'"'](HTTP_|REQUEST_|QUERY_|PHP_SELF|REMOTE_)'
-e 'getallheaders\(|apache_request_headers\('
```
WordPress often passes request data through `wp_unslash()` first — that removes
slashes, **it does not sanitize**. Treat `wp_unslash($_POST[...])` as tainted.

---

## 1. SQL injection — CWE-89 (the #1 WP plugin bug)
```
-e '\$wpdb->(query|get_results|get_var|get_row|get_col|prepare)\('
-e '\$wpdb->(query|get_results|get_var|get_row|get_col)\([^)]*\$'     # interpolated var in query
-e '"\s*(SELECT|INSERT|UPDATE|DELETE|REPLACE)\b[^"]*\$'               # -i  string-built SQL
-e '(SELECT|INSERT|UPDATE|DELETE)\b[^;]*\.\s*\$'                      # -i  concatenated SQL
-e '\$wpdb->prepare\([^,]*\$[^,]*,'                                   # prepare with var in the FORMAT (broken)
```
Use `-i` for the SQL-keyword patterns. **Confirm:** a source flows into the query
string instead of `$wpdb->prepare('... %s %d ...', $args)` placeholders. A
`$wpdb->prepare` whose *first* argument is built from a variable is still
injectable. `esc_sql()` on a value used outside quotes is **not** sufficient.

## 2. OS command / code execution — CWE-78/94/95
```
-e '\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\('
-e '`[^`]*\$'                                         # backtick exec with a var
-e '\b(eval|assert|create_function)\('
-e 'preg_replace\(\s*["'"'"'][^"'"'"']*e["'"'"']'      # /e modifier -> code exec
-e 'call_user_func(_array)?\([^)]*\$_(GET|POST|REQUEST)'   # dynamic callback from input
-e '\$\$?[a-zA-Z_]\w*\s*\('                            # variable function  $fn(...)
```
**Confirm:** an untrusted source is interpolated into the command/callback.

## 3. PHP object injection (unsafe deserialization) — CWE-502
```
-e '\bunserialize\('
-e 'maybe_unserialize\('
```
**Confirm:** the serialized bytes are attacker-controlled (request/cookie, or an
option/meta value an attacker can set earlier). Chains to RCE if a POP gadget is
present in the plugin or a bundled library.

## 4. Path traversal / LFI-RFI / arbitrary file ops — CWE-22/73/98
```
-e '\b(include|include_once|require|require_once)\b[^;]*\$'    # dynamic include
-e '\b(fopen|file_get_contents|readfile|file|fpassthru|highlight_file|show_source)\([^)]*\$'
-e '\b(file_put_contents|fwrite|fputs)\([^)]*\$'
-e '\b(unlink|rmdir|rename|copy|mkdir|chmod)\([^)]*\$'
-e 'move_uploaded_file\('
-e '\$_FILES\['
-e '\.\./|%2e%2e'                                              # traversal markers
```
**Confirm:** a source reaches the path with no `sanitize_file_name` / allow-list /
`realpath` containment. For uploads: no extension/MIME allow-list, or the file
lands in a web-reachable dir (`wp-content/uploads/...`) → RCE via `.php` upload.

## 5. Arbitrary options / user-meta / privilege escalation — CWE-269/862
```
-e 'update_option\([^)]*\$_(GET|POST|REQUEST)'
-e '(update|add)_user_meta\([^)]*\$_(GET|POST|REQUEST)'
-e 'wp_update_user\(|wp_insert_user\(|add_role\(|->add_cap\(|set_role\('
-e 'update_option\(\s*\$'                                       # option NAME from a variable
```
**Confirm:** request data controls the option/meta **name or value**, or the
`role`/capabilities on a user — reachable without the required capability. Setting
`default_role`/`users_can_register`, or a user's `wp_capabilities`, is admin
takeover.

## 6. SSRF — CWE-918
```
-e 'wp_remote_(get|post|request|head|retrieve_body)\([^)]*\$'
-e 'curl_setopt\([^)]*CURLOPT_URL'
-e '\b(fsockopen|stream_socket_client|fopen|file_get_contents)\([^)]*\$'   # with http(s) URL
```
**Confirm:** the URL/host comes from user input with no allow-list / egress
control (loopback/metadata reachable).

## 7. XSS — reflected & stored — CWE-79
```
-e '\becho\b[^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
-e '\bprint\b[^;]*\$_(GET|POST|REQUEST)'
-e 'echo\s+\$'                                          # echo of a variable (check escaping)
-e '_e\(|esc_html_e\(|printf\(|sprintf\('              # check args are escaped
-e '(add_query_arg|remove_query_arg)\('                # unescaped -> reflected XSS in admin
```
**Confirm:** untrusted data reaches HTML/attribute/JS/URL context **without** the
right escaper (`esc_html` / `esc_attr` / `esc_url` / `esc_js` / `wp_kses`). Stored
XSS rendered on an **admin** page (settings echoed back) is high value (admin
session → CSRF/nonce theft → RCE). Note `add_query_arg`/`remove_query_arg` echo
the current URL unescaped.

## 8. Weak crypto / secrets — CWE-327/338/798 (only if it enables a real exploit)
```
-e '\b(md5|sha1)\(|MODE_ECB|DES\b|mcrypt_'
-e '\b(mt_rand|rand|uniqid|wp_rand)\('                  # non-CSPRNG for tokens
-e '(api[_-]?key|secret|token|password)\s*=\s*["'"'"'][^"'"'"']{8,}'   # -i hardcoded
```
**Confirm:** the weak primitive guards something sensitive (a password-reset /
nonce-substitute / API token). A **bare MD5/SHA1 with no security impact is NOT a
finding.** Predictable password-reset or auth tokens (from `mt_rand`/`uniqid`) →
account takeover = HIGH/CRITICAL.

---

## Authorization markers — for the authz-analyzer (the map, not sinks)
Grep these to locate **where WordPress access control is (and isn't) enforced**,
then diff protected vs. unprotected handlers. See `docs/WP_METHODOLOGY.md`.
```
# entry-point registrations (attack surface)
-e "add_action\(\s*['"'"'\"]wp_ajax_nopriv_"      # UNAUTHENTICATED ajax
-e "add_action\(\s*['"'"'\"]wp_ajax_"             # logged-in ajax (any role incl. subscriber)
-e "add_action\(\s*['"'"'\"]admin_post(_nopriv)?_"
-e 'register_rest_route\('
-e 'add_shortcode\(|add_(menu|submenu|options|management)_page\('
# checks that DO enforce (their ABSENCE near a state change is the finding)
-e 'current_user_can\(|user_can\(|current_user_can_for_blog\('
-e 'wp_verify_nonce\(|check_admin_referer\(|check_ajax_referer\('
-e 'is_user_logged_in\(|is_admin\(\)'             # is_admin() is NOT an auth check (admin *area*, not capability)
-e "permission_callback"                          # REST: __return_true means NO authz
-e 'sanitize_(text_field|key|file_name|email|user)|wp_kses|absint|intval|esc_'
```
**For each entry point in `model.json`:** is there a **nonce/referer** check on
state-changing actions? a **capability** check (`current_user_can('manage_options'
| 'edit_posts' | …)`) matching the sensitivity? Is it registered as `nopriv`
(reachable by anyone) or REST with `permission_callback => '__return_true'`? Are
sibling actions under the same handler protected inconsistently?

Common WordPress-specific traps:
- `is_admin()` checks the **admin area context**, not the user's capability — it
  is **not** an authorization check.
- `wp_ajax_*` (without `nopriv`) is reachable by **any logged-in user including a
  subscriber** — not "admins only."
- A nonce proves intent (anti-CSRF), **not** authorization — a valid nonce plus a
  missing `current_user_can` is still broken access control.
- `check_ajax_referer(..., false)` / `wp_verify_nonce` return value ignored =
  no protection.

---

## Output contract (what the workflow produces from this file)
A hotspot list, each: `{class, cwe, file, line, sink, has_nearby_source,
user_reachable, entrypoint, pre_auth, why_it_matters}` — **only user-reachable
PHP sinks**, ranked reachable-with-source and pre-auth first. Non-reachable hits
are dropped. These become the `sast_candidates` handed to the analysis agents.
Nothing here is a finding until an agent confirms the flow.
