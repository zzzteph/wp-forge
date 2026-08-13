# WP-FORGE — WordPress plugin vulnerability & authorization methodology

WordPress plugins fail in a small set of very repeatable ways. This is the
catalog the `authz-analyzer` and `code-analyzer` agents work through, driven by
the plugin's project model (`ENTRYPOINTS.md`, `ROLES.md`, `AUTH.md`,
`model.json`). It is **model-driven**: every check is "for *this* hook and *these*
roles, what should happen vs. what the code actually enforces."

WordPress has almost no framework-level protection for plugins: a registered hook
runs whatever the plugin wrote. Three questions frame everything:
- **AuthN** — must the caller be logged in at all? (`nopriv` / REST
  `__return_true` = anyone on the internet.)
- **AuthZ (function level)** — may *this role* do this? (`current_user_can`)
- **Intent (CSRF)** — did the user mean to do this? (nonce / referer). A nonce is
  **not** authorization.

## The WordPress attack surface (entry points)
Enumerate every one of these that handles input; each is a place an attacker
reaches PHP:
| Registration | Reachable by | Notes |
|---|---|---|
| `add_action('wp_ajax_nopriv_<a>', cb)` | **anonymous** | `POST/GET /wp-admin/admin-ajax.php?action=<a>` |
| `add_action('wp_ajax_<a>', cb)` | **any logged-in user (incl. subscriber)** | *not* admin-only — a very common mistake |
| `add_action('admin_post_<a>' / 'admin_post_nopriv_<a>', cb)` | logged-in / anonymous | `/wp-admin/admin-post.php` |
| `register_rest_route(ns, route, ['permission_callback'=>…])` | per callback; `__return_true` = **anyone** | `/wp-json/…` or `/?rest_route=…` |
| `add_shortcode('<t>', cb)` | anyone viewing a post with the shortcode | attributes are attacker-influenced |
| `add_menu_page/add_submenu_page(...)` | the page's `capability` gates the *menu*, not the handler's actions | verify the handler re-checks |
| block `render_callback`, widgets | anyone viewing | request-derived attributes |
| `init` / `template_redirect` / `wp_loaded` handlers reading `$_GET/$_POST` | anyone | "listener" endpoints outside admin-ajax |
| cron (`wp_schedule_event`), upload handlers, import/export | varies | often process attacker data |

## The checks

### A. Missing authentication (CWE-306)
A sensitive action reachable with **no identity**: `wp_ajax_nopriv_*`,
`admin_post_nopriv_*`, REST `permission_callback => '__return_true'`, or a
`template_redirect`/`init` listener — reaching a state change or a sink. For every
entry point: is identity required on the path to the handler? Unauthenticated →
raise severity sharply.

### B. Broken function-level authz — vertical privilege escalation (CWE-862/285)
A lower tier reaches an action reserved for a higher one. The classic WordPress
bug: an action registered on `wp_ajax_<a>` (so **any subscriber** can call it)
that changes options, other users, or content — with **no `current_user_can`**.
Compare each entry point's *required* capability (from `ROLES.md` / the
sensitivity of what it does) to what the handler actually checks. Traps:
- `is_admin()` used as an auth check — it only means "admin area context."
- capability checked on the render/GET path but not on the state-changing
  `POST`/AJAX sibling.
- `add_submenu_page($cap, …)` gates the menu link, but the handler is callable
  directly via `admin-post`/`admin-ajax` without that capability.

### C. Missing / broken CSRF protection (nonce) (CWE-352)
State-changing action with no `wp_verify_nonce` / `check_admin_referer` /
`check_ajax_referer`, or the return value ignored. **A CSRF gap is reportable
when it yields a valuable effect** (change admin email/password, create an admin,
change plugin settings that lead to code exec, etc.). A missing nonce on a
trivial, low-value action is not HIGH/CRITICAL by itself — note it and move on.
**Nonce present but no capability check is still Broken Access Control (B).**

### D. Broken object-level authz — IDOR / BOLA (CWE-639/862)
Handler loads/edits an object by a caller-supplied id **without checking the
caller may access it**: `get_post`, `get_user_by`, `get_post_meta`, custom-table
lookups, `post__in`, order/entry ids. WordPress ids are **auto-increment
integers → trivially enumerable**, so an unscoped lookup is mass-harvestable.
Check every verb and nested references. Record `id_structure` (usually
"auto-increment integer"), `enumerable: yes`, and any **disclosure** (list/search
endpoints leaking ids).

### E. Mass assignment / privilege field tampering (CWE-915)
User-controlled payload sets fields that grant privilege or reassign ownership:
`role`, `wp_capabilities`, `user_level`, `default_role`, `users_can_register`,
`owner`/`author`, `post_author`. Look for `wp_update_user($_POST)`,
`update_user_meta($id,'wp_capabilities',$req)`, `update_option($name,$value)` with
request-controlled name/value, serializers/`$_POST` splatted into an update.

### F. Trusting client-controlled identity / capability (CWE-807/290)
Authorization decided on data the client sets: a `user_id`/`role` in the request
used without re-checking capabilities; `$_COOKIE` trusted as identity; a REST
`permission_callback` that returns true based on a request field. Identity must
come from the WP session/nonce, never from raw request fields.

### G. Enforcement in the wrong place / order (CWE-863)
The check exists but is ineffective: capability check *after* the side effect; a
`return`/early-exit that skips it; `check_ajax_referer` with `$die=false` and the
result ignored; nonce verified but action proceeds regardless.

### Injection classes (data-flow — see `sast/wp_signatures.md`)
- **SQL injection** — request data in `$wpdb->query/get_*` without
  `$wpdb->prepare` placeholders (or `prepare` with a variable format string).
- **RCE / code injection** — `eval`/`assert`/`create_function`, `preg_replace/e`,
  dynamic `call_user_func`/variable functions, `system`/`exec`/backticks on
  request data.
- **PHP object injection** — `unserialize()`/`maybe_unserialize()` on
  attacker-controlled bytes (needs a POP gadget for RCE; often present in bundled
  libs).
- **Path traversal / LFI / arbitrary file** — dynamic `include/require`,
  `file_get_contents`/`fopen`/`unlink`/`file_put_contents` with request paths;
  **unrestricted upload** (no extension/MIME allow-list, or writing into a
  web-served dir → `.php` upload = RCE).
- **SSRF** — `wp_remote_*`/`curl` with a user URL and no allow-list.
- **XSS** — request data echoed without `esc_*`/`wp_kses`; stored XSS rendered on
  an **admin** page is high value (CSRF → nonce theft → RCE chain).

## Confirming a finding (static → runtime)
1. **Static proof:** cite the entry point (the hook + `admin-ajax`/`rest` route),
   the missing/incorrect check (`file:line`), the capability/ownership expectation
   from the model, and the exact gap.
2. **Runtime proof** in the sandbox (`scripts/verify.py wp-up …`):
   - **authz / IDOR / priv-esc (two-principal):** `wp-login` as the **subscriber**
     (jar `B`) or fire **anonymous** (jar `anon`); perform the privileged action /
     read B's object; confirm success where WordPress should have returned
     `-1`/`403`. `[SECANAL]` `error_log` lines show whose capability/id the code
     ran with.
   - **missing-authn:** fire with no login (jar `anon`) against `admin-ajax.php`
     / the REST route.
   - **injection:** SQLi (error/boolean/time or a marker row), RCE (unique math /
     benign command), upload (drop + fetch a benign file), SSRF (loopback
     sentinel), traversal (read a blocked file). Benign proof only — no damage.

## Severity guidance (only CRITICAL/HIGH are recorded)
- **CRITICAL:** unauthenticated (or subscriber-level) SQLi / RCE / arbitrary file
  upload/read / object injection; unauthenticated privilege escalation or admin
  account creation; unauthenticated arbitrary options update
  (`users_can_register` + `default_role=administrator` = takeover).
- **HIGH:** authenticated-but-low-privilege (subscriber) version of the above;
  authenticated IDOR on other users' PII/actions with enumerable ids; stored XSS
  executing in an admin session; CSRF leading to a valuable privileged change.
- **MEDIUM/LOW (do NOT record):** nonce-only gaps on low-value actions,
  self-XSS, reflected XSS requiring implausible interaction with no privileged
  impact, defense-in-depth nits, bare weak-crypto with no exploit,
  info-disclosure of non-sensitive data. Note them as `dismissed`; never report.

**Modifiers:** *who can reach it* (anonymous > subscriber > admin) and *active
installs* (blast radius) raise priority. WordPress ids are enumerable by default,
so IDOR rarely gets the "random id" discount. Always state the reason in
`severity_rationale`.

## What is NOT a finding
A real capability check upstream (defense-in-depth only); intentionally public,
non-sensitive endpoints; UI-only hiding where the handler also enforces;
vulnerabilities only in `vendor/` code that **no plugin entry point reaches**.
Note these as dismissed with the reason — don't inflate the count.
