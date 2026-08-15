# WP-FORGE — WordPress plugin security workflow (self-contained brain)

**You point Claude Code at this file; it analyzes WordPress.org plugins for you.**
This is the single source of truth for one WP-FORGE run. It works **out of the
box** — no Claude skill or custom agent needs to be installed. Everything it
needs is in this folder: helper scripts in `scripts/` (`wp.py`, `wpdb.py`,
`pipeline.py`, `verify.py`), the PHP/WordPress grep guardrail in
`sast/wp_signatures.md`, the WordPress authorization catalog in
`docs/WP_METHODOLOGY.md`, and role briefs in `.claude/agents/*.md` (read as plain
files when not registered as agents).

> **How to run it**
> - Interactive (Claude console or VS Code extension), from this folder:
>   *"Follow `opt/wp_workflow.md`"* (optionally *"…for plugin `<slug>`"* or
>   *"…batch of N"*).
> - Headless / CI: `claude -p "Follow opt/wp_workflow.md"
>   --dangerously-skip-permissions`.
> - The optional `/wp-forge` skill is just a shortcut that says exactly the above.

WP-FORGE runs unchanged on **Linux and Windows** — every helper is stdlib Python
and Docker. Use `python3` on Linux/macOS, `python` on Windows; substitute
whichever launcher exists. Nothing else is OS-specific.

---

## 0. What one run does
Fetch the current wordpress.org plugin directory → pick a batch of the
**most-recently-updated** plugins not already analyzed at their current version →
for each: download the archive, model it, hunt for **HIGH/CRITICAL PHP**
vulnerabilities, **prove them in a live WordPress+MySQL sandbox**, record them in
the durable DB, and **report locally** (console + a per-plugin
`notifications.log`). Notify-only — WP-FORGE never touches the plugins' authors or
repos and contacts no external service.

```
sync catalog (wp.py sync) ─► next batch (wp.py next-batch) ─► per plugin:
   prep (download + extract + shape the LATEST)  → full BASELINE analysis (always)
   A. Comprehension → durable model   (idea · entry points · roles · authn/authz)
   B. Grep guardrail                  (sast/wp_signatures.md → ranked hotspots)
   C. Authorization analysis          (nonce/CSRF, capability, nopriv AJAX, REST authz)
   D. Data-flow analysis              (SQLi via $wpdb, RCE, LFI, upload, SSRF, XSS)
   E. Verify in WordPress sandbox     (install plugin, two-principal / injection PoC)
   F. Reconcile + notify (local)      (new vs known vs mitigated)
   G. Record to DB (wp.py record) — mark analyzed at this version
loop to next plugin ─► cycle summary + nuke sandbox + wipe scratch (archives/, target/)
```

## 1. Guardrails (read before doing anything)
- **Notify-only + fully local.** Report to the person by printing to the console
  and appending to `knowledge/<slug>/notifications.log` (via `pipeline.py notify`).
  Never contact a plugin author, open an issue, publish anything, or reach an
  external service. In CI, exit 0 no matter what.
- **Report bar: CRITICAL/HIGH, PHP, exploitable AND valuable — nothing else.**
  Only surface issues a real attacker can exploit for real impact in a default
  WordPress install of the plugin. **Do not record or report MEDIUM/LOW or
  theoretical/best-practice issues** (a bare MD5, missing headers, a nonce-only
  gap with no sensitive action, verbose errors) unless they compose into a
  concrete CRITICAL/HIGH exploit. When value is doubtful, drop it. **Zero
  findings for a plugin is a fine, honest result.** **Prioritise unauthenticated
  bugs and apply the auth penalty (below).**
- **PHP only.** The vulnerability must live in the plugin's PHP. JS/CSS/build
  assets are out of scope except as a source that reaches a PHP sink.
- **User-reachable only.** Only code on a call path from a real WordPress entry
  point (a registered hook: shortcode, `wp_ajax_*` / `wp_ajax_nopriv_*`,
  `admin_post_*`, REST route, admin page, widget, block render, cron, filter that
  handles request data, template). Dead code, tests, and vendored libs no
  entry point reaches are out of scope.
- **Never ask questions — ever.** In any mode, make the most reasonable choice,
  log it, and keep going. Never wait for input.
- **Stay in scope.** Touch only this folder and the Docker sandbox. Never modify
  or re-upload a plugin. The only outbound traffic is the WP.org API + archive
  download; findings are reported locally, never sent anywhere.
- **Serial by design — one plugin, one pass, at a time.** No parallelism anywhere:
  never process more than one plugin at once, never fan out multiple analysis
  subagents, never launch background jobs / driver scripts / plugin "blocks". Each
  plugin is downloaded and analyzed to completion before the next begins.
  `analysis.max_verify_per_cycle` is a safety cap on verification attempts;
  `wp.batch_size` only sizes a bare, unscoped `/wp-forge`. Prefer highest severity /
  most reachable first.
- **Idempotency.** The DB (`scripts/wpdb.py`) tracks which `slug@version` are
  analyzed and which findings were reported. Re-analyze a plugin only when a new
  version exists. Only **new** vulns and **one-time mitigations** are sent.
- **Latest-only; never hoard sources.** Always analyze the plugin's **current
  version** as a full baseline — we don't diff against or keep prior versions.
  `archives/` (the downloaded zip) and `target/` (the extracted source) are
  **disposable scratch**: delete each plugin's copy once it's recorded (§9) and
  wipe both dirs at cycle end (§10). Everything is re-fetchable from wp.org, so
  nothing plugin-sized is kept between runs. (The one deliberate exception is a
  HIGH/CRITICAL finding's PoC bundle, which self-contains its exact plugin
  version so the bug stays reproducible — §8.)
- **Every HIGH/CRITICAL ships a runnable PoC + Docker bundle.** No HIGH/CRITICAL
  finding is complete without a `docker-compose.yml` + `poc.py` that stands the
  bug up and proves it with a single command (`python poc.py`). Scaffold it for
  **every** HIGH/CRITICAL — whether or not live verification succeeded (§8).
- **Always tear down** the Docker sandbox at the end (§9), even on error.
- **Time-box.** If a plugin won't install/run after reasonable effort, record
  HIGH/CRITICAL candidates as unverified and move on to the next plugin.
- **Hang = skip; never intervene by hand.** Every per-plugin step is bounded — the
  downloader self-caps time and size (`wp.py` raises and the plugin is skipped),
  and you must time-box any scan/verify (`timeout <s> …`). If a step hangs or
  fails — a slow/huge download, a scan that won't finish, a plugin that won't
  install — **mark that one plugin `error`
  (`python scripts/wpdb.py set-status --slug <slug> --status error --error "<why>"`)
  and move to the next**; it is retried on a later run. Do
  **not** `pkill`/`kill` processes, inspect process trees, edit or "harden"
  driver/runner scripts, `rm` anything outside this plugin's own `archives/` +
  `target/` scratch, restart the block, or pause to ask what to do — those
  improvisations are exactly what make bulk runs unreliable. A per-plugin failure
  is a *skipped item, not a stop*; the only "done" signal is `next-batch`
  returning `[]`.
- **Show progress.** A status line per phase to stdout (and appended to the log),
  tagged as a progress line via `notify --silent` if `report.progress`.

### Severity scoring — unauthenticated is the target
The whole point is **pre-auth** bugs (an attacker with **no account**). Rate each
finding's intrinsic severity, then apply an **auth penalty** for the *lowest*
privilege that can reach it:

| Access required to exploit | Severity change |
|---|---|
| **Unauthenticated** — `wp_ajax_nopriv_*`, REST `permission_callback => __return_true`, public shortcode/route | **no change** (the target) |
| **Any logged-in account** — subscriber / customer / contributor / author … | **−1 level** |
| **Admin / equivalent high privilege** | **−2 levels** |

Levels are `CRITICAL → HIGH → (below the bar → drop)`. So a subscriber-only
CRITICAL stays **HIGH**; a subscriber-only HIGH becomes MEDIUM → **dropped**; an
admin-only finding drops **−2** → out of scope. Net: **admin-only bugs almost
always fall out of scope, and low-privilege bugs must start at CRITICAL to survive.**

**Exceptions — keep full severity (no penalty) even when authenticated:**
- **RCE** (remote code execution), or
- **SQL injection**, or
- **Trivially-obtainable account** — the plugin, or a default install, lets anyone
  self-register the required role (open registration, a `wp_ajax_nopriv_*`
  register/login action, a public "create account" flow). If the account is free to
  get, the bug is effectively **unauthenticated** — no penalty. (WooCommerce stores
  with customer registration on are the common case.)

Record the **adjusted** severity as the finding's `severity`, and always name the
required access in `reachability` (`pre-auth` / `subscriber` / `admin`). Hunt,
prioritise, and verify the pre-auth findings first.

### How to run the analysis roles (works with or without installed agents)
Each role has a **brief** at `.claude/agents/<role>.md`. To run one, spawn a
subagent with the Agent tool:
- **Preferred:** `subagent_type: "<role>"` (recon-cartographer / authz-analyzer /
  code-analyzer / finding-verifier) if available.
- **Always-works fallback:** `subagent_type: "general-purpose"` with a prompt
  beginning *"Read `.claude/agents/<role>.md` and follow it exactly as your
  instructions, plus `docs/WP_METHODOLOGY.md` and `sast/wp_signatures.md` for
  WordPress specifics,"* then the assignment.
- **Last resort** (no Agent tool): do the role's work inline following the brief.
Run the roles **one at a time** — at most one subagent in flight, never multiple
Agent calls in a single message. No parallelism anywhere; doing the work inline
(no subagent at all) is perfectly fine and often simplest.

## 2. Preflight — refresh the catalog & pick the batch
```bash
python scripts/wpdb.py init                                  # ensure the DB exists
python scripts/wp.py sync --browse updated --pages <wp.catalog_pages> --per-page <wp.per_page>
python scripts/wp.py next-batch --count <wp.batch_size>      # plugins due for (re)analysis, newest first
```
`next-batch` returns plugins never analyzed, or whose current version differs
from `analyzed_version`, ordered by `last_updated`.

**Scoping the run:**
- If the user named a specific `<slug>` (e.g. `/wp-forge woocommerce`), skip
  sync/next-batch and analyze just that plugin.
- **Window scopes — `today` / `week` / `month`** (via `/wp-forge today|week|month`,
  or `config.yaml → wp.since`): sync only that window and **drain it continuously**
  (see below) — analyze every plugin updated in the window, batch after batch,
  **never pausing to ask anything**. `today` = updated today, `week` = the last
  7 days, `month` = the last 30 days; `wp.py` resolves the keyword to a date:
  ```bash
  python scripts/wp.py sync --since <today|week|month>       # fill the DB with just that window's releases
  python scripts/wp.py next-batch --count <wp.batch_size> --updated-since <today|week|month>
  ```
  `sync --since` pages the `updated` feed and stops once it falls before the
  window's start (the feed is newest-first). `newly_published` counts plugins
  whose first publish was in-window. An explicit ISO date (`YYYY-MM-DD`) works too.
- Otherwise use the plain `sync` above (newest `wp.catalog_pages` pages).

**Then process the scope strictly ONE PLUGIN AT A TIME — serial, in THIS session.**
There is **no parallelism and no external orchestration** anywhere in a run. You
download one plugin, run §3–§9 on it to completion, record it, discard its scratch,
and only then move to the next slug. Do **not** spawn background jobs (`nohup`,
trailing `&`, a `driver`/`runner`/`weekly_*` script), process "blocks" of plugins,
or work on more than one plugin at once. The whole run is a plain sequential loop
you drive yourself, in-session.

### Drain mode — analyze the WHOLE scoped set unattended (never ask to continue)
A window scope (`today` / `week` / `month`), an explicit *"analyze all"* /
`/wp-forge all`, or `config.yaml → wp.drain: true` drains by default: analyze
*every* plugin in the scope, **one after another**, and **never** pause to ask
whether to continue, confirm, or clarify. `/wp-forge today` means every plugin
updated today — but still one at a time, never 3/5 and never a background batch.
`wp.batch_size` only applies to a bare, unscoped `/wp-forge` (§10). Get the list,
then walk it:
```bash
# <window> is today|week|month (or an ISO date); omit --updated-since for the whole catalog
python scripts/wp.py pending    --updated-since <window>                 # N = how many remain in-scope
python scripts/wp.py next-batch --count <N> --updated-since <window>     # the full list of slugs to walk
```
Walk the returned slugs **sequentially**:
1. Take the next slug; run §3–§9 fully (download → model → hunt → verify → record).
2. Discard that plugin's scratch, emit a one-line progress ping, take the next slug.
3. At the end of the list, re-query `next-batch`; if it returns `[]`, **stop** — the
   scope is fully analyzed. Each recorded (or `error`-skipped) plugin drops out of
   the queue, so it shrinks to `[]` on its own.
That empty result is the only "am I done?" signal — you never ask. This is
resumable: if the run is interrupted, starting again continues from what's left.
The one-batch-then-stop rule below (§10) applies only to a bare, unscoped
`/wp-forge` (no window) — window/`all`/`wp.drain` runs always drain.

## 3. Per-plugin preflight — bind the plugin & download it
Every plugin is keyed like the rest of the pipeline: its "repo url" is
`https://wordpress.org/plugins/<slug>/`, so all per-plugin state
(`target/`, `state/`, `knowledge/wordpress.org/plugins/<slug>/`) is keyed to it.
`wp.py --slug` sets this for you; on **every** `pipeline.py` call in the phases
below, set the same env inline so findings land under the right plugin:
```bash
# bash
SECANAL_TARGET_REPO="https://wordpress.org/plugins/<slug>/" python scripts/pipeline.py <...>
# PowerShell (single call)
$env:SECANAL_TARGET_REPO="https://wordpress.org/plugins/<slug>/"; python scripts\pipeline.py <...>
```
Download + extract + version-diff + shape in one call. `prep` is self-limiting
(§1), but wrap it in `timeout` too so extraction/shape can never stall — and if it
fails or times out, **skip this plugin and go straight to the next** (never retry
in place, never investigate, never ask):
```bash
if ! timeout 150 python scripts/wp.py prep --slug <slug>; then
    python scripts/wpdb.py set-status --slug <slug> --status error --error "prep failed/timeout"
    continue            # next plugin — a skipped item is not a stop (§1)
fi
```
Read the JSON: `version`, `shape`, `plugin_root` (the extracted plugin at
`target/wordpress.org/plugins/<slug>/`). **Always analyze the current version as a
full BASELINE** — model and analyze the whole plugin every time. We do **not**
diff against or load a prior version (`prev_version`/`changed_files` are ignored);
we only care about what's exploitable in the plugin as it ships today. If the DB
already holds findings for an earlier version of this slug, reconcile the fresh
results against those DB records (§8) — not against stored files, which we don't
keep.

Mark it in progress:
`python scripts/wpdb.py set-status --slug <slug> --status analyzing`.
(Status becomes `downloaded` after prep, `analyzing` during the phases, `error` on
a skipped failure — retried on a later run — and `analyzed` after `wp.py record`
in §9.)

## 4. Phase A — Comprehension → durable plugin model
Produce/refresh `knowledge/wordpress.org/plugins/<slug>/{PROJECT,ENTRYPOINTS,ROLES,AUTH}.md`
and `model.json`. Follow the **recon-cartographer** brief, applied to WordPress:
- **idea:** what the plugin does; its data/actions worth attacking (options,
  user data, uploads, payments, admin actions).
- **entry points (WordPress attack surface):** enumerate every registered hook
  that handles input —
  - `add_shortcode(...)` handlers;
  - `add_action('wp_ajax_<a>', ...)` (logged-in) and especially
    `add_action('wp_ajax_nopriv_<a>', ...)` (**unauthenticated**);
  - `add_action('admin_post_<a>', ...)` / `admin_post_nopriv_<a>`;
  - `register_rest_route(...)` — record its `permission_callback`;
  - admin menu pages (`add_menu_page`/`add_submenu_page` → handler);
  - `add_action('init'/'template_redirect'/'wp_loaded', ...)` that reads
    `$_GET/$_POST/$_REQUEST`;
  - block `render_callback`, widgets, `do_action`/`apply_filters` on request data,
    file upload handlers, cron (`wp_schedule_event`) consumers.
  For each: input params, whether a **nonce** is checked, the **capability**
  required (`current_user_can`), and whether it's reachable **pre-auth**
  (`nopriv`/REST `__return_true`) or post-auth.
- **roles:** WordPress roles/caps in play (anonymous, subscriber, author,
  editor, administrator) and which the plugin's actions require vs. enforce.
- **authn/authz:** how the plugin authenticates the caller (it usually relies on
  WP cookies + nonces + capabilities) and **where those checks are missing**.

Write `model.json` deterministically from the cartographer fragment(s). Use the
schema in `.claude/agents/recon-cartographer.md`; for `entrypoints[].kind` use
`shortcode|ajax|ajax_nopriv|admin_post|rest|admin_page|hook|cron|upload`, and add
per entry point: `nonce_checked` (bool), `capability` (string or null),
`pre_auth` (bool). `entrypoints[].files` maps changed files back to entry points
on incremental runs.

## 5. Phase B — Grep guardrail (PHP/WordPress hotspots)
Run the signature sweep from `sast/wp_signatures.md` with ripgrep over the scope
(whole plugin on baseline; `changed_files` + neighbours on incremental):
```bash
# Bounded + focused: server-side PHP only, skip vendored/generated/minified bulk,
# cap file size, and time-box the sweep so a giant/minified plugin (e.g. w3-total-cache)
# can't stall the scan with pathological lines. These guards are built in — do NOT
# hand-tune regex or kill a slow grep; if it still times out, skip the plugin (§1).
timeout 120 rg -n --no-heading -e '<sink-pattern>' \
  target/wordpress.org/plugins/<slug>/ \
  -g '*.php' --max-filesize 2M \
  -g '!**/{vendor,node_modules,dist,build,assets,languages,tests}/**' \
  -g '!**/*.min.*'
```
For each hit, grep nearby **sources** (`$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES`,
`file_get_contents('php://input')`, REST `$request->get_param`) to rank
source-reachable hits first, then **drop every hit not reachable from a
`model.json` entry point.** Also run the **authorization markers** section against
every entry point (missing `wp_verify_nonce`/`check_admin_referer`,
missing `current_user_can`, `wp_ajax_nopriv_*`, `permission_callback` =>
`__return_true`). **Output = a ranked hotspot list of user-reachable candidates,
not findings.**

## 6. Phase C — Authorization analysis (highest yield for WP plugins)
Follow the **authz-analyzer** brief and `docs/WP_METHODOLOGY.md`. Run this as a
**single** authz pass for the plugin (one subagent, or inline) — no splitting into
parallel workers — given the model + the authz hotspots + (incremental)
`changed_files`. Walk every entry point for the WordPress classes:
- **Missing/incorrect capability check** (broken function-level authz / priv-esc)
  — an action reserved for admin reachable by a subscriber or anonymous.
- **Missing nonce / CSRF** on a state-changing action **that also lacks a real
  capability gate** (nonce-only is weak; report when it yields a valuable
  privileged action, options change, account takeover, etc.).
- **Unauthenticated AJAX / REST** (`wp_ajax_nopriv_*`, `admin_post_nopriv_*`,
  REST `permission_callback => '__return_true'`) reaching a sensitive
  action/sink.
- **IDOR / object access** via `post__in`, `get_post`, meta/option ids, user ids
  with no ownership/cap check.
- **Arbitrary options / user-meta update, privilege escalation** (`update_option`,
  `update_user_meta`, `wp_update_user` with `role`/caps from request).
Each keeper carries a **two-principal PoC** (principal A = subscriber or
anonymous, B/admin = the privileged effect). These become the finding's fields.

## 7. Phase D — Data-flow analysis (PHP injection classes)
Follow the **code-analyzer** brief with `sast/wp_signatures.md`. Run this as a
**single** data-flow pass for the plugin (one subagent, or inline) — walk the hot
areas one after another, never fanned out in parallel. Trace untrusted input →
dangerous sink for the WordPress/PHP classes:
- **SQL injection** — `$wpdb->query/get_results/get_var/get_row/prepare` with
  interpolated input instead of `$wpdb->prepare` placeholders.
- **RCE / code injection** — `eval`, `assert`, `create_function`,
  `call_user_func(_array)` on request data, `preg_replace('/e')`, dynamic
  `include/require`.
- **PHP object injection** — `unserialize()` on request/option data.
- **Path traversal / LFI / arbitrary file read-write-delete** — `include/require`,
  `file_get_contents`, `fopen`, `unlink`, `file_put_contents`, `move_uploaded_file`
  with request-controlled paths; **unrestricted file upload**.
- **SSRF** — `wp_remote_get/post`, `curl_exec`, `file_get_contents($url)` with a
  user URL.
- **Stored / reflected XSS** — request data echoed without
  `esc_html/esc_attr/esc_url/wp_kses`, or stored via option/meta and rendered
  unescaped **on a privileged page** (admin XSS → CSRF-to-XSS-to-RCE chains).
Each finding needs a concrete `entrypoint → sink` reachability argument, its auth
state (pre-auth / subscriber / admin), and an `instrument_hint`.

**Record only keepers that clear the bar** (dedupe first with `get --brief`):
```bash
SECANAL_TARGET_REPO="https://wordpress.org/plugins/<slug>/" python scripts/pipeline.py add-finding --json '{
  "title":"...", "severity":"CRITICAL|HIGH", "category":"sql-injection|rce|object-injection|file-upload|path-traversal|ssrf|xss|priv-esc|missing-authz|idor|csrf|...",
  "file":"...", "line":0, "cwe":["CWE-..."], "entrypoint":"wp_ajax_nopriv_foo",
  "reachability":"entrypoint -> ... -> sink (pre-auth?)", "poc":"...",
  "instrument_hint":"file:line + variable" }'
```
Do **not** store MEDIUM/LOW or low-value issues — dismiss silently.

## 8. Phase E — Verify in a live WordPress sandbox
Only if `verify.enabled` and Docker is available. **Verify EVERY recorded
HIGH/CRITICAL finding for this plugin** (`new`/`triaged`) — not just a top-N
slice; a plugin rarely has more than a handful that clear the bar, and an
unverified claim is worth far less than a proven one. (`max_verify_per_cycle` is
only a safety cap for a pathological plugin with dozens of candidates — if you hit
it, verify highest-severity first and log what was deferred.) Mark each
`verifying`, then spawn a **finding-verifier** subagent. Stand up WordPress and
install the plugin, then prove the flow:
```bash
python scripts/verify.py wp-up --slug <slug>            # WP + MariaDB, install core, activate plugin, seed admin + subscriber
python scripts/verify.py wp-cli --slug <slug> -- plugin list        # arbitrary wp-cli (create users, set options, dump data)
python scripts/verify.py wp-sync --slug <slug>          # re-push the plugin after editing files to instrument
python scripts/verify.py wp-login --user subscriber --password 'WpForge!Sub23456' --jar B   # log a principal in; cookies persist in jar 'B'
python scripts/verify.py wp-curl --path '/wp-admin/admin-ajax.php?action=foo' --method POST --data 'id=1' --jar B    # fire as that principal
python scripts/verify.py wp-curl --path '/?rest_route=/plugin/v1/x' --jar anon                                       # fire unauthenticated
python scripts/verify.py logs --name wp --tail 200      # read apache/php logs (+ your [SECANAL] lines)
```
The verifier follows `.claude/agents/finding-verifier.md`, adapted to WordPress:
- **Instrument the path** by editing the plugin PHP in the extracted clone
  (`target/…`), then `wp-sync` to push it live (PHP is interpreted — no rebuild).
  Insert loud `error_log('[SECANAL] file.php:NN var='.var_export($x,true));` lines
  at the source, each hop, and immediately before the sink; read them with
  `logs --name wp`.
- **Two-principal (authz/IDOR/priv-esc):** `wp-login` principal A (subscriber) to
  jar `A`, capture what B/admin owns, replay as A and confirm the crossing. For
  missing-authn, fire with jar `anon` (no login).
- **Injection:** SQLi (error/boolean/time or a marker row), RCE (`{{unique math}}`
  / benign command side effect), file upload (drop a benign file and fetch it),
  SSRF (loopback sentinel), traversal (read a should-be-blocked file). Keep
  payloads benign — proof, not damage.

#### Safe-PoC guardrail — prove control, never exploit (MANDATORY, all PoCs)
A PoC exists **only** to show the bug is real and reachable. It must never become a
working attack. This binds both the live verification and the shipped `poc.py`.

- **SQL injection — confirm without exfiltrating:**
  - Prove control with a **non-exfiltrating probe**: a boolean differential
    (`1=1` vs `1=2`), a time delay (`SLEEP(N)`/`BENCHMARK`), an error-based type
    mismatch, or a `UNION` that returns a **fixed unique canary** (e.g.
    `WPFORGE-POC-<finding-id>`) or a harmless server fact (`@@version`,
    `database()`). Reading one non-sensitive scalar to prove control is fine.
  - **Do NOT dump data.** Never `SELECT` from `wp_users`/`wp_usermeta`, password
    hashes, secret keys/salts, auth tokens, PII, or option secrets; never
    enumerate or page table contents beyond the single canary.
  - **Strictly read-only.** No `INSERT`/`UPDATE`/`DELETE`/`REPLACE`/`TRUNCATE`/
    `DROP`/`ALTER`/`GRANT`, no stacked/multi-statement queries that change state,
    and no `INTO OUTFILE`/`DUMPFILE`/`LOAD_FILE` (that is file write/read/RCE
    escalation, not SQLi proof).
- **Other classes, same spirit:** RCE → a unique arithmetic/echo marker or a
  benign side effect (touch a sentinel file), never a real command, reverse shell,
  or persistence. Traversal / file read → read a planted non-secret sentinel (or a
  public file) to prove the boundary crossing; demonstrate *reach* to
  `wp-config.php` without printing its secrets — **redact** keys/salts/DB creds in
  evidence. File upload → drop a benign **inert** file (a text marker, not a web
  shell) and fetch it. SSRF → hit a loopback sentinel, never pull internal or
  cloud-metadata data.
- **Sandbox only.** Every PoC runs against the local ephemeral WordPress+MySQL
  sandbox (dummy data) — the bundle's `docker-compose.yml` is the only allowed
  target. Never point a PoC at a live or third-party site.
- **Evidence hygiene.** Record the canary/marker and the differential (or timing)
  as proof — never captured data. If a probe incidentally returns sensitive rows,
  do not store or print them: log "control proven via `<probe>`" and redact.
- **Minimal & reversible.** One request that proves it; if any state changes
  despite care, note it and let the sandbox teardown reset it.
Apply the verdict:
```bash
python scripts/pipeline.py set-status <id> verified  --evidence "<request + [SECANAL] log excerpt>"
python scripts/pipeline.py set-status <id> triaged   --note "present but not reachable in default install: <why>"
python scripts/pipeline.py set-status <id> dismissed --note "<why>"
```
If the plugin can't be installed/run, keep HIGH/CRITICAL as **unverified
candidates** (still reportable per policy) — and still scaffold their PoC + Docker
bundle below so anyone can verify them later.

### Ship a runnable PoC + Docker bundle (MANDATORY — every HIGH/CRITICAL)
**Every** recorded HIGH/CRITICAL finding gets a self-contained, reproducible
bundle so anyone can re-prove it with one command — this is not optional and not
limited to verified findings. Scaffold it as soon as the finding is recorded:
```bash
python scripts/wp_poc.py scaffold --slug <slug> --id <finding-id>
```
This writes `pocs/<slug>/<finding-id>/` (each plugin in its own folder) — a
`docker-compose.yml` (WordPress + MariaDB + the pinned plugin version,
auto-installed with an admin + subscriber seeded), a `README.md`, and a `poc.py`
orchestrator whose `exploit()` is a **stub to fill in**. This bundle is the one
place we deliberately keep a plugin's source (pinned to the affected version) so
the bug reproduces even if the plugin is later pulled from wp.org. Then:
1. edit `poc.py`'s `EXPLOIT` section with the exact request that proves the bug
   (reuse the primitives it provides: `login(*SUB)` / `session()` / `get` / `post`);
2. run `python poc.py` from the bundle dir and confirm the verdict + exit code —
   **VULNERABLE (PoC succeeded)** (exit 0) for a verified finding; the sandbox
   tears down on exit;
3. paste that line into the finding's evidence:
   `python scripts/pipeline.py set-status <id> verified --evidence "poc.py: PASS — <line>"`.
- **Verified findings:** the bundle must reproduce green (`python poc.py` → exit 0)
  before the finding is considered done.
- **Unverified HIGH/CRITICAL candidates** (Docker unavailable, or the flow couldn't
  be driven this cycle): still scaffold the bundle and fill in `exploit()` with the
  best-known request from analysis, so a human can run `python poc.py` to confirm it
  later. Ship the `docker-compose.yml` + `poc.py` regardless — a HIGH/CRITICAL
  without a bundle is incomplete.

### Reconciliation (against the DB — new vs. known vs. mitigated)
If the DB already holds findings for an earlier version of this slug, reconcile
this version's fresh results against those **records** (we don't keep old files):
- **Still present, already reported** → stay silent.
- **Still present, not yet reported** → report as NEW (§ below).
- **A previously-recorded finding no longer appears in the latest version** (the
  vulnerable code is gone, or a verifier re-check reports `mitigated`) →
  `set-status <id> fixed --evidence "mitigated: no longer present in v<version>"`,
  send the one-time mitigation notice, mark `--fix-reported`.
- **dismissed** → never report.

### Report locally (notify-only)
`pipeline.py notify` prints the message and appends it to
`knowledge/<slug>/notifications.log` — plain text, no external service. Only emit
what isn't already reported:
```bash
SECANAL_TARGET_REPO="https://wordpress.org/plugins/<slug>/" python scripts/pipeline.py get --unreported --min-sev HIGH --brief
```
**Verified:**
```bash
python scripts/pipeline.py notify "$(cat <<'MSG'
🔴 VERIFIED — {severity}: {title}
Plugin: {slug} v{version}  ({active_installs} installs)
Where:  {file}:{line}  ({category}, {cwe})
Reach:  {entrypoint -> sink, auth state}
Proof:  {[SECANAL] log / response}
PoC:    {request/payload}
MSG
)"
python scripts/pipeline.py set-status <id> --reported --note "emitted locally"
```
**HIGH/CRITICAL unverified** → same shape prefixed `🟠 UNCONFIRMED — {severity}`
with a `Status: awaiting/failed verification ({reason})` line, then `--reported`.
**Mitigated** → `✅ MITIGATED — {severity}: {title}` with what changed, then `--fix-reported`.
Per-run advisories (one file per plugin) are written at cycle end (§10) under
`reports/<run>/` so separate runs never mix; if `report.attach_report_file`,
attach the relevant one from that folder.

## 9. Phase G — Record to the DB, drop the scratch & advance
Sync this plugin's findings into the durable DB and mark it analyzed at its
current version (so `next-batch` won't re-pick it until a new release):
```bash
python scripts/wp.py record --slug <slug>
```
Then **discard this plugin's source scratch** — the PoC bundles (§8) already hold
their own pinned copies, and findings live in the DB, so the plugin files are no
longer needed:
```bash
rm -rf target/wordpress.org/plugins/<slug> archives/<slug>                                             # bash
Remove-Item -Recurse -Force target/wordpress.org/plugins/<slug>, archives/<slug> -EA SilentlyContinue  # PowerShell
```
Then continue to the next plugin in the batch (§3).

## 10. Cycle summary + cleanup (always)
After the whole batch:
```bash
python scripts/wpdb.py summary
python scripts/pipeline.py notify "✅ WP-FORGE cycle: {n_plugins} plugins — {n_new} new, {n_verified} verified, {n_candidates} candidates, {n_fixed} mitigated, {n_sent} sent."   # if report.cycle_summary
python scripts/gen_disclosure_reports.py   # per-run advisories → reports/run-<timestamp>/ (its own folder per run; if report.attach_report_file)
python scripts/verify.py nuke   # tear down the Docker sandbox — ALWAYS
rm -rf archives/* target/*      # wipe disposable source scratch — findings live in the DB, repros in their PoC bundles
```
Print a short final summary to stdout (plugins analyzed, findings by status).
**Non-drain runs:** do not loop past the batch — the scheduler / user / CI starts
the next run. **Drain runs (§2):** you only reach here once `next-batch` returned
`[]`, i.e. the whole scoped set is analyzed — then summarize and nuke.
