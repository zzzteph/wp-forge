---
name: critical
description: Run one cycle of the WordPress-plugin security pipeline focused ONLY on the seven strictly-unauthenticated, high-impact vulnerability classes that empirically dominate WordPress-plugin CRITICAL/HIGH CVEs — pre-auth SQL injection, broken access control / missing authorization (nonce/capability/nopriv gaps), arbitrary file upload/write, path traversal / arbitrary file read, RCE / code injection, local/remote file inclusion, and impactful SSRF. Anything requiring any login, and every other class (XSS, CSRF, object injection, IDOR-only, info disclosure), is dropped, not recorded. Same catalog sync, download, modeling, live WordPress+MySQL Docker verification, durable DB, and local notify-only reporting as /wp-forge. Use when the user runs /wp-forge:critical or asks to scan WordPress plugins for the top unauthenticated critical vulnerability classes.
---

# wp-forge:critical — unauthenticated critical-only pipeline

Run the normal WordPress-plugin workflow, but the report bar is the narrowest and
highest: **only vulnerabilities that are both strictly unauthenticated and in one
of the seven high-impact classes below.** This list is not arbitrary — it is the
set of classes that actually dominate real WordPress-plugin CRITICAL/HIGH
disclosures (Wordfence / Patchstack / NVD, 2024–2026), ranked by how often an
unauthenticated instance is reported. Hunt these; ignore everything else.

**Read and follow [`opt/wp_workflow.md`](../../../opt/wp_workflow.md) exactly**,
resolving the tool home once and using it for every command and bundled path:
```bash
WP_FORGE_HOME="${CLAUDE_PLUGIN_ROOT:-$PWD}"
```
Read the workflow from `$WP_FORGE_HOME/opt/wp_workflow.md`; run helpers as
`python "$WP_FORGE_HOME/scripts/wp.py" …`; state is written under `$WP_FORGE_HOME/`.

**Input (all optional):** identical to `/wp-forge` — bare (one batch, then stop),
`<slug>` (one plugin), `today` / `week` / `month` / `all` (drain the window
continuously, never pausing to ask), `batch N` (N plugins, then stop).

## Scope override — the seven unauthenticated classes only
While executing the workflow, replace the "what to report" bar with this.

**In scope** — reachable with **no authentication whatsoever** (`wp_ajax_nopriv_*`,
open REST routes with a true/`__return_true`/missing `permission_callback`,
`init` / `template_redirect` / `admin_post_nopriv` handlers, direct-access PHP
entry points, webhooks) **and** in one of these classes, in priority order:

1. **SQL injection** — `$wpdb` string-built queries, unprepared
   `query()`/`get_results()`, unsafe `IN (…)` / `ORDER BY` / `LIKE`
   interpolation. *(The single most-reported exploitable class.)*
2. **Broken access control / missing authorization** — the nonce / capability /
   `nopriv` gap: sensitive actions with no `current_user_can`, no nonce, or a
   `nopriv` AJAX / open REST route exposing a privileged operation; includes
   authentication bypass and account-takeover primitives. *(Produces the most
   CRITICALs, and is usually the vehicle that lifts a lesser bug to critical.)*
3. **Arbitrary file upload / write** — unrestricted upload reachable pre-auth;
   small footprint, near-always chains to a web shell / RCE.
4. **Path traversal / arbitrary file read** — attacker-controlled path into
   `file_get_contents`/`fopen`/`readfile`/download handlers, reading
   `wp-config.php` (→ DB creds → full compromise) or `/etc/passwd`.
5. **RCE / code injection / command injection** — `eval`/`call_user_func`/
   dynamic includes/`system`/`exec` reachable from an unauthenticated source.
6. **Local / remote file inclusion (LFI/RFI)** — attacker-controlled
   `include`/`require` path.
7. **SSRF with real impact** — internal-service or cloud-metadata reach.

**Out of scope — drop it, do not record or report:** anything requiring a login
of **any** level (subscriber → admin), and every class *not* in the seven above —
including reflected/stored XSS, CSRF-only, PHP object injection / deserialization,
IDOR without critical impact, information disclosure, and missing hardening —
**unless** it composes into one of the seven unauthenticated classes above (then
report it as that). Do not write advisories, PoCs, or DB findings for out-of-scope
issues.

**Prove it end to end:** an unauthenticated request path all the way to the sink,
demonstrated in the sandbox. If auth gates the path, or it isn't one of the seven
classes, drop it.

Keep **every other guardrail** from the workflow: notify-only + fully local
(console + `knowledge/<slug>/notifications.log`), a runnable **PoC + Docker
bundle** for each in-scope finding, live **WordPress-sandbox verification** (fire
the PoC as a logged-out client), DB idempotency (`wp.py record` — mark the plugin
analyzed at its version and sync in-scope findings), **no questions**, and always
nuke the sandbox and wipe scratch at the end. **Zero findings for a plugin is a
fine, honest result.**
