---
name: path-trav
description: Run one cycle of the WordPress-plugin security pipeline focused ONLY on unauthenticated path traversal / directory traversal and arbitrary file read (../ sequences reaching file_get_contents / fopen / readfile / include / download handlers, unauthenticated file-fetch AJAX or REST). Any finding that needs a login, or that is any other bug class, is dropped, not recorded. Same catalog sync, download, modeling, live WordPress+MySQL Docker verification, durable DB, and local notify-only reporting as /wp-forge. Use when the user runs /wp-forge:path-trav or asks to scan WordPress plugins for unauthenticated path traversal / arbitrary file read.
---

# wp-forge:path-trav — unauthenticated path-traversal-only pipeline

Run the normal WordPress-plugin workflow, but hunt, verify, and report **one bug
class only**: unauthenticated path / directory traversal and the arbitrary file
read it enables.

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

## Scope override — unauthenticated path traversal only
While executing the workflow, replace the "what to report" bar with this:

- **In scope:** path / directory traversal reachable **without authentication**
  that yields arbitrary file read (or, where it applies, arbitrary file
  include/write via the same traversal primitive). Look for attacker-controlled
  path segments (`../`, absolute paths, null bytes, encoded separators) flowing
  into `file_get_contents` / `fopen` / `readfile` / `fread` / `include` /
  `require` / `unlink` / `copy` / `move_uploaded_file` / download-and-stream
  handlers — via `wp_ajax_nopriv_*`, unauthenticated REST routes, or any
  logged-out request path.
- **Out of scope — drop it, do not record or report:** every other class (SQLi,
  RCE-not-via-traversal, upload, object injection, SSRF, XSS, access control,
  IDOR…) **and any traversal that requires a login of any level**. Do not write
  advisories, PoCs, or DB findings for these.
- Prove reachability and impact: an unauthenticated request must drive the
  traversal to a real file-system read/include of a file outside the intended
  directory (demonstrate reading something like `wp-config.php` or `/etc/passwd`
  in the sandbox).

Keep **every other guardrail** from the workflow: notify-only + fully local
(console + `knowledge/<slug>/notifications.log`), a runnable **PoC + Docker
bundle** for each in-scope HIGH/CRITICAL, live **WordPress-sandbox verification**
(fire the traversal as a logged-out client and show the leaked file), DB
idempotency (`wp.py record` — mark the plugin analyzed at its version and sync
in-scope findings), **no questions**, and always nuke the sandbox and wipe
scratch at the end. **Zero traversal findings for a plugin is a fine, honest
result.**
