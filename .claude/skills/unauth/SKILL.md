---
name: unauth
description: Run one cycle of the WordPress-plugin security pipeline focused ONLY on unauthenticated issues — vulnerabilities an attacker can reach with no login at all (nopriv AJAX, unauthenticated REST routes, public request handlers). Any bug class qualifies (SQLi, RCE, traversal, upload, object injection, SSRF, auth bypass, access control), but anything that needs any authenticated session is dropped, not recorded. Same catalog sync, download, modeling, live WordPress+MySQL Docker verification, durable DB, and local notify-only reporting as /wp-forge. Use when the user runs /wp-forge:unauth or asks to scan WordPress plugins for pre-auth / unauthenticated vulnerabilities only.
---

# wp-forge:unauth — unauthenticated-only pipeline

Run the normal WordPress-plugin workflow, but only a vulnerability that a
**completely unauthenticated** attacker can trigger counts as a finding. The bug
*class* is open (any of them); the *reachability* is not.

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

## Scope override — unauthenticated reachability only
While executing the workflow, replace the "what to report" bar with this:

- **In scope:** any HIGH/CRITICAL PHP vulnerability reachable with **no
  authentication whatsoever** — `wp_ajax_nopriv_*` handlers, REST routes with
  `permission_callback` returning true / `__return_true` / missing, `init` /
  `template_redirect` / `admin_post_nopriv` request handling, direct-access PHP
  entry points, webhooks, and any other path a logged-out visitor can hit. The
  class is unrestricted: SQLi, RCE, path traversal, arbitrary file upload/read,
  PHP object injection, SSRF, authentication bypass, broken access control.
- **Out of scope — drop it, do not record or report:** anything that requires a
  logged-in session of **any** privilege level (subscriber, contributor, editor,
  admin) — even a trivially self-registerable account. If a login is needed to
  reach it, it is out of scope here. Do not write advisories, PoCs, or DB
  findings for these.
- Prove the reachability: the source must be an unauthenticated request path all
  the way to the sink. If auth gates the path, drop it.

Keep **every other guardrail** from the workflow: notify-only + fully local
(console + `knowledge/<slug>/notifications.log`), a runnable **PoC + Docker
bundle** for each in-scope HIGH/CRITICAL, live **WordPress-sandbox verification**
(fire the PoC as a logged-out client), DB idempotency (`wp.py record` — mark the
plugin analyzed at its version and sync in-scope findings), **no questions**, and
always nuke the sandbox and wipe scratch at the end. **Zero unauthenticated
findings for a plugin is a fine, honest result.**
