---
name: sqli
description: Run one cycle of the WordPress-plugin security pipeline focused ONLY on SQL injection that is unauthenticated, or reachable with basic non-admin authentication (subscriber/registered user, or a trivially self-registerable account). Same catalog sync, download, modeling, live WordPress+MySQL Docker verification, durable DB, and local notify-only reporting as /wp-forge — but every non-SQLi finding and every admin-only SQLi is dropped, not recorded. Use when the user runs /wp-forge:sqli or asks to scan WordPress plugins for unauthenticated / low-privilege SQL injection.
---

# wp-forge:sqli — SQL-injection-only pipeline (unauth + non-admin)

Run the normal WordPress-plugin workflow, but hunt, verify, and report **one bug
class only**. Everything about *how* a cycle runs is unchanged — the only change
is *what counts as a finding*.

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

## Scope override — SQL injection only
While executing the workflow, replace the "what to report" bar with this:

- **In scope:** SQL injection reachable **without authentication**, OR reachable
  with only **basic non-admin authentication** — a subscriber/registered user, or
  an account that is **trivially obtainable** (open/self-registration). This
  covers `$wpdb` string-built queries, unprepared `query()`/`get_results()`,
  unsafe `IN (...)` / `ORDER BY` / `LIKE` interpolation, `nopriv` AJAX and
  unauthenticated REST routes that reach the DB, etc.
- **Out of scope — drop it, do not record or report:** every non-SQLi class
  (RCE, traversal, upload, object injection, SSRF, XSS, access control, IDOR…)
  **and admin-only SQL injection** (where a full administrator login is required
  to reach the sink). Do not write advisories, PoCs, or DB findings for these.
- Still apply the model's data-flow rigor: prove the untrusted source reaches the
  query sink; a candidate that can't be reached by an unauth/non-admin principal
  is out of scope.

Keep **every other guardrail** from the workflow: notify-only + fully local
(console + `knowledge/<slug>/notifications.log`), a runnable **PoC + Docker
bundle** for each in-scope HIGH/CRITICAL, live **WordPress-sandbox verification**
with a two-principal / injection PoC, DB idempotency (`wp.py record` — mark the
plugin analyzed at its version and sync in-scope findings), **no questions**, and
always nuke the sandbox and wipe scratch at the end. **Zero SQLi findings for a
plugin is a fine, honest result.**
