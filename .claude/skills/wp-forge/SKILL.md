---
name: wp-forge
description: Run one cycle of the WordPress-plugin security pipeline — refresh the wordpress.org catalog, pick a batch of the most-recently-updated plugins not yet analyzed at their current version, download each archive, model it, hunt for HIGH/CRITICAL PHP vulnerabilities (SQLi via $wpdb, RCE, object injection, arbitrary file upload/read, SSRF, broken access control / nonce / capability, IDOR, privilege escalation), prove them in a live WordPress+MySQL Docker sandbox, record everything in the durable DB, and report locally (console + notifications.log), contacting no external service. Use when the user runs /wp-forge, points you at opt/wp_workflow.md, or asks to scan/analyze WordPress plugins.
---

# wp-forge — shortcut to the WordPress plugin workflow

This skill is a thin entry point. **The canonical, self-contained instructions
live in [`opt/wp_workflow.md`](../../../opt/wp_workflow.md)** — read that file now
and follow it exactly, start to finish. It works out of the box from this
folder's files; nothing needs to be installed.

**Where the tool lives (installed plugin vs. clone).** All scripts and docs sit
in the wp-forge folder. When this runs as an **installed plugin** that folder is
**`${CLAUDE_PLUGIN_ROOT}`**; when you run from a **clone** it's the repo root
(your current folder). Resolve it once and use it for every command and
bundled-file path:
```bash
WP_FORGE_HOME="${CLAUDE_PLUGIN_ROOT:-$PWD}"
```
Read the workflow from `$WP_FORGE_HOME/opt/wp_workflow.md` and run helpers as
`python "$WP_FORGE_HOME/scripts/wp.py" …`. State (the DB, per-plugin model,
findings, advisories, PoC bundles, `notifications.log`) is written under
`$WP_FORGE_HOME/` (`db/`, `knowledge/`, `pocs/`, `reports/`).

**Input (all optional):**
- nothing → analyze a batch of the most-recently-updated plugins (batch size from
  `config.yaml → wp.batch_size`).
- `/wp-forge <slug>` → analyze just that one plugin.
- `/wp-forge today` · `/wp-forge week` · `/wp-forge month` → scope to plugins
  updated in that window (today / last 7 days / last 30 days) and **drain it
  continuously**: analyze *every* plugin in the window, batch after batch, until
  none remain — **never pausing to ask anything**. Just run and return the results.
- `/wp-forge all` → drain the whole catalog the same way (long; resumable).
- `/wp-forge batch N` → analyze N plugins this cycle, then stop.

Then execute `opt/wp_workflow.md`:
1. Preflight — `wpdb.py init`, `wp.py sync` (refresh catalog), `wp.py next-batch`.
2. Per plugin: `wp.py prep --slug <slug>` (download+extract+shape the latest),
   analyze the current version as a full baseline (no cross-version diffing).
3. Comprehension → durable model in `knowledge/wordpress.org/plugins/<slug>/`.
4. Grep guardrail (`sast/wp_signatures.md`) → ranked PHP hotspots.
5. Authorization analysis (`docs/WP_METHODOLOGY.md`) — nonce/CSRF, capability,
   nopriv AJAX, REST authz, IDOR, privilege escalation.
6. Data-flow analysis — SQLi/RCE/object-injection/upload/traversal/SSRF/XSS.
7. Verify top candidates in the live WordPress sandbox (`verify.py wp-up …`).
8. Reconcile (new vs. known vs. mitigated) and **notify-only, locally** (console + `knowledge/<slug>/notifications.log`).
9. Record to the DB (`wp.py record`) and advance.
10. Cycle summary + tear down the sandbox (`verify.py nuke`).

A bare `/wp-forge` runs **one batch cycle, non-interactively, then stops.** A
window scope (`today`/`week`/`month`) or `all` runs in **drain mode** — keep
processing batches until `wp.py next-batch` returns `[]`, **never pausing to ask
anything** (no confirmations, no "continue?"). Just run and return the results.
Either way, honour every guardrail in `opt/wp_workflow.md`: notify-only,
unauthenticated-first HIGH/CRITICAL PHP (apply the auth penalty) + a PoC/Docker
bundle each, user-reachable only, no questions, budgets, DB idempotency, always nuke.
