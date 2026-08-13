# wp-forge

Agentic **WordPress-plugin vulnerability pipeline**. Pulls the wordpress.org
directory, hunts real **HIGH/CRITICAL PHP** vulns, **proves each in a live
WordPress + Docker sandbox** with a runnable PoC, and reports **locally**.
Notify-only · fully local · Linux + Windows.

## Install (Claude Code plugin)
```
/plugin marketplace add zzzteph/wp-forge
/plugin install wp-forge@wp-forge
```
Update later with `/plugin marketplace update wp-forge`. You still need Python +
Docker locally (the analysis runs local helpers) — run **Setup** once. Or skip the
marketplace and just clone the repo and run from the folder.

## Setup
```powershell
.\setup.ps1     # installs PyYAML, inits the DB, pulls the sandbox images
```
No secrets or accounts. Needs: Claude Code · Python 3.11+ · ripgrep · Docker.

## Run
Start Claude Code in this folder (`claude --dangerously-skip-permissions`), then:

| Command | What it does |
|---|---|
| `/wp-forge today` | drain every plugin updated **today** — continuously, never asking |
| `/wp-forge week` | …the last 7 days |
| `/wp-forge month` | …the last 30 days |
| `/wp-forge <slug>` | analyze one plugin, end to end |
| `/wp-forge` | one batch of the newest updates, then stop |

`today` / `week` / `month` run to completion with **zero questions**, then return
the results. Every HIGH/CRITICAL ships a self-contained **PoC + Docker** bundle
(`python poc.py`); advisories land in `reports/<run>/<slug>-<version>.md`. All
output is local (nothing is sent anywhere).

## Notes
Untrusted plugin code runs inside Docker (loopback-only, ephemeral, torn down each
cycle) — only test plugins you're authorized to. The full workflow lives in
[`opt/wp_workflow.md`](opt/wp_workflow.md).

Forked from **security-forge** (the general repo / bug-bounty pipeline) and
specialized for WordPress.org plugins. Versioned with SemVer — see
[`CHANGELOG.md`](CHANGELOG.md).
