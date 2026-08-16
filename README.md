# wp-forge

wp-forge scans WordPress.org plugins for serious PHP vulnerabilities. It pulls the
plugin directory, hunts high- and critical-severity bugs (SQL injection, RCE,
object injection, arbitrary file upload or read, SSRF, broken access control,
IDOR, privilege escalation), and confirms each one with a runnable proof of concept
in a throwaway WordPress + Docker sandbox. Everything runs on your machine and
nothing is sent anywhere. It works on Linux and Windows and is driven by Claude
Code.

## Where results are stored

Everything wp-forge produces stays inside the repo folder:

| What | Where |
|---|---|
| Advisory writeups, one per finding | `reports/run-<timestamp>/<slug>-<version>.md` (with a `README.md` index in the same folder) |
| Proof-of-concept bundles | `pocs/<slug>/<finding-id>/` — a `docker-compose.yml` and a `poc.py` you run with `python poc.py` |
| Per-plugin run log | `knowledge/<slug>/notifications.log` |
| Durable database (what's been analyzed, every finding) | `db/wp-forge.db` |

A finding is only recorded if it is high or critical, so an empty result for a
plugin is normal.

## Install

As a Claude Code plugin:

```
/plugin marketplace add zzzteph/wp-forge
/plugin install wp-forge@wp-forge
```

Update later with `/plugin marketplace update wp-forge`. You can also skip the
marketplace and run it from a clone of the repo.

## Setup

Run once. You need Claude Code, Python 3.11+, ripgrep, and Docker. There are no
accounts or secrets.

```powershell
.\setup.ps1      # Windows: installs PyYAML, creates the DB, pulls the sandbox images
```

On Linux or macOS, do the same three steps by hand:

```bash
pip install -r requirements.txt
python scripts/wpdb.py init
docker pull wordpress:php8.2-apache && docker pull mariadb:11 && docker pull wordpress:cli
```

## Run

Start Claude Code in this folder (`claude --dangerously-skip-permissions`).

Analyze one plugin, or everything updated in a time window:

| Command | What it does |
|---|---|
| `/wp-forge <slug>` | one plugin, start to finish |
| `/wp-forge today` | every plugin updated today |
| `/wp-forge week` | every plugin updated in the last 7 days |
| `/wp-forge month` | every plugin updated in the last 30 days |

Look for a single bug class (unauthenticated by default):

| Command | Looks only for |
|---|---|
| `/wp-forge:sqli` | SQL injection |
| `/wp-forge:path-trav` | path traversal and arbitrary file read |
| `/wp-forge:unauth` | anything reachable with no login |
| `/wp-forge:critical` | the top unauthenticated critical classes |

Each focused mode takes the same arguments as `/wp-forge` (`<slug>`, `today`,
`week`, `month`).

### Large or unattended runs

For a big scope (thousands of plugins), run the orchestrator instead. It runs
wp-forge separately for every plugin, one at a time, each in its own fresh session:

```bash
python orchestrate.py --skill critical --window week
```

If a plugin stalls, errors, or gets interrupted, it is skipped and the run moves
on. You can stop and re-run at any time; the database tracks what is done, so it
continues from where it left off. Useful flags: `--dry-run` to preview, `--timeout
<seconds>` to cap each plugin, `--window all` for the whole catalog, and
`--skill full` to run the complete pipeline rather than a focused mode.

## Notes

Plugin code is untrusted, so it only ever runs inside Docker (loopback only,
ephemeral, torn down after each plugin). Only scan plugins you are authorized to
test.

The full workflow is documented in [`opt/wp_workflow.md`](opt/wp_workflow.md).

wp-forge began as a fork of security-forge, a general-purpose bug-bounty pipeline,
and was specialized for WordPress.org plugins. Releases follow SemVer; see
[`CHANGELOG.md`](CHANGELOG.md).
