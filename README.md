# wp-forge

wp-forge scans WordPress.org plugins for serious PHP vulnerabilities. It pulls
the plugin directory, looks for high- and critical-severity bugs (SQL injection,
RCE, object injection, arbitrary file upload or read, SSRF, broken access
control, IDOR, privilege escalation), and confirms each one with a runnable proof
of concept in a throwaway WordPress + Docker sandbox. Everything runs on your
machine, and nothing is sent anywhere.

It works on Linux and Windows, and is driven by Claude Code.

## Install

As a Claude Code plugin:

```
/plugin marketplace add zzzteph/wp-forge
/plugin install wp-forge@wp-forge
```

Update later with `/plugin marketplace update wp-forge`. You can also skip the
marketplace and run it straight from a clone of the repo. Either way you'll need
Python and Docker locally, so run setup once first.

## Setup

```powershell
.\setup.ps1     # installs PyYAML, creates the DB, pulls the sandbox images
```

There are no accounts or secrets to configure. You need Claude Code, Python
3.11+, ripgrep, and Docker.

## Run

Start Claude Code in this folder (`claude --dangerously-skip-permissions`), then:

| Command | What it does |
|---|---|
| `/wp-forge today` | analyze every plugin updated today, without stopping to ask |
| `/wp-forge week` | the same, over the last 7 days |
| `/wp-forge month` | the same, over the last 30 days |
| `/wp-forge <slug>` | analyze a single plugin, end to end |
| `/wp-forge` | one batch of the newest updates, then stop |

The `today`, `week`, and `month` runs go until they're finished without asking
anything, then hand back the results. Every high or critical finding ships with a
self-contained PoC you can run with `python poc.py`, and the writeup lands in
`reports/<run>/<slug>-<version>.md`.

## Notes

Plugin code is untrusted, so it only ever runs inside Docker (loopback-only,
ephemeral, torn down after each cycle). Only scan plugins you're authorized to
test.

The full workflow is documented in [`opt/wp_workflow.md`](opt/wp_workflow.md).

wp-forge began as a fork of security-forge, a general-purpose bug-bounty
pipeline, and was specialized for WordPress.org plugins. Releases follow SemVer;
see [`CHANGELOG.md`](CHANGELOG.md).
