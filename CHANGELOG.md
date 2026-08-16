# Changelog

All notable changes to **wp-forge** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com) and the project uses
[Semantic Versioning](https://semver.org). The version of record is
[`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).

## [0.8.1] — 2026-08-16

### Changed
- **README examples** — added a worked "Examples" section: focused slash-command
  runs, unattended `orchestrate.py` invocations (with `--output-dir` / `--dry-run` /
  `--timeout`), and the commands to inspect results afterward (`wpdb.py summary` /
  `findings`, `reports/`, running a PoC bundle).

## [0.8.0] — 2026-08-16

### Added
- **Configurable artifact folder (`WP_FORGE_DATA_DIR` + `orchestrate.py --output-dir`).**
  All run artifacts — `db/`, `logs/`, `reports/`, `pocs/`, `knowledge/`, and the
  `target/`/`state/`/`archives/` scratch — now honor a single data-root env var,
  defaulting to the repo folder. Set `WP_FORGE_DATA_DIR` (or pass `--output-dir` to
  the orchestrator, which exports it to every session it launches) to keep results
  in a visible location instead of the hidden `~/.claude/plugins/...` cache (which is
  also wiped on plugin update). Code is still read from the repo; only outputs move.

## [0.7.1] — 2026-08-16

### Changed
- **README rewrite** — simpler run instructions (single plugin / window / focused
  modes / the `orchestrate.py` runner) and a "Where results are stored" table up top
  (`reports/run-<timestamp>/<slug>-<version>.md`, `pocs/<slug>/<finding-id>/`,
  `knowledge/<slug>/notifications.log`, `db/wp-forge.db`).

## [0.7.0] — 2026-08-16

### Added
- **`orchestrate.py` — per-plugin orchestrator (maximum reliability).** Runs a
  *dedicated headless Claude session for each plugin*, one at a time, with a hard
  per-plugin wall-clock timeout. Whatever a single session does — finishes, stalls,
  gets safeguard-killed, errors — the orchestrator kills it at the deadline, tears
  down the sandbox, records the outcome, and moves to the next plugin. Because the
  orchestrator holds no model context, it drains scopes no single session could;
  context exhaustion and cross-plugin bleed are structurally impossible. Fully
  resumable via the DB; `--dry-run`, `--timeout`, `--max-plugins`, `--model`,
  `--skill`, `--window` supported. This is the recommended way to run a large or
  unattended drain — effectively "run wp-forge for each plugin separately".
- **Poison-pill protection (`wpdb.py reap-stale` + `attempts` counter).** A plugin
  left `analyzing` by a cycle that died mid-analysis — a crash, or a platform cyber
  safeguard killing the session on scary-looking code (e.g. a file-upload handler) —
  is reaped at the next cycle's preflight: retried once, then marked `skipped` after
  2 aborts so it can't kill every cycle. A safeguard trip on one plugin no longer
  stalls the whole run — the offender is retired and the drain continues.
- **`drain.sh` / `drain.ps1` — outer drain runner.** A lighter alternative to the
  orchestrator: relaunches fresh whole cycles back-to-back (each session analyzes as
  many plugins as its context holds) until the scoped queue is empty. Fewer session
  startups, but a session can stop early; use the orchestrator for full isolation.
  Parameterized by skill (`critical`/`sqli`/`unauth`/`path-trav`/`full`) and window.

## [0.6.0] — 2026-08-16

### Changed
- **Strictly serial execution — one plugin at a time.** The workflow is now an
  explicit sequential loop: download a plugin, analyze it to completion, record it,
  then the next. No parallelism anywhere — no parallel analysis subagents, no
  background jobs / driver scripts, no plugin "blocks". `max_analyzer_agents` is set
  to `1`; the drain still covers the whole scope (`/wp-forge today` = every plugin
  updated today), just one after another.

## [0.5.0] — 2026-08-14

### Added
- **Hang guards** — a single big or slow plugin can no longer stall a run. `wp.py`
  downloads are self-limiting (90s wall-clock, 80MB compressed / 400MB extracted
  caps, overridable via `WP_DOWNLOAD_TIMEOUT_S` / `WP_MAX_ARCHIVE_MB` /
  `WP_MAX_EXTRACT_MB`) and fail fast; the grep sweep is time-boxed (`timeout 120`)
  and skips vendored / generated / minified bulk and files >2MB (fixes the
  `w3-total-cache` minified-file stall).
- **`wpdb.py set-status`** — mark a plugin `error` from the CLI; since `next-batch`
  re-picks `error` plugins, a skipped one is automatically retried on a later run.

### Changed
- **Reliability contract — hang means skip, never intervene.** The workflow now
  states explicitly that a stalled/failed per-plugin step is marked `error` and the
  run moves on. It must **never** `pkill`/kill processes, inspect process trees, edit
  or "harden" driver scripts, broad-`rm`, restart a block, or pause to ask — the
  improvisations that made bulk drains unreliable. A per-plugin failure is a skipped
  item, not a stop.

## [0.4.0] — 2026-08-14

### Added
- **Safe-PoC guardrail** — a mandatory "prove control, never exploit" rule binding
  both live verification and the shipped `poc.py`. SQL injection must be confirmed
  with a non-exfiltrating probe (boolean/time/error, or a `UNION` canary /
  `@@version`) — no dumping `wp_users`/hashes/secrets, no enumerating tables, strictly
  read-only (no writes/DDL, no `INTO OUTFILE`/`LOAD_FILE`). Extended in the same
  spirit to RCE / traversal / upload / SSRF, with sandbox-only targets and evidence
  redaction.

### Changed
- **Drain the whole scope, not a fixed chunk** — in drain mode the batch now equals
  the entire scoped set, so `/wp-forge today` analyzes *every* plugin updated today
  (not 3–5). `wp.batch_size` is now only the chunk for a bare, unscoped `/wp-forge`.
- **Whole-catalog default** — `config.yaml` ships with `since: ""`, `catalog_pages: 700`,
  `per_page: 100` so a sync loads the entire wordpress.org directory (~70k plugins)
  into the DB for `all`/drain runs. Lower `catalog_pages` after the first full sync.

## [0.3.0] — 2026-08-14

### Added
- **Focused hunt modes** — four scope-narrowed variants of the pipeline, each
  reusing the full run (catalog sync, download, modeling, sandbox verification,
  durable DB, notify-only reporting) but recording only in-scope findings:
  - **`/wp-forge:sqli`** — SQL injection only, unauthenticated or basic non-admin
    (admin-only SQLi dropped).
  - **`/wp-forge:unauth`** — any class, but only when reachable with no login.
  - **`/wp-forge:path-trav`** — unauthenticated path traversal / arbitrary file
    read only.
  - **`/wp-forge:critical`** — the seven strictly-unauthenticated, high-impact
    classes that dominate real WordPress-plugin CRITICAL/HIGH CVEs (SQLi, broken
    access control / missing authorization, arbitrary file upload/write, path
    traversal / arbitrary file read, RCE / code injection, LFI/RFI, SSRF).
- The focused modes **share the analyzed ledger** with `/wp-forge` — they mark a
  plugin analyzed at its version, so the window drains still terminate.

## [0.2.0] — 2026-08-13

### Added
- **Marketplace install** — the repo is a Claude Code plugin marketplace:
  `/plugin marketplace add zzzteph/wp-forge` then `/plugin install wp-forge@wp-forge`.
- **`/wp-forge today | week | month`** — continuous, no-question drains that analyze
  every plugin updated in the rolling window (today / 7 days / 30 days) to completion.
- **Mandatory PoC + Docker bundle** for every HIGH/CRITICAL finding, scaffolded into
  its own per-plugin folder `pocs/<slug>/<finding-id>/`.
- **Unauthenticated-first severity scoring** — pre-auth bugs are the target; −1 level
  if a login is required, −2 if admin, *except* RCE, SQL injection, or when the
  account is trivially obtainable (open/self-registration).

### Changed
- Renamed the pipeline **`wpanal` → `wp-forge`** (skill `/wp-forge`, plugin metadata,
  DB `db/wp-forge.db`).
- **Latest-only analysis** — always full-baseline the current version; `archives/`
  and `target/` are disposable scratch, wiped each cycle. No cross-version diffing,
  no stored plugin files.
- **Per-run advisories** — disclosure reports are written under `reports/<run>/` with
  version-stamped filenames `<slug>-<version>.md`, so runs and versions never overlap.

## [0.1.0] — 2026-08-02

### Added
- Initial pivot from single-repo analysis (SECANAL / **security-forge**) to a
  **WordPress.org plugin** vulnerability pipeline: catalog sync, download, per-plugin
  modeling, HIGH/CRITICAL PHP hunting (SQLi, RCE, object injection, file upload/read,
  SSRF, broken access control, IDOR, priv-esc), live WordPress + MariaDB Docker
  verification, a durable SQLite DB, and notify-only local reporting.
