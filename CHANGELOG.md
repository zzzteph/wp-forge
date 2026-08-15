# Changelog

All notable changes to **wp-forge** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com) and the project uses
[Semantic Versioning](https://semver.org). The version of record is
[`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).

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
