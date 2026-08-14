# Changelog

All notable changes to **wp-forge** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com) and the project uses
[Semantic Versioning](https://semver.org). The version of record is
[`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).

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
