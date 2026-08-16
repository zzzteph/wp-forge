"""WP-FORGE durable database — the catalog of analyzed plugins + discovered vulns.

This is the single, queryable "DB of analyzed plugins and vulnerabilities" the
pipeline keeps across cycles. It uses SQLite (Python stdlib — no extra dep) so it
scales to the whole wordpress.org catalog (60k+ plugins) and supports cheap
"have we already analyzed slug@version?" lookups that drive incremental batches.

Two tables:
  plugins   one row per plugin slug: latest known version (from the WP.org API),
            popularity, and how far WP-FORGE has gotten with it (status +
            last_analyzed_version). This is the batch queue and the ledger.
  findings  one row per HIGH/CRITICAL vulnerability, keyed by a stable id and
            tagged with the plugin slug + the version it was found in. Mirrors
            the per-plugin findings.json (which the analysis agents write through
            the pipeline CLI) into one place for cross-plugin querying.

The DB lives at db/wp-forge.db (durable, not gitignored) so it persists between
runs and can be backed up / committed as the project's memory.

CLI:
    python scripts/wpdb.py init
    python scripts/wpdb.py summary
    python scripts/wpdb.py plugins [--status analyzed] [--limit 50]
    python scripts/wpdb.py findings [--slug foo] [--min-sev HIGH] [--limit 50]
    python scripts/wpdb.py next-batch [--count 10]      # plugins due for (re)analysis
    python scripts/wpdb.py show --slug foo
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_ROOT, now_iso, sev_rank, configure_stdio  # noqa: E402

configure_stdio()

DB_DIR = DATA_ROOT / "db"
DB_PATH = DB_DIR / "wp-forge.db"

# Plugin lifecycle:
#   seen        listed by the catalog sync, not yet touched
#   downloaded  archive fetched + extracted
#   analyzing   a cycle is working on it
#   analyzed    a full cycle finished for its current version
#   error       something failed (see error column); ret/re-tried next cycle
#   skipped     deliberately excluded (e.g. below min_active_installs)
PLUGIN_STATUS = {"seen", "downloaded", "analyzing", "analyzed", "error", "skipped"}


def _connect() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init() -> dict:
    with _connect() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS plugins (
                slug                  TEXT PRIMARY KEY,
                name                  TEXT,
                version               TEXT,          -- latest version known from the API
                active_installs       INTEGER DEFAULT 0,
                rating                REAL DEFAULT 0,
                num_ratings           INTEGER DEFAULT 0,
                last_updated          TEXT,          -- WP.org "last_updated"
                added                 TEXT,          -- WP.org "added"
                homepage              TEXT,
                download_link         TEXT,
                tested                TEXT,
                requires_php          TEXT,
                short_description     TEXT,
                first_seen            TEXT,
                status                TEXT DEFAULT 'seen',
                analyzed_version      TEXT,          -- last version we finished analyzing
                analyzed_at           TEXT,
                error                 TEXT,
                high_count            INTEGER DEFAULT 0,
                critical_count        INTEGER DEFAULT 0,
                updated               TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id                TEXT PRIMARY KEY,
                slug              TEXT NOT NULL,
                version           TEXT,
                severity          TEXT,
                category          TEXT,
                title             TEXT,
                file              TEXT,
                line              INTEGER,
                cwe               TEXT,          -- JSON array
                entrypoint        TEXT,
                reachability      TEXT,
                poc               TEXT,
                evidence          TEXT,
                status            TEXT,          -- lifecycle: new/triaged/verifying/verified/dismissed/fixed
                verdict           TEXT,          -- verifier verdict if any
                reported          INTEGER DEFAULT 0,
                fix_reported      INTEGER DEFAULT 0,
                first_seen        TEXT,
                last_seen         TEXT,
                updated           TEXT,
                FOREIGN KEY (slug) REFERENCES plugins (slug)
            );

            CREATE INDEX IF NOT EXISTS idx_plugins_status   ON plugins (status);
            CREATE INDEX IF NOT EXISTS idx_plugins_updated  ON plugins (last_updated);
            CREATE INDEX IF NOT EXISTS idx_findings_slug    ON findings (slug);
            CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings (severity);
            """
        )
        # Migration: attempts counter (aborted-cycle / poison-pill tracking).
        cols = {r["name"] for r in c.execute("PRAGMA table_info(plugins)")}
        if "attempts" not in cols:
            c.execute("ALTER TABLE plugins ADD COLUMN attempts INTEGER DEFAULT 0")
    return {"db": str(DB_PATH), "initialized": True}


def reap_stale(max_attempts: int = 2) -> dict:
    """Reap plugins left mid-flight by an aborted cycle (crash, or a platform
    safeguard killing the session). A plugin still marked `analyzing` when a new
    cycle starts means a prior cycle died on it: bump its attempts, and once it has
    burned `max_attempts` retries, mark it `skipped` so it stops poisoning the
    queue (`next_batch` never returns `skipped`). Otherwise mark it `error` for one
    more try. Returns what was reaped so the caller can log it."""
    init()
    retried, skipped = [], []
    with _connect() as c:
        rows = c.execute(
            "SELECT slug, attempts FROM plugins WHERE status='analyzing'").fetchall()
        for r in rows:
            n = (r["attempts"] or 0) + 1
            if n >= max_attempts:
                c.execute("UPDATE plugins SET status='skipped', attempts=?, "
                          "error='aborted x'||?||' (crash/safeguard) — skipped', updated=? "
                          "WHERE slug=?", (n, n, now_iso(), r["slug"]))
                skipped.append(r["slug"])
            else:
                c.execute("UPDATE plugins SET status='error', attempts=?, "
                          "error='prior cycle aborted mid-analysis', updated=? "
                          "WHERE slug=?", (n, now_iso(), r["slug"]))
                retried.append(r["slug"])
    return {"reaped": len(retried) + len(skipped), "retry": retried, "skipped": skipped}


# --- Plugin catalog ---------------------------------------------------------

def upsert_plugin(info: dict) -> str:
    """Insert or refresh a plugin row from a WP.org API record. Preserves
    analysis progress (status/analyzed_version) on updates. Returns the slug."""
    slug = (info.get("slug") or "").strip()
    if not slug:
        raise ValueError("plugin info has no slug")
    init()
    with _connect() as c:
        row = c.execute("SELECT slug FROM plugins WHERE slug=?", (slug,)).fetchone()
        fields = {
            "name": info.get("name"),
            "version": info.get("version"),
            "active_installs": int(info.get("active_installs") or 0),
            "rating": float(info.get("rating") or 0),
            "num_ratings": int(info.get("num_ratings") or 0),
            "last_updated": info.get("last_updated"),
            "added": info.get("added"),
            "homepage": info.get("homepage"),
            "download_link": info.get("download_link"),
            "tested": info.get("tested"),
            "requires_php": info.get("requires_php"),
            "short_description": (info.get("short_description") or "")[:500],
            "updated": now_iso(),
        }
        if row:
            sets = ", ".join(f"{k}=?" for k in fields)
            c.execute(f"UPDATE plugins SET {sets} WHERE slug=?",
                      (*fields.values(), slug))
        else:
            fields["slug"] = slug
            fields["first_seen"] = now_iso()
            fields["status"] = "seen"
            cols = ", ".join(fields)
            qs = ", ".join("?" for _ in fields)
            c.execute(f"INSERT INTO plugins ({cols}) VALUES ({qs})", tuple(fields.values()))
    return slug


def set_plugin_status(slug: str, status: str, error: str | None = None,
                      analyzed_version: str | None = None) -> None:
    if status not in PLUGIN_STATUS:
        raise SystemExit(f"invalid plugin status '{status}'. one of {sorted(PLUGIN_STATUS)}")
    init()
    with _connect() as c:
        sets = ["status=?", "updated=?"]
        vals: list = [status, now_iso()]
        if error is not None:
            sets.append("error=?"); vals.append(error[:1000])
        if analyzed_version is not None:
            sets += ["analyzed_version=?", "analyzed_at=?"]
            vals += [analyzed_version, now_iso()]
        vals.append(slug)
        c.execute(f"UPDATE plugins SET {', '.join(sets)} WHERE slug=?", tuple(vals))


def get_plugin(slug: str) -> dict | None:
    init()
    with _connect() as c:
        row = c.execute("SELECT * FROM plugins WHERE slug=?", (slug,)).fetchone()
        return dict(row) if row else None


def analyzed_at_version(slug: str, version: str) -> bool:
    """True if we've already completed analysis of this exact slug@version."""
    p = get_plugin(slug)
    return bool(p and p.get("status") == "analyzed"
               and p.get("analyzed_version") == version)


def next_batch(count: int = 10, min_active_installs: int = 0,
               updated_since: str | None = None) -> list[dict]:
    """Plugins due for (re)analysis: never analyzed, or a newer version exists.
    Most-recently-updated first (freshest code = freshest bugs).

    updated_since: optional ISO date; restrict to plugins whose last_updated is
    on/after it (e.g. drain just today's releases). Values are date-prefixed
    ('2026-08-02 9:14am GMT'), so a lexicographic >= compares the date correctly."""
    init()
    q = [
        "SELECT * FROM plugins",
        "WHERE status != 'skipped'",
        "  AND active_installs >= ?",
        "  AND ( analyzed_version IS NULL OR analyzed_version != version OR status = 'error' )",
    ]
    vals: list = [min_active_installs]
    if updated_since:
        q.append("  AND last_updated >= ?")
        vals.append(updated_since)
    q.append("ORDER BY last_updated DESC LIMIT ?")
    vals.append(count)
    with _connect() as c:
        rows = c.execute("\n".join(q), tuple(vals)).fetchall()
        return [dict(r) for r in rows]


def pending_count(min_active_installs: int = 0, updated_since: str | None = None) -> int:
    """How many plugins still need (re)analysis (optionally within a date window).
    Lets a drain loop know when it's done without asking."""
    return len(next_batch(count=10_000_000, min_active_installs=min_active_installs,
                          updated_since=updated_since))


# --- Findings mirror --------------------------------------------------------

def sync_finding(slug: str, version: str, f: dict) -> None:
    """Upsert one finding (from the per-plugin findings.json) into the DB."""
    fid = f.get("id")
    if not fid:
        return
    init()
    with _connect() as c:
        exists = c.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
        vals = {
            "slug": slug,
            "version": version,
            "severity": (f.get("severity") or "").upper(),
            "category": f.get("category"),
            "title": f.get("title"),
            "file": f.get("file"),
            "line": f.get("line"),
            "cwe": json.dumps(f.get("cwe") or []),
            "entrypoint": f.get("entrypoint"),
            "reachability": f.get("reachability"),
            "poc": f.get("poc"),
            "evidence": f.get("evidence"),
            "status": f.get("status"),
            "verdict": f.get("verdict"),
            "reported": 1 if f.get("reported") else 0,
            "fix_reported": 1 if f.get("fix_reported") else 0,
            "last_seen": now_iso(),
            "updated": now_iso(),
        }
        if exists:
            sets = ", ".join(f"{k}=?" for k in vals)
            c.execute(f"UPDATE findings SET {sets} WHERE id=?", (*vals.values(), fid))
        else:
            vals["id"] = fid
            vals["first_seen"] = now_iso()
            cols = ", ".join(vals)
            qs = ", ".join("?" for _ in vals)
            c.execute(f"INSERT INTO findings ({cols}) VALUES ({qs})", tuple(vals.values()))
        # refresh the plugin's severity counts
        hi = c.execute("SELECT COUNT(*) FROM findings WHERE slug=? AND severity='HIGH'", (slug,)).fetchone()[0]
        cr = c.execute("SELECT COUNT(*) FROM findings WHERE slug=? AND severity='CRITICAL'", (slug,)).fetchone()[0]
        c.execute("UPDATE plugins SET high_count=?, critical_count=? WHERE slug=?", (hi, cr, slug))


def query_findings(slug: str | None = None, min_sev: str | None = None,
                   status: str | None = None, limit: int | None = None) -> list[dict]:
    init()
    q = "SELECT * FROM findings"
    where, vals = [], []
    if slug:
        where.append("slug=?"); vals.append(slug)
    if status:
        where.append("status=?"); vals.append(status)
    if where:
        q += " WHERE " + " AND ".join(where)
    with _connect() as c:
        rows = [dict(r) for r in c.execute(q, tuple(vals)).fetchall()]
    if min_sev:
        floor = sev_rank(min_sev)
        rows = [r for r in rows if sev_rank(r.get("severity")) >= floor]
    rows.sort(key=lambda r: sev_rank(r.get("severity")), reverse=True)
    return rows[:limit] if limit else rows


def summary() -> dict:
    init()
    with _connect() as c:
        by_status = {r["status"]: r["n"] for r in
                     c.execute("SELECT status, COUNT(*) n FROM plugins GROUP BY status")}
        totals = {
            "plugins": c.execute("SELECT COUNT(*) FROM plugins").fetchone()[0],
            "analyzed": c.execute("SELECT COUNT(*) FROM plugins WHERE status='analyzed'").fetchone()[0],
            "findings": c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "critical": c.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'").fetchone()[0],
            "high": c.execute("SELECT COUNT(*) FROM findings WHERE severity='HIGH'").fetchone()[0],
            "verified": c.execute("SELECT COUNT(*) FROM findings WHERE status='verified'").fetchone()[0],
        }
    return {"db": str(DB_PATH), "plugins_by_status": by_status, **totals}


# --- CLI --------------------------------------------------------------------

def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def main() -> None:
    ap = argparse.ArgumentParser(prog="wpdb", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("summary")
    p = sub.add_parser("plugins"); p.add_argument("--status"); p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("findings"); p.add_argument("--slug"); p.add_argument("--min-sev"); p.add_argument("--status"); p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("next-batch"); p.add_argument("--count", type=int, default=10); p.add_argument("--min-active-installs", type=int, default=0)
    p = sub.add_parser("show"); p.add_argument("--slug", required=True)
    p = sub.add_parser("set-status"); p.add_argument("--slug", required=True)
    p.add_argument("--status", required=True); p.add_argument("--error")
    p = sub.add_parser("reap-stale"); p.add_argument("--max-attempts", type=int, default=2)
    args = ap.parse_args()

    if args.cmd == "init":
        _print(init())
    elif args.cmd == "summary":
        _print(summary())
    elif args.cmd == "plugins":
        init()
        with _connect() as c:
            q = "SELECT slug,name,version,active_installs,last_updated,status,analyzed_version,high_count,critical_count FROM plugins"
            vals = []
            if args.status:
                q += " WHERE status=?"; vals.append(args.status)
            q += " ORDER BY last_updated DESC LIMIT ?"; vals.append(args.limit)
            _print([dict(r) for r in c.execute(q, tuple(vals)).fetchall()])
    elif args.cmd == "findings":
        _print(query_findings(args.slug, args.min_sev, args.status, args.limit))
    elif args.cmd == "next-batch":
        _print(next_batch(args.count, args.min_active_installs))
    elif args.cmd == "show":
        p = get_plugin(args.slug)
        if not p:
            raise SystemExit(f"unknown plugin: {args.slug}")
        p["findings"] = query_findings(args.slug)
        _print(p)
    elif args.cmd == "set-status":
        init()
        set_plugin_status(args.slug, args.status, error=args.error)
        _print(get_plugin(args.slug))
    elif args.cmd == "reap-stale":
        _print(reap_stale(args.max_attempts))


if __name__ == "__main__":
    main()
