"""WP-FORGE — wordpress.org plugin catalog fetch, download, and per-plugin prep.

This is the WordPress equivalent of scripts/repo.py: instead of cloning a git
repo, it discovers plugins through the official wordpress.org Plugins API, pulls
their .zip archives, extracts them, and computes a per-version file diff so the
analysis can be incremental across plugin releases (a new version behaves like a
new commit). Everything uses the Python stdlib (urllib + zipfile + json) so it
runs unchanged on Linux and Windows.

The catalog + progress ledger lives in the SQLite DB (scripts/wpdb.py). Per
plugin, the state is keyed exactly like the rest of the pipeline: the plugin's
"repo url" is https://wordpress.org/plugins/<slug>/ so
common.target_slug() -> "wordpress.org/plugins/<slug>" keys target/, state/, and
knowledge/ per plugin. wp.py sets SECANAL_TARGET_REPO from --slug itself, so the
same slug drives pipeline.py / store.py calls the workflow makes afterwards.

CLI:
    python scripts/wp.py sync   [--since today|week|month] [--browse updated] [--pages 3] [--per-page 100]
    python scripts/wp.py list   [--browse updated] [--page 1] [--per-page 50]
    python scripts/wp.py next-batch [--count 10] [--min-active-installs 0]
    python scripts/wp.py info    --slug <slug>
    python scripts/wp.py prep    --slug <slug>                   # download+extract+diff+shape
    python scripts/wp.py download --slug <slug> [--version X]    # just fetch+extract
    python scripts/wp.py record  --slug <slug>                   # sync findings.json -> DB, mark analyzed
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

# --- bootstrap per-plugin keying BEFORE importing common --------------------
# common.py resolves all per-target paths from SECANAL_TARGET_REPO at import
# time. If we were given a --slug, set that env first so target/state/knowledge
# all key to this plugin (and match the pipeline.py calls the workflow makes).
def _argv_slug() -> str | None:
    for i, a in enumerate(sys.argv):
        if a == "--slug" and i + 1 < len(sys.argv):
            return sys.argv[i + 1].strip()
        if a.startswith("--slug="):
            return a.split("=", 1)[1].strip()
    return None


def plugin_url(slug: str) -> str:
    return f"https://wordpress.org/plugins/{slug}/"


_SLUG_ARG = _argv_slug()
if _SLUG_ARG:
    os.environ.setdefault("SECANAL_TARGET_REPO", plugin_url(_SLUG_ARG))

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wpdb  # noqa: E402
from common import (ROOT, TARGET_DIR, STATE_DIR, configure_stdio,  # noqa: E402
                    eprint, now_iso)
import repo  # noqa: E402  (reuse detect_shape)

configure_stdio()

API = "https://api.wordpress.org/plugins/info/1.2/"
ARCHIVE_DIR = ROOT / "archives"
UA = "wp-forge/1.0 (+https://wordpress.org/plugins/)"

# Fields we want back from query_plugins (keep the payload lean).
QUERY_FIELDS = {
    "short_description": True, "description": False, "sections": False,
    "downloaded": False, "download_link": True, "last_updated": True,
    "added": True, "tags": False, "active_installs": True, "ratings": False,
    "rating": True, "num_ratings": True, "homepage": True, "tested": True,
    "requires": True, "requires_php": True, "screenshots": False, "versions": False,
    "banners": False, "icons": False, "contributors": False, "compatibility": False,
}


def _http_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _query_params(browse: str, page: int, per_page: int) -> str:
    params = {
        "action": "query_plugins",
        "request[browse]": browse,       # updated | popular | new | top-rated
        "request[page]": str(page),
        "request[per_page]": str(per_page),
    }
    for k, v in QUERY_FIELDS.items():
        params[f"request[fields][{k}]"] = "1" if v else "0"
    return urllib.parse.urlencode(params)


def query_plugins(browse: str = "updated", page: int = 1, per_page: int = 50) -> dict:
    """One page of the plugin directory. Returns {info, plugins:[...]}"""
    url = f"{API}?{_query_params(browse, page, per_page)}"
    return _http_json(url)


def plugin_information(slug: str) -> dict:
    params = {"action": "plugin_information", "request[slug]": slug}
    url = f"{API}?{urllib.parse.urlencode(params)}"
    return _http_json(url)


def _slim(p: dict) -> dict:
    """Normalize an API plugin record to the fields the DB stores."""
    return {
        "slug": p.get("slug"), "name": p.get("name"), "version": p.get("version"),
        "active_installs": p.get("active_installs"), "rating": p.get("rating"),
        "num_ratings": p.get("num_ratings"), "last_updated": p.get("last_updated"),
        "added": p.get("added"), "homepage": p.get("homepage"),
        "download_link": p.get("download_link"), "tested": p.get("tested"),
        "requires_php": p.get("requires_php"), "short_description": p.get("short_description"),
    }


def _resolve_since(s: str | None) -> str | None:
    """Map a window keyword or ISO date to an ISO 'YYYY-MM-DD' lower bound:
    'today'/'day' -> today, 'week' -> 7 days ago, 'month' -> 30 days ago; an
    explicit 'YYYY-MM-DD' passes through. Returns None for empty input. This is
    what makes `wp-forge today|week|month` a first-class continuous scope."""
    if not s:
        return None
    import datetime
    key = s.strip().lower()
    windows = {"today": 0, "day": 0, "week": 7, "month": 30}
    if key not in windows:
        return s.strip()   # assume an explicit ISO date
    d = (datetime.datetime.now(datetime.timezone.utc).date()
         - datetime.timedelta(days=windows[key]))
    return d.isoformat()


def _day(s: str | None) -> str:
    """First 10 chars of a WP.org date ('2026-08-02 9:14am GMT' -> '2026-08-02')."""
    return (s or "")[:10]


def sync(browse: str = "updated", pages: int = 3, per_page: int = 100,
         since: str | None = None, max_pages: int = 60) -> dict:
    """Pull pages of the directory and upsert them into the DB.

    Without `since`: the first `pages` pages (freshly-updated first).
    With `since` (an ISO date or 'today'): keep paging the `updated` browse and
    upsert only plugins whose last_updated >= since, stopping as soon as a page
    falls entirely before that date (the feed is sorted newest-first). This is
    how you scope a run to just today's / this-week's releases."""
    wpdb.init()
    since = _resolve_since(since)
    total, added_new, first_page = 0, 0, None
    page = 1
    hard_cap = max_pages if since else pages
    while page <= hard_cap:
        try:
            data = query_plugins("updated" if since else browse, page, per_page)
        except Exception as e:  # noqa: BLE001
            eprint(f"[wp] sync page {page} failed: {e}")
            break
        if first_page is None:
            first_page = data.get("info", {})
        plugins = data.get("plugins", []) or []
        if not plugins:
            break
        stop = False
        for p in plugins:
            if not p.get("slug"):
                continue
            if since:
                lu = _day(p.get("last_updated"))
                if lu < since:
                    stop = True
                    continue
            wpdb.upsert_plugin(_slim(p))
            total += 1
            if _day(p.get("added")) == _day(p.get("last_updated")) and since:
                added_new += 1
        if stop:
            break
        page += 1
    out = {"browse": ("updated" if since else browse), "per_page": per_page,
           "synced": total, "pages_scanned": page, "catalog_info": first_page}
    if since:
        out["since"] = since
        out["newly_published"] = added_new
    return out


# --- download + extract -----------------------------------------------------

def _extract_zip(zip_path: Path, dest: Path) -> Path:
    """Extract a plugin zip into dest, stripping a single common top-level dir so
    dest itself becomes the plugin root. Returns dest. Guards against path
    traversal (Zip Slip) — safe on both Linux and Windows."""
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        tops = {n.split("/", 1)[0] for n in names}
        strip = (len(tops) == 1)
        top = next(iter(tops)) if strip else ""
        for member in zf.infolist():
            if member.is_dir():
                continue
            rel = member.filename
            if strip and rel.startswith(top + "/"):
                rel = rel[len(top) + 1:]
            if not rel:
                continue
            out = (dest / rel).resolve()
            if not str(out).startswith(str(dest.resolve())):
                eprint(f"[wp] skipping unsafe path in zip: {member.filename}")
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(out, "wb") as fh:
                shutil.copyfileobj(src, fh)
    return dest


def download(slug: str, version: str | None = None,
             download_link: str | None = None) -> dict:
    """Fetch the plugin archive and extract it into TARGET_DIR (the plugin root).
    Falls back to the stable download URL if no explicit link is known."""
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    if not download_link:
        rec = wpdb.get_plugin(slug)
        download_link = (rec or {}).get("download_link")
    if not download_link:
        # canonical stable archive; version-pinned if we know it
        download_link = (f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
                         if version else f"https://downloads.wordpress.org/plugin/{slug}.zip")
    fname = download_link.rstrip("/").split("/")[-1] or f"{slug}.zip"
    zip_path = ARCHIVE_DIR / slug / fname
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(download_link, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as resp, open(zip_path, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    root = _extract_zip(zip_path, TARGET_DIR)
    return {"slug": slug, "archive": str(zip_path), "download_link": download_link,
            "plugin_root": str(root), "bytes": zip_path.stat().st_size}


# --- per-version diff (git-like incremental across releases) -----------------

MANIFEST = lambda: STATE_DIR / "manifest.json"          # noqa: E731
LAST_VERSION = lambda: STATE_DIR / "last_version.txt"    # noqa: E731
SKIP = {".git", "node_modules", "vendor", "__pycache__", "dist", "build"}


def _manifest(root: Path) -> dict:
    """relpath -> sha1 for every file under the plugin root (skipping vendor)."""
    out: dict[str, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP for part in p.relative_to(root).parts[:-1]):
            continue
        h = hashlib.sha1()
        try:
            h.update(p.read_bytes())
        except OSError:
            continue
        out[p.relative_to(root).as_posix()] = h.hexdigest()
    return out


def _diff(prev: dict, cur: dict) -> list[str]:
    changed = [f for f, h in cur.items() if prev.get(f) != h]
    changed += [f for f in prev if f not in cur]   # deletions
    return sorted(set(changed))


def read_last_version() -> str | None:
    p = LAST_VERSION()
    return p.read_text(encoding="utf-8").strip() if p.exists() else None


def prep(slug: str) -> dict:
    """The one call a cycle runs per plugin: resolve info, download+extract,
    diff against the previously analyzed version, detect shape. Mirror of
    pipeline.py prep, for WordPress plugins."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    # resolve current info (DB first, else live API)
    rec = wpdb.get_plugin(slug)
    if not rec or not rec.get("download_link"):
        try:
            info = _slim(plugin_information(slug))
            wpdb.upsert_plugin(info)
            rec = wpdb.get_plugin(slug)
        except Exception as e:  # noqa: BLE001
            eprint(f"[wp] plugin_information({slug}) failed: {e}")
    version = (rec or {}).get("version")
    prev_version = (rec or {}).get("analyzed_version")

    prev_manifest = {}
    if MANIFEST().exists():
        try:
            prev_manifest = json.loads(MANIFEST().read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            prev_manifest = {}

    dl = download(slug, version, (rec or {}).get("download_link"))
    root = Path(dl["plugin_root"])
    cur_manifest = _manifest(root)
    changed = _diff(prev_manifest, cur_manifest)
    is_first = not prev_manifest

    shape = repo.detect_shape()

    wpdb.set_plugin_status(slug, "downloaded")
    MANIFEST().write_text(json.dumps(cur_manifest, indent=0), encoding="utf-8")

    return {
        "when": now_iso(), "slug": slug, "name": (rec or {}).get("name"),
        "version": version, "prev_version": prev_version,
        "is_first_scan": is_first,
        "changed_files": changed, "changed_count": len(changed),
        "file_count": len(cur_manifest),
        "active_installs": (rec or {}).get("active_installs"),
        "plugin_root": str(root), "archive": dl["archive"],
        "shape": shape,
    }


def record(slug: str) -> dict:
    """After a cycle: mirror this plugin's findings.json into the DB and mark it
    analyzed at its current version."""
    import store  # noqa: E402  (keyed to this slug via env)
    rec = wpdb.get_plugin(slug)
    version = (rec or {}).get("version")
    findings = store.query()   # all findings for this plugin
    for f in findings:
        wpdb.sync_finding(slug, f.get("last_commit") or version, f)
    hi = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
    cr = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
    wpdb.set_plugin_status(slug, "analyzed", analyzed_version=version)
    return {"slug": slug, "analyzed_version": version,
            "findings_synced": len(findings), "high": hi, "critical": cr}


# --- CLI --------------------------------------------------------------------

def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def main() -> None:
    ap = argparse.ArgumentParser(prog="wp", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sync"); p.add_argument("--browse", default="updated")
    p.add_argument("--pages", type=int, default=3); p.add_argument("--per-page", type=int, default=100)
    p.add_argument("--since", help="window (today|week|month) or ISO date YYYY-MM-DD: only sync plugins updated on/after it")

    p = sub.add_parser("list"); p.add_argument("--browse", default="updated")
    p.add_argument("--page", type=int, default=1); p.add_argument("--per-page", type=int, default=50)

    p = sub.add_parser("next-batch"); p.add_argument("--count", type=int, default=10)
    p.add_argument("--min-active-installs", type=int, default=0)
    p.add_argument("--updated-since", help="window (today|week|month) or ISO date: only plugins updated on/after it")
    p = sub.add_parser("pending"); p.add_argument("--min-active-installs", type=int, default=0)
    p.add_argument("--updated-since", help="window (today|week|month) or ISO date: count only within this window")

    p = sub.add_parser("info"); p.add_argument("--slug", required=True)
    p = sub.add_parser("prep"); p.add_argument("--slug", required=True)
    p = sub.add_parser("download"); p.add_argument("--slug", required=True); p.add_argument("--version")
    p = sub.add_parser("record"); p.add_argument("--slug", required=True)

    args = ap.parse_args()
    if args.cmd == "sync":
        _print(sync(args.browse, args.pages, args.per_page, since=args.since))
    elif args.cmd == "list":
        data = query_plugins(args.browse, args.page, args.per_page)
        for p in data.get("plugins", []) or []:
            if p.get("slug"):
                wpdb.upsert_plugin(_slim(p))
        _print({"info": data.get("info"), "plugins": [_slim(p) for p in data.get("plugins", [])]})
    elif args.cmd == "next-batch":
        since = _resolve_since(args.updated_since)
        _print(wpdb.next_batch(args.count, args.min_active_installs, updated_since=since))
    elif args.cmd == "pending":
        since = _resolve_since(args.updated_since)
        _print({"pending": wpdb.pending_count(args.min_active_installs, updated_since=since),
                "updated_since": since})
    elif args.cmd == "info":
        _print(_slim(plugin_information(args.slug)))
    elif args.cmd == "prep":
        _print(prep(args.slug))
    elif args.cmd == "download":
        _print(download(args.slug, args.version))
    elif args.cmd == "record":
        _print(record(args.slug))


if __name__ == "__main__":
    main()
