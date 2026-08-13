"""WP-FORGE — scaffold a self-contained, runnable PoC bundle for a verified finding.

Given a finding id (from the DB), writes pocs/<slug>/<id>/ containing:

  docker-compose.yml   WordPress + MariaDB + the pinned plugin, auto-installed
                       (core install + plugin activate + admin/subscriber seed)
  poc.py               stdlib orchestrator: brings the stack up, waits for WP,
                       runs the exploit, prints PASS/FAIL + evidence, tears down.
                       Has a clearly-marked EXPLOIT section the finding-verifier
                       fills in with the finding's concrete request.
  plugin/              the exact plugin source under test (copied from target/)
  finding.json         the finding metadata (title, file:line, reachability, poc)
  README.md            two-command manual repro

Anyone with Docker can reproduce the bug with:  python poc.py

Stdlib only; runs on Linux and Windows. Keyed per plugin like the rest of the
pipeline (sets SECANAL_TARGET_REPO from --slug so paths resolve).

CLI:
    python scripts/wp_poc.py scaffold --slug <slug> --id <finding-id> [--port 8899]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path


def _argv_val(flag: str) -> str | None:
    for i, a in enumerate(sys.argv):
        if a == flag and i + 1 < len(sys.argv):
            return sys.argv[i + 1].strip()
        if a.startswith(flag + "="):
            return a.split("=", 1)[1].strip()
    return None


# key per-plugin paths before importing common (same trick as wp.py)
_SLUG = _argv_val("--slug")
if _SLUG:
    os.environ.setdefault("SECANAL_TARGET_REPO", f"https://wordpress.org/plugins/{_SLUG}/")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wpdb  # noqa: E402
from common import ROOT, TARGET_DIR, configure_stdio, eprint  # noqa: E402

configure_stdio()


# ---------------------------------------------------------------------------
# Templates. Placeholders are %%NAME%% (replaced via str.replace) so the YAML /
# Python braces in the bodies are left untouched.
# ---------------------------------------------------------------------------

COMPOSE_TMPL = """# wp-forge PoC — WordPress + MariaDB + %%SLUG%% (auto-installed).
# Reproducible sandbox for finding %%FINDING_ID%%. Brought up by poc.py.
services:
  db:
    image: mariadb:11
    environment:
      MARIADB_ROOT_PASSWORD: root
      MARIADB_DATABASE: wordpress
      MARIADB_USER: wp
      MARIADB_PASSWORD: wp
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 5s
      timeout: 5s
      retries: 30
    tmpfs:
      - /var/lib/mysql          # ephemeral DB; nothing persists after teardown

  wp:
    image: wordpress:php8.2-apache
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "127.0.0.1:%%PORT%%:80"    # loopback only
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wp
      WORDPRESS_DB_PASSWORD: wp
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_DEBUG: "1"
    volumes:
      - wpdata:/var/www/html
      - ./plugin:/var/www/html/wp-content/plugins/%%SLUG%%

  # one-shot: waits for core files, installs WP, activates the plugin, seeds users
  install:
    image: wordpress:cli
    depends_on:
      - wp
    user: "33:33"
    volumes:
      - wpdata:/var/www/html
      - ./plugin:/var/www/html/wp-content/plugins/%%SLUG%%
    entrypoint: ["sh", "-c"]
    command:
      - >
        until wp core version --path=/var/www/html >/dev/null 2>&1; do
          echo '[poc] waiting for WordPress core files...'; sleep 3; done;
        wp core install --path=/var/www/html --url="http://localhost:%%PORT%%"
          --title="wp-forge PoC" --admin_user=admin --admin_password="Adm!nPoc12345"
          --admin_email=admin@wp-forge.test --skip-email;
        wp plugin activate %%SLUG%% --path=/var/www/html;
        wp user create subscriber sub@wp-forge.test --role=subscriber
          --user_pass="Sub!Poc12345" --path=/var/www/html || true;
        echo '[poc] install complete';
    restart: "no"

volumes:
  wpdata:
"""


POC_TMPL = r'''#!/usr/bin/env python3
"""Runnable PoC for wp-forge finding %%FINDING_ID%% in the "%%SLUG%%" plugin (v%%VERSION%%).

    %%TITLE%%
    %%FILE%%:%%LINE%%   (%%CATEGORY%%)
    reachability: %%REACHABILITY%%

Usage:
    python poc.py            # up -> wait -> run exploit -> print verdict -> tear down
    python poc.py --keep     # leave the stack running afterwards (for manual poking)
    python poc.py --down     # just tear the stack down

Requires Docker (+ compose). Stdlib only. The WordPress admin URL is
http://127.0.0.1:%%PORT%%  (admin/Adm!nPoc12345, subscriber/Sub!Poc12345).
"""
import argparse, http.cookiejar, subprocess, sys, time, urllib.parse, urllib.request

PROJECT = "wpforgepoc_%%FINDING_ID%%"
BASE    = "http://127.0.0.1:%%PORT%%"
SLUG    = "%%SLUG%%"
ADMIN   = ("admin", "Adm!nPoc12345")
SUB     = ("subscriber", "Sub!Poc12345")


def _compose(*args):
    return subprocess.run(["docker", "compose", "-p", PROJECT, *args]).returncode


def up():
    print("[poc] bringing up WordPress + MariaDB + the plugin ...")
    _compose("up", "-d")


def down():
    print("[poc] tearing down ...")
    _compose("down", "-v")


def wait_ready(timeout=240):
    print("[poc] waiting for WordPress to finish installing ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(BASE + "/wp-login.php", timeout=5) as r:
                if r.status == 200:
                    print("[poc] WordPress is up.")
                    return True
        except Exception:
            pass
        time.sleep(4)
    print("[poc] TIMED OUT waiting for WordPress.")
    return False


def session():
    """A urllib opener with a cookie jar (for login-based flows)."""
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def login(user, password):
    """Log in and return an opener carrying the auth cookies (or None)."""
    op = session()
    op.open(BASE + "/wp-login.php", timeout=10)  # sets test cookie
    data = urllib.parse.urlencode({
        "log": user, "pwd": password, "wp-submit": "Log In",
        "redirect_to": BASE + "/wp-admin/", "testcookie": "1",
    }).encode()
    op.open(BASE + "/wp-login.php", data=data, timeout=10)
    return op


def get(op, path, timeout=15):
    with op.open(BASE + path, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def post(op, path, fields, timeout=15):
    body = urllib.parse.urlencode(fields).encode()
    with op.open(BASE + path, data=body, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


# ===========================================================================
# EXPLOIT — the finding-verifier fills this in with the concrete request(s).
# Return (passed: bool, evidence: str). Keep it benign: prove, don't damage.
#
# Finding PoC hint (from analysis):
#   %%POC%%
#
# Handy primitives above: login(user, pass) -> opener; get(op, path);
# post(op, path, {fields}). Use SUB for the subscriber principal, ADMIN for admin,
# or an unauthenticated `session()` for pre-auth bugs. Example skeletons:
#
#   # missing-authz / nopriv AJAX (pre-auth):
#   op = session()
#   st, body = post(op, "/wp-admin/admin-ajax.php?action=SOME_ACTION", {"id": "1"})
#   return ("secret" in body, f"status={st} body[:200]={body[:200]!r}")
#
#   # IDOR / broken access control (subscriber acting on an admin object):
#   op = login(*SUB)
#   st, body = get(op, "/wp-admin/admin-ajax.php?action=SOME_ACTION&id=1")
#   return (st == 200 and "OTHER_USER_DATA" in body, f"status={st} ...")
#
#   # SQLi (time-based): compare response time of a SLEEP payload vs control.
# ===========================================================================
def exploit():
    # TODO(finding-verifier): replace this stub with the real PoC for %%FINDING_ID%%.
    return (False, "exploit() not implemented yet — fill in the request for this finding")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the stack up afterwards")
    ap.add_argument("--down", action="store_true", help="just tear the stack down")
    args = ap.parse_args()
    if args.down:
        down(); return
    up()
    try:
        if not wait_ready():
            sys.exit(2)
        passed, evidence = exploit()
        print("\n" + "=" * 68)
        print(f"[poc] finding %%FINDING_ID%% ({SLUG}): "
              f"{'VULNERABLE (PoC succeeded)' if passed else 'not reproduced'}")
        print(f"[poc] evidence: {evidence}")
        print("=" * 68)
        sys.exit(0 if passed else 1)
    finally:
        if not args.keep:
            down()
        else:
            print(f"[poc] left running at {BASE} (admin/Adm!nPoc12345). "
                  f"Tear down: docker compose -p {PROJECT} down -v")


if __name__ == "__main__":
    main()
'''


README_TMPL = """# PoC — %%TITLE%%

**Plugin:** `%%SLUG%%` v%%VERSION%%  ·  **Finding:** `%%FINDING_ID%%`
**Location:** `%%FILE%%:%%LINE%%`  (%%CATEGORY%%)
**Reachability:** %%REACHABILITY%%

Self-contained, runnable proof of concept. It spins up a throwaway WordPress +
MariaDB, installs and activates the exact plugin version under test, seeds an
admin and a subscriber, then fires the exploit and reports whether it worked.

## Requirements
Docker (with the Compose plugin). Nothing else — the PoC script is pure Python
stdlib and runs on Linux and Windows.

## Run
```bash
python poc.py            # up -> wait -> exploit -> verdict -> tear down
python poc.py --keep     # …but leave WordPress running afterwards for manual poking
python poc.py --down     # tear a left-running stack down
```
Exit code `0` = the PoC reproduced the vulnerability; `1` = it did not; `2` =
the sandbox failed to come up.

WordPress is exposed on **http://127.0.0.1:%%PORT%%** (loopback only) while it
runs. Credentials: `admin` / `Adm!nPoc12345`, `subscriber` / `Sub!Poc12345`.

## What it does
`docker-compose.yml` defines three services: `db` (MariaDB, ephemeral tmpfs),
`wp` (WordPress with the plugin bind-mounted from `./plugin`), and a one-shot
`install` job that waits for core, runs `wp core install`, activates the plugin,
and creates the two principals. `poc.py` brings the stack up, waits for it, runs
`exploit()`, prints the evidence, and tears everything down (`down -v`).

## Safety
Everything is bound to `127.0.0.1`, the database is ephemeral (tmpfs), and the
exploit is benign (it proves the flaw, it does not damage). Only run against
plugins you are authorized to test.
"""


def _sub(tmpl: str, mapping: dict) -> str:
    out = tmpl
    for k, v in mapping.items():
        out = out.replace(f"%%{k}%%", str(v if v is not None else ""))
    return out


def scaffold(slug: str, finding_id: str, port: int = 8899) -> dict:
    f = None
    for row in wpdb.query_findings(slug=slug):
        if row.get("id") == finding_id:
            f = row
            break
    if not f:
        raise SystemExit(f"finding {finding_id} not found for plugin {slug} in the DB")
    plugin = wpdb.get_plugin(slug) or {}

    out_dir = ROOT / "pocs" / slug / finding_id      # each plugin gets its own folder; each finding a subfolder
    out_dir.mkdir(parents=True, exist_ok=True)

    # copy the exact plugin source under test (self-contained bundle)
    dest_plugin = out_dir / "plugin"
    if TARGET_DIR.exists() and any(TARGET_DIR.iterdir()):
        if dest_plugin.exists():
            shutil.rmtree(dest_plugin, ignore_errors=True)
        shutil.copytree(TARGET_DIR, dest_plugin,
                        ignore=shutil.ignore_patterns(".git", "node_modules"))
        plugin_copied = True
    else:
        dest_plugin.mkdir(exist_ok=True)
        (dest_plugin / "PLACE_PLUGIN_HERE.txt").write_text(
            f"Run `python scripts/wp.py prep --slug {slug}` first, then re-scaffold — "
            f"the plugin source (target/) was not present to copy.\n", encoding="utf-8")
        plugin_copied = False

    mapping = {
        "SLUG": slug, "VERSION": plugin.get("version") or f.get("version") or "?",
        "FINDING_ID": finding_id, "PORT": port,
        "TITLE": (f.get("title") or "").replace("\n", " "),
        "FILE": f.get("file") or "?", "LINE": f.get("line") or 0,
        "CATEGORY": f.get("category") or "?",
        "REACHABILITY": (f.get("reachability") or "").replace("\n", " "),
        "POC": (f.get("poc") or "see finding.json").replace("\n", " "),
    }

    (out_dir / "docker-compose.yml").write_text(_sub(COMPOSE_TMPL, mapping), encoding="utf-8")
    (out_dir / "poc.py").write_text(_sub(POC_TMPL, mapping), encoding="utf-8")
    (out_dir / "README.md").write_text(_sub(README_TMPL, mapping), encoding="utf-8")
    (out_dir / "finding.json").write_text(
        json.dumps(f, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    return {"bundle": str(out_dir), "slug": slug, "finding_id": finding_id,
            "plugin_copied": plugin_copied, "port": port,
            "files": ["docker-compose.yml", "poc.py", "README.md", "finding.json", "plugin/"],
            "next": "the finding-verifier fills in poc.py exploit(), then runs `python poc.py`"}


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def main() -> None:
    ap = argparse.ArgumentParser(prog="wp_poc", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scaffold")
    p.add_argument("--slug", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--port", type=int, default=8899)
    args = ap.parse_args()
    if args.cmd == "scaffold":
        _print(scaffold(args.slug, args.id, args.port))


if __name__ == "__main__":
    main()
