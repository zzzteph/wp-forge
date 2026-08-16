#!/usr/bin/env python3
"""WP-FORGE — per-plugin orchestrator (maximum reliability).

Runs a DEDICATED headless Claude session for EACH plugin, one at a time, with a
hard per-plugin wall-clock timeout. Whatever a single session does — finishes,
stalls, gets killed by a platform cyber-safeguard, errors, or refuses — the
orchestrator kills it at the deadline, tears down the sandbox, records the outcome
in the durable DB, and moves on to the NEXT plugin. It never stops for one plugin.

Why this is reliable: the orchestrator itself is a plain subprocess manager and
holds *no model context*, so it can drain thousands of plugins that no single
Claude session could. Each plugin gets a fresh session that sees only that one
plugin — context exhaustion, cross-plugin bleed, and "it stopped after 64" all go
away. Failures are bounded and isolated per plugin.

Usage:
  python orchestrate.py                         # skill=critical, window=week
  python orchestrate.py --skill sqli --window month
  python orchestrate.py --skill full --window all --timeout 1800
  python orchestrate.py --dry-run               # list what it would do, launch nothing

Each plugin's session logs to logs/orch-<slug>-<ts>.log. Fully resumable: the DB
tracks analyzed/error/skipped, so re-running continues from what's left.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable or "python"
SKILLS = {"critical", "sqli", "unauth", "path-trav", "full"}


def _helper_json(script: str, *args):
    """Run a wp.py / wpdb.py subcommand and parse its JSON stdout (or None)."""
    r = subprocess.run([PY, str(ROOT / "scripts" / script), *args],
                       cwd=str(ROOT), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def wp(*a):
    return _helper_json("wp.py", *a)


def wpdb(*a):
    return _helper_json("wpdb.py", *a)


def pending_count(window: str) -> int:
    a = ["pending"] + ([] if window == "all" else ["--updated-since", window])
    return int((wp(*a) or {}).get("pending", 0))


def next_slugs(window: str, count: int) -> list:
    a = ["next-batch", "--count", str(count)] + \
        ([] if window == "all" else ["--updated-since", window])
    r = wp(*a)
    return [p["slug"] for p in r if p.get("slug")] if isinstance(r, list) else []


def build_prompt(slug: str, skill: str) -> str:
    scope = ("Follow opt/wp_workflow.md sections 3-9 for this one plugin."
             if skill == "full" else
             f"Follow opt/wp_workflow.md sections 3-9 for this one plugin, and only "
             f"record findings that match the scope in .claude/skills/{skill}/SKILL.md.")
    return (
        f"You are analyzing EXACTLY ONE WordPress plugin: '{slug}'. {scope} "
        f"Steps, for this slug only: run `python scripts/wp.py prep --slug {slug}`, "
        f"build/refresh its model, hunt for HIGH/CRITICAL PHP bugs, verify real "
        f"candidates in the Docker sandbox, scaffold a PoC + Docker bundle for every "
        f"HIGH/CRITICAL, then `python scripts/wp.py record --slug {slug}` to mark it "
        f"analyzed, and finally `python scripts/verify.py nuke`. Do NOT analyze any "
        f"other plugin, do NOT loop to a next plugin, never ask questions, and keep "
        f"everything local (notify-only). Stop as soon as this one plugin is recorded."
    )


def _kill_tree(p: subprocess.Popen):
    """Hard-kill the session and any children (docker etc.) it spawned."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                           capture_output=True)
    except Exception:
        pass
    try:
        p.wait(timeout=30)
    except Exception:
        pass


def run_session(prompt: str, claude: str, model: str, timeout: int, log_path: Path) -> int:
    """Launch one headless Claude session, bounded by a hard timeout. Returns the
    exit code, or 124 if it was killed at the deadline. Never raises."""
    cmd = [claude, "-p", prompt, "--dangerously-skip-permissions"]
    if model:
        cmd += ["--model", model]
    popen_kw = {}
    if os.name == "posix":
        popen_kw["start_new_session"] = True          # own process group → killpg
    else:
        popen_kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as log:
            p = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log,
                                 stderr=subprocess.STDOUT, **popen_kw)
            try:
                return p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_tree(p)
                return 124
    except FileNotFoundError:
        print(f"[orch] FATAL: '{claude}' not found — install Claude Code or pass "
              f"--claude <path>.", file=sys.stderr)
        raise SystemExit(2)


def cleanup(slug: str):
    """Guarantee teardown after every session: nuke the sandbox and wipe this
    plugin's disposable scratch, so the next plugin starts clean even on a kill."""
    subprocess.run([PY, str(ROOT / "scripts" / "verify.py"), "nuke"],
                   cwd=str(ROOT), capture_output=True, text=True)
    import shutil
    for sub in ("archives", "target/wordpress.org/plugins"):
        try:
            shutil.rmtree(ROOT / sub / slug, ignore_errors=True)
        except Exception:
            pass


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skill", default="critical", choices=sorted(SKILLS),
                    help="analysis scope (default: critical)")
    ap.add_argument("--window", default="week",
                    help="today | week | month | all | ISO date (default: week)")
    ap.add_argument("--timeout", type=int, default=1500,
                    help="hard per-plugin session timeout, seconds (default: 1500)")
    ap.add_argument("--max-plugins", type=int, default=0,
                    help="stop after N plugins this run (0 = until the scope is empty)")
    ap.add_argument("--max-attempts", type=int, default=2,
                    help="skip a plugin after this many aborted sessions across runs")
    ap.add_argument("--claude", default=os.environ.get("CLAUDE_BIN", "claude"),
                    help="path to the Claude Code CLI (default: claude)")
    ap.add_argument("--model", default="", help="optional --model to pass through")
    ap.add_argument("--no-sync", action="store_true",
                    help="skip the catalog sync (use the DB as-is)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and launch nothing")
    args = ap.parse_args()

    (ROOT / "logs").mkdir(exist_ok=True)

    # Preflight: ensure DB, retire poison-pills from prior runs, refresh the window.
    wpdb("init")
    if not args.dry_run:
        wpdb("reap-stale", "--max-attempts", str(args.max_attempts))
        if not args.no_sync and args.window != "all":
            wp("sync", "--since", args.window)

    total = pending_count(args.window)
    print(f"[orch] skill={args.skill} window={args.window} pending={total} "
          f"timeout={args.timeout}s{' (DRY-RUN)' if args.dry_run else ''}")

    attempted, analyzed, errored, skipped, n = set(), 0, 0, 0, 0
    while True:
        if args.max_plugins and n >= args.max_plugins:
            break
        # pull a big block; filter out anything we've already run this process
        slugs = [s for s in next_slugs(args.window, 200) if s not in attempted]
        if not slugs:
            break
        for slug in slugs:
            if args.max_plugins and n >= args.max_plugins:
                break
            attempted.add(slug)
            n += 1
            ts = time.strftime("%Y%m%d-%H%M%S")
            log = ROOT / "logs" / f"orch-{slug}-{ts}.log"
            if args.dry_run:
                print(f"[orch] ({n}) would analyze {slug} → {log.name}")
                continue
            wpdb("set-status", "--slug", slug, "--status", "analyzing")
            print(f"[orch] ({n}/{total}) {slug} → session (≤{args.timeout}s) {log.name}")
            t0 = time.monotonic()
            rc = run_session(build_prompt(slug, args.skill), args.claude,
                             args.model, args.timeout, log)
            cleanup(slug)
            # a still-'analyzing' plugin means the session didn't finish it →
            # reap-stale converts it to error (retry next run) or skipped (>=N aborts)
            reap = wpdb("reap-stale", "--max-attempts", str(args.max_attempts)) or {}
            row = wpdb("show", "--slug", slug) or {}
            st = row.get("status")
            dt = int(time.monotonic() - t0)
            if st == "analyzed":
                analyzed += 1
                print(f"[orch]   ✓ analyzed {row.get('analyzed_version')} "
                      f"(rc={rc}, {dt}s, HIGH={row.get('high_count',0)} CRIT={row.get('critical_count',0)})")
            elif st == "skipped":
                skipped += 1
                print(f"[orch]   ⤼ skipped after repeated aborts (rc={rc}, {dt}s)")
            else:
                errored += 1
                print(f"[orch]   ✗ not completed (status={st}, rc={rc}, {dt}s) — retry next run")

    print(f"\n[orch] done. sessions={n} analyzed={analyzed} "
          f"error(retry later)={errored} skipped={skipped} remaining≈{pending_count(args.window)}")


if __name__ == "__main__":
    main()
