#!/usr/bin/env bash
# WP-FORGE — drain runner (Linux / macOS / WSL / git-bash).
#
# WHY THIS EXISTS: one Claude session is context-bounded — it analyzes as many
# plugins as fit (often a few dozen), then stops. The durable DB (db/wp-forge.db)
# makes a run resumable, but something has to relaunch it. This script does that:
# it fires FRESH headless cycles back-to-back — each a clean session that resumes
# from the DB at the next unanalyzed plugin — until the scoped queue is empty.
# No parallelism: one cycle runs fully before the next starts. This is the
# supported outer loop; a single cycle is still strictly serial internally.
#
#   ./drain.sh                       # drain the 'critical' mode over the 'week' window
#   ./drain.sh critical week         # explicit skill + window
#   ./drain.sh sqli month            # any focused skill: critical|sqli|unauth|path-trav|full
#   ./drain.sh full all              # the full pipeline over the whole catalog
#   MAX_CYCLES=50 ./drain.sh         # cap the number of cycles this launch will run
set -euo pipefail
cd "$(dirname "$0")"

SKILL="${1:-${SKILL:-critical}}"      # critical | sqli | unauth | path-trav | full
WINDOW="${2:-${WINDOW:-week}}"        # today | week | month | all
MAX_CYCLES="${MAX_CYCLES:-500}"       # safety cap; re-run to continue past it
mkdir -p logs
lock="logs/.drain.lock"

if [ -f "$lock" ] && kill -0 "$(cat "$lock" 2>/dev/null)" 2>/dev/null; then
  echo "[drain] another drain (pid $(cat "$lock")) is running; exiting."; exit 0
fi
echo $$ > "$lock"; trap 'rm -f "$lock"' EXIT

since=(); [ "$WINDOW" != "all" ] && since=(--updated-since "$WINDOW")
pending() {
  python scripts/wp.py pending "${since[@]}" 2>/dev/null \
    | python -c 'import sys,json; print(json.load(sys.stdin).get("pending",0))' 2>/dev/null \
    || echo 0
}

if [ "$SKILL" = "full" ]; then
  scope="Follow opt/wp_workflow.md."
else
  scope="Follow opt/wp_workflow.md, restricting findings to the scope defined in .claude/skills/${SKILL}/SKILL.md."
fi

i=0
while :; do
  p="$(pending)"
  echo "[drain] skill=$SKILL window=$WINDOW pending=$p (cycle $i/$MAX_CYCLES)"
  [ "${p:-0}" -le 0 ] && { echo "[drain] queue empty — scope fully analyzed. Done."; break; }
  [ "$i" -ge "$MAX_CYCLES" ] && { echo "[drain] hit MAX_CYCLES=$MAX_CYCLES; re-run ./drain.sh to continue."; break; }
  i=$((i + 1))
  stamp="$(date +%Y%m%d-%H%M%S)"; log="logs/drain-${stamp}.log"
  prompt="${scope} Scope to plugins updated in the '${WINDOW}' window and drain it. Process as many plugins as you can, STRICTLY ONE AT A TIME, fully non-interactively — never ask questions, notify-only (console + knowledge/<slug>/notifications.log), and tear down the docker sandbox at the end. Resume from the durable DB; when your session is running low on room, stop cleanly (the next cycle continues from what's left). This is an automated drain cycle."
  echo "[drain] cycle $i start $stamp -> $log"
  claude -p "$prompt" --dangerously-skip-permissions 2>&1 | tee -a "$log" \
    || echo "[drain] cycle $i exited non-zero — continuing to next cycle"
done

# Keep the last 60 drain logs.
ls -1t logs/drain-*.log 2>/dev/null | tail -n +61 | xargs -r rm -f
