#!/usr/bin/env bash
# WP-FORGE — headless cycle runner (Linux / macOS / WSL / git-bash).
# Runs ONE batch cycle of WordPress-plugin analysis via Claude Code, then exits.
#
# Cron example (every 6 hours):
#   0 */6 * * * /path/to/wp-forge/run_cycle.sh >> /path/to/wp-forge/logs/cron.log 2>&1
#
# Optional args:
#   ./run_cycle.sh                 # analyze a batch of most-recently-updated plugins
#   ./run_cycle.sh <plugin-slug>   # analyze just one plugin
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs
stamp="$(date +%Y%m%d-%H%M%S)"
log="logs/cycle-${stamp}.log"
lock="logs/.cycle.lock"

# Prevent overlapping cycles.
if [ -f "$lock" ]; then
  if [ "$(( $(date +%s) - $(stat -c %Y "$lock" 2>/dev/null || stat -f %m "$lock") ))" -lt 43200 ]; then
    echo "[wp-forge] a cycle is already running; skipping." | tee -a "$log"; exit 0
  fi
  rm -f "$lock"
fi
touch "$lock"
trap 'rm -f "$lock"' EXIT

SLUG="${1:-}"
if [ -n "$SLUG" ]; then
  PROMPT="Follow opt/wp_workflow.md to run exactly one WordPress-plugin analysis cycle for plugin ${SLUG}. Work fully non-interactively: never ask questions, make reasonable choices, honour the notify-only guardrail (local notifications only: console + notifications.log), and finish by tearing down the docker sandbox. This is an automated scheduled run."
else
  PROMPT="Follow opt/wp_workflow.md to run exactly one WordPress-plugin analysis cycle (a batch of the most-recently-updated plugins). Work fully non-interactively: never ask questions, make reasonable choices, honour the notify-only guardrail (local notifications only: console + notifications.log), and finish by tearing down the docker sandbox. This is an automated scheduled run."
fi

echo "[wp-forge] cycle start $stamp" | tee -a "$log"
# Add e.g. --model opus for stronger analysis.
claude -p "$PROMPT" --dangerously-skip-permissions 2>&1 | tee -a "$log"
echo "[wp-forge] cycle end" | tee -a "$log"

# Keep the last 40 logs.
ls -1t logs/cycle-*.log 2>/dev/null | tail -n +41 | xargs -r rm -f
