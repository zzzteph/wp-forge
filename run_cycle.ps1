# WP-FORGE — headless cycle runner (Windows / PowerShell).
#
# Runs ONE batch cycle of WordPress-plugin analysis via Claude Code, then exits.
# Point Windows Task Scheduler at this file to run "from time to time".
#
# Register a scheduled task (every 6 hours, example):
#   $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
#                -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\run_cycle.ps1`""
#   $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
#                -RepetitionInterval (New-TimeSpan -Hours 6)
#   Register-ScheduledTask -TaskName "wp-forge" -Action $action -Trigger $trigger
#
# Unregister:  Unregister-ScheduledTask -TaskName "wp-forge" -Confirm:$false
#
# Optional: pass a single plugin slug to analyze just that plugin:
#   .\run_cycle.ps1 -Slug woocommerce

param([string]$Slug = "")

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

New-Item -ItemType Directory -Force -Path "$PSScriptRoot\logs" | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$log   = "$PSScriptRoot\logs\cycle-$stamp.log"
$lock  = "$PSScriptRoot\logs\.cycle.lock"

# Prevent overlapping cycles (a run can outlast the scheduler interval).
if (Test-Path $lock) {
    $age = (Get-Date) - (Get-Item $lock).LastWriteTime
    if ($age.TotalHours -lt 12) {
        "[wp-forge] a cycle is already running (lock age $([int]$age.TotalMinutes)m); skipping." |
            Tee-Object -FilePath $log -Append
        exit 0
    }
    Remove-Item $lock -Force   # stale lock
}
New-Item -ItemType File -Path $lock -Force | Out-Null

if ($Slug) {
    $prompt = @"
Follow opt/wp_workflow.md to run exactly one WordPress-plugin analysis cycle for plugin $Slug.
Work fully non-interactively: never ask questions, make reasonable choices, honour the
notify-only guardrail (local notifications only: console + notifications.log), and finish by tearing down the docker
sandbox. This is an automated scheduled run.
"@
} else {
    $prompt = @"
Follow opt/wp_workflow.md to run exactly one WordPress-plugin analysis cycle (a batch of the
most-recently-updated plugins). Work fully non-interactively: never ask questions, make
reasonable choices, honour the notify-only guardrail (local notifications only: console + notifications.log), and finish
by tearing down the docker sandbox. This is an automated scheduled run.
"@
}

# Optional: pin a stronger model for analysis by adding e.g. --model opus below.
$claudeArgs = @("-p", $prompt, "--dangerously-skip-permissions")

try {
    "[wp-forge] cycle start $stamp" | Tee-Object -FilePath $log -Append
    & claude @claudeArgs 2>&1 | Tee-Object -FilePath $log -Append
    "[wp-forge] cycle end (exit $LASTEXITCODE)" | Tee-Object -FilePath $log -Append
}
catch {
    "[wp-forge] ERROR: $_" | Tee-Object -FilePath $log -Append
}
finally {
    Remove-Item $lock -Force -ErrorAction SilentlyContinue
    # Keep the last 40 logs.
    Get-ChildItem "$PSScriptRoot\logs\cycle-*.log" | Sort-Object LastWriteTime -Descending |
        Select-Object -Skip 40 | Remove-Item -Force -ErrorAction SilentlyContinue
}
