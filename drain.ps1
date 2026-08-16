# WP-FORGE — drain runner (Windows / PowerShell).
#
# WHY THIS EXISTS: one Claude session is context-bounded — it analyzes as many
# plugins as fit (often a few dozen), then stops. The durable DB (db\wp-forge.db)
# makes a run resumable, but something has to relaunch it. This script does that:
# it fires FRESH headless cycles back-to-back — each a clean session that resumes
# from the DB at the next unanalyzed plugin — until the scoped queue is empty.
# No parallelism: one cycle runs fully before the next starts.
#
#   .\drain.ps1                          # drain the 'critical' mode over the 'week' window
#   .\drain.ps1 -Skill critical -Window week
#   .\drain.ps1 -Skill sqli -Window month   # skill: critical|sqli|unauth|path-trav|full
#   .\drain.ps1 -Skill full -Window all      # full pipeline over the whole catalog
#   .\drain.ps1 -MaxCycles 50                # cap cycles for this launch

param(
    [string]$Skill  = "critical",   # critical | sqli | unauth | path-trav | full
    [string]$Window = "week",       # today | week | month | all
    [int]$MaxCycles = 500
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
New-Item -ItemType Directory -Force -Path "$PSScriptRoot\logs" | Out-Null
$lock = "$PSScriptRoot\logs\.drain.lock"

if (Test-Path $lock) {
    $pid0 = (Get-Content $lock -ErrorAction SilentlyContinue)
    if ($pid0 -and (Get-Process -Id $pid0 -ErrorAction SilentlyContinue)) {
        "[drain] another drain (pid $pid0) is running; exiting."; exit 0
    }
}
Set-Content -Path $lock -Value $PID -Encoding ascii

function Get-Pending {
    $sinceArgs = @()
    if ($Window -ne "all") { $sinceArgs = @("--updated-since", $Window) }
    try {
        $json = & python scripts\wp.py pending @sinceArgs 2>$null | Out-String
        return [int]([regex]::Match($json, '"pending"\s*:\s*(\d+)').Groups[1].Value)
    } catch { return 0 }
}

if ($Skill -eq "full") {
    $scope = "Follow opt/wp_workflow.md."
} else {
    $scope = "Follow opt/wp_workflow.md, restricting findings to the scope defined in .claude/skills/$Skill/SKILL.md."
}

try {
    $i = 0
    while ($true) {
        $p = Get-Pending
        "[drain] skill=$Skill window=$Window pending=$p (cycle $i/$MaxCycles)"
        if ($p -le 0)          { "[drain] queue empty — scope fully analyzed. Done."; break }
        if ($i -ge $MaxCycles) { "[drain] hit MaxCycles=$MaxCycles; re-run .\drain.ps1 to continue."; break }
        $i++
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $log   = "$PSScriptRoot\logs\drain-$stamp.log"
        $prompt = "$scope Scope to plugins updated in the '$Window' window and drain it. Process as many plugins as you can, STRICTLY ONE AT A TIME, fully non-interactively — never ask questions, notify-only (console + knowledge/<slug>/notifications.log), and tear down the docker sandbox at the end. Resume from the durable DB; when your session is running low on room, stop cleanly (the next cycle continues from what's left). This is an automated drain cycle."
        "[drain] cycle $i start $stamp -> $log"
        & claude -p $prompt --dangerously-skip-permissions 2>&1 | Tee-Object -FilePath $log -Append
        if ($LASTEXITCODE -ne 0) { "[drain] cycle $i exited $LASTEXITCODE — continuing" }
    }
}
finally {
    Remove-Item $lock -Force -ErrorAction SilentlyContinue
    Get-ChildItem "$PSScriptRoot\logs\drain-*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -Skip 60 |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
