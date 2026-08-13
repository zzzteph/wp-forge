# wp-forge — first-time setup for a fresh copy (Windows / PowerShell).
# Installs the one Python dep, initializes the DB, and pre-pulls the WordPress
# verification-sandbox docker images.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "== wp-forge setup ==" -ForegroundColor Cyan

# 1) Python dep (PyYAML). Everything else is stdlib.
Write-Host "-> installing Python deps (PyYAML)"
python -m pip install --quiet --upgrade -r requirements.txt

# 2) Seed .env from the template if missing (optional — no secrets are required).
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "-> created .env (optional; wp-forge needs no secrets to run)"
}

# 3) Initialize the durable plugin/vulnerability DB.
Write-Host "-> initializing the plugin/vulnerability DB (db\wp-forge.db)"
python scripts\wpdb.py init | Out-Null
python scripts\pipeline.py setup | Out-Null

# 4) Pre-pull the WordPress verification sandbox images (skip with -NoPull).
if ($args -contains "-NoPull") {
    Write-Host "-> skipping docker image pull (-NoPull)"
} else {
    Write-Host "-> pulling WordPress sandbox images (wordpress, mariadb, wordpress:cli, curl)"
    foreach ($img in @("wordpress:php8.2-apache", "mariadb:11", "wordpress:cli", "curlimages/curl:latest")) {
        try { docker pull $img } catch { Write-Host "   (skip $img — docker not available?)" -ForegroundColor DarkYellow }
    }
}

Write-Host ""
Write-Host "Setup done. Next:" -ForegroundColor Green
Write-Host "  1. Run a cycle:   claude --dangerously-skip-permissions   then type  /wp-forge"
Write-Host "     or point at:    Follow opt/wp_workflow.md"
Write-Host "     or headless:    .\run_cycle.ps1"
Write-Host ""
Write-Host "  Inspect the DB:   python scripts\wpdb.py summary"
Write-Host "  Findings + progress are printed and saved to knowledge\<slug>\notifications.log"
