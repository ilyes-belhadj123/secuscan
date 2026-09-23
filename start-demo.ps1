# Lance SecuScan en local (API + interface web) pour la démo.
# Usage : clic droit > Exécuter avec PowerShell, ou `powershell -ExecutionPolicy Bypass -File start-demo.ps1`
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Installation des dépendances..." -ForegroundColor Cyan
Push-Location "$root\apps\api"; uv sync --quiet; Pop-Location
Push-Location "$root\apps\web"; if (-not (Test-Path node_modules)) { npm install --silent }; Pop-Location

Write-Host "Démarrage de l'API (port 8000) et de l'interface (port 5173)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\apps\api'; uv run python -m uvicorn secuscan.main:app --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\apps\web'; npm run dev -- --host 127.0.0.1"

Start-Sleep -Seconds 5
Start-Process "http://127.0.0.1:5173"
