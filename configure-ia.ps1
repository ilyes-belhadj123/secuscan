# Configure la clé OpenRouter dans .env, en saisie masquée (la clé n'est jamais affichée).
# Usage : clic droit > Exécuter avec PowerShell, ou `powershell -ExecutionPolicy Bypass -File configure-ia.ps1`
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $root ".env"

if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $root ".env.example") $envFile
}

$secure = Read-Host "Collez votre nouvelle clé OpenRouter (saisie masquée)" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim()
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if (-not $key.StartsWith("sk-or-")) {
    Write-Host "Clé invalide : elle doit commencer par sk-or-. Rien n'a été modifié." -ForegroundColor Red
    exit 1
}

$lines = @(Get-Content $envFile | Where-Object { $_ -notmatch '^\s*OPENROUTER_API_KEY\s*=' })
$lines += "OPENROUTER_API_KEY=$key"
# UTF-8 sans BOM : un BOM rendrait la première variable illisible
[IO.File]::WriteAllLines($envFile, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
$key = $null

Write-Host "Clé enregistrée dans .env (fichier exclu de Git)." -ForegroundColor Green
Write-Host "Redémarrez l'API (ou start-demo.ps1) pour activer l'IA."
