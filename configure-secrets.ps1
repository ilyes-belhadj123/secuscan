# Renseigne les secrets de SecuScan dans .env, en saisie masquée : aucune valeur n'est affichée.
# Usage : clic droit > Exécuter avec PowerShell, ou `powershell -ExecutionPolicy Bypass -File configure-secrets.ps1`
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) { Copy-Item (Join-Path $root ".env.example") $envFile }

function Read-Secret([string]$prompt) {
    $secure = Read-Host $prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Set-EnvValue([string]$name, [string]$value) {
    $lines = @(Get-Content $envFile | Where-Object { $_ -notmatch "^\s*$name\s*=" })
    $lines += "$name=$value"
    # UTF-8 sans BOM : un BOM rendrait la première variable illisible
    [IO.File]::WriteAllLines($envFile, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
}

Write-Host "Que voulez-vous configurer ?"
Write-Host "  1. Clé OpenRouter (IA)"
Write-Host "  2. Application OAuth GitHub (dépôts privés)"
Write-Host "  3. Application OAuth GitLab (dépôts privés)"
$choice = Read-Host "Votre choix (1, 2 ou 3)"

switch ($choice) {
    "1" {
        $key = Read-Secret "Clé OpenRouter (saisie masquée)"
        if (-not $key.StartsWith("sk-or-")) { Write-Host "Clé invalide (doit commencer par sk-or-)." -ForegroundColor Red; exit 1 }
        Set-EnvValue "OPENROUTER_API_KEY" $key
    }
    { $_ -in "2", "3" } {
        $prefix = if ($choice -eq "2") { "SECUSCAN_GITHUB" } else { "SECUSCAN_GITLAB" }
        $id = Read-Host "Client ID de l'application (non secret)"
        $secret = Read-Secret "Client secret (saisie masquée)"
        if (-not $id -or -not $secret) { Write-Host "Valeurs manquantes : rien n'a été modifié." -ForegroundColor Red; exit 1 }
        Set-EnvValue "${prefix}_CLIENT_ID" $id
        Set-EnvValue "${prefix}_CLIENT_SECRET" $secret
        # Clé de chiffrement des jetons : générée une seule fois (la changer rendrait les jetons illisibles)
        if (-not (Select-String -Path $envFile -Pattern "^\s*SECUSCAN_TOKEN_KEY\s*=\s*\S" -Quiet)) {
            $bytes = New-Object byte[] 32
            [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
            Set-EnvValue "SECUSCAN_TOKEN_KEY" ([Convert]::ToBase64String($bytes))
            Write-Host "Clé de chiffrement des jetons générée." -ForegroundColor Green
        }
    }
    default { Write-Host "Choix inconnu." -ForegroundColor Red; exit 1 }
}
$key = $null; $secret = $null
Write-Host "Enregistré dans .env (fichier exclu de Git). Redémarrez l'API pour l'appliquer." -ForegroundColor Green
