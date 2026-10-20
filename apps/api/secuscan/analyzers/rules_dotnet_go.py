"""Règles C# (.NET / ASP.NET Core) et Go.

Les injections dont la valeur vient d'une variable (paramètre d'action ASP.NET, r.URL.Query() en
Go…) sont suivies par taint.py ; ces règles couvrent ce qui se voit sur une ligne.
"""
import re

from ..models import Severity
from .rule_model import Rule

C, H, M, L = Severity.critical, Severity.high, Severity.medium, Severity.low
CS, GO = ("csharp",), ("go",)


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


_SENSITIVE = _r(r"token|secret|password|passwd|reset|otp|session|key|nonce", re.I)

DOTNET_GO_RULES: list[Rule] = [
    # ------------------------------------------------------------------ C#
    Rule(
        "CS-SQLI", CS,
        _r(r"(new\s+SqlCommand|\.ExecuteSqlRaw(Async)?|\.FromSqlRaw|\.SqlQueryRaw|\.ExecuteSqlCommand)\(\s*"
           r"(\$@?\"|@?\"[^\"]*\"\s*\+)"),
        "Injection SQL", "CWE-89", C,
        "La requête SQL est construite par concaténation ou interpolation de valeurs.",
        "Utiliser des paramètres : new SqlCommand(\"… WHERE x = @x\", cn) puis Parameters.AddWithValue(\"@x\", v), "
        "ou FromSqlInterpolated / FromSql avec EF Core.",
    ),
    Rule(
        "CS-CMDI", CS,
        _r(r"Process\.Start\([^;]*\+|\.Arguments\s*=\s*[^;]*\+|\.Arguments\s*=\s*\$\""),
        "Injection de commande système", "CWE-78", C,
        "Une commande système est lancée avec des arguments construits par concaténation.",
        "Utiliser ProcessStartInfo.ArgumentList (un argument par élément), UseShellExecute = false, et une liste "
        "blanche des valeurs.",
    ),
    Rule(
        "CS-DESER", CS,
        _r(r"new\s+(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)\("
           r"|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Objects|Auto)"),
        "Désérialisation non sécurisée", "CWE-502", C,
        "BinaryFormatter (ou Json.NET avec TypeNameHandling) peut instancier n'importe quel type : des données "
        "piégées suffisent à exécuter du code.",
        "Utiliser System.Text.Json vers un type précis ; ne jamais désérialiser de types choisis par l'émetteur.",
    ),
    Rule(
        "CS-XXE", CS,
        _r(r"XmlResolver\s*=\s*new\s+XmlUrlResolver|DtdProcessing\s*=\s*DtdProcessing\.Parse"),
        "Entités XML externes (XXE)", "CWE-611", H,
        "Le parseur XML résout les entités externes : un document piégé peut lire des fichiers du serveur.",
        "Laisser XmlResolver à null et DtdProcessing à Prohibit (valeurs par défaut récentes).",
    ),
    Rule(
        "CS-WEAKHASH", CS,
        _r(r"\b(MD5|SHA1)\.(Create|HashData)\(|new\s+(MD5|SHA1)(CryptoServiceProvider|Managed)\("),
        "Algorithme de hachage faible", "CWE-328", M,
        "MD5 / SHA-1 ne protègent plus ni l'intégrité ni les mots de passe.",
        "SHA-256 pour l'intégrité ; Rfc2898DeriveBytes.Pbkdf2 (ou ASP.NET Identity) pour les mots de passe.",
    ),
    Rule(
        "CS-WEAKCIPHER", CS,
        _r(r"\b(DES|TripleDES|RC2)\.Create\(|CipherMode\.ECB|new\s+(DES|TripleDES|RC2)CryptoServiceProvider\("),
        "Chiffrement faible", "CWE-327", M,
        "DES, 3DES, RC2 ou le mode ECB laissent fuiter la structure des données chiffrées.",
        "Utiliser AesGcm avec un nonce aléatoire.",
    ),
    Rule(
        "CS-TLS", CS,
        _r(r"ServerCertificate(Custom)?ValidationCallback\s*\+?=\s*[^;]*=>\s*true|DangerousAcceptAnyServerCertificateValidator"),
        "Vérification TLS désactivée", "CWE-295", H,
        "Tous les certificats sont acceptés : une interception (homme du milieu) passe inaperçue.",
        "Supprimer le contournement ; pour un certificat interne, l'ajouter au magasin de confiance.",
    ),
    Rule(
        "CS-RANDOM", CS,
        _r(r"new\s+Random\("),
        "Générateur aléatoire non cryptographique", "CWE-338", L,
        "System.Random est prévisible et ne doit pas générer de valeurs sensibles.",
        "Utiliser RandomNumberGenerator.GetBytes / GetInt32.",
        context_requires=_SENSITIVE,
    ),
    # ------------------------------------------------------------------ Go
    Rule(
        "GO-SQLI", GO,
        _r(r"\.(Query|QueryRow|Exec|Prepare|Raw)(Context)?\(\s*(ctx\s*,\s*)?(fmt\.Sprintf\(|\"[^\"]*\"\s*\+)"),
        "Injection SQL", "CWE-89", C,
        "La requête SQL est construite avec fmt.Sprintf ou une concaténation.",
        "Passer les valeurs en paramètres : db.Query(\"… WHERE x = $1\", v).",
    ),
    Rule(
        "GO-CMDI", GO,
        _r(r"exec\.Command(Context)?\([^)]*\"\s*\+"),
        "Injection de commande système", "CWE-78", C,
        "Une commande est construite par concaténation (souvent passée à « sh -c »).",
        "Appeler le programme directement, un argument par paramètre : exec.Command(\"ping\", \"-c\", \"1\", hote).",
    ),
    Rule(
        "GO-WEAKHASH", GO,
        _r(r"\b(md5|sha1)\.(New|Sum)\("),
        "Algorithme de hachage faible", "CWE-328", M,
        "MD5 / SHA-1 ne protègent plus ni l'intégrité ni les mots de passe.",
        "crypto/sha256 pour l'intégrité ; golang.org/x/crypto/bcrypt ou argon2 pour les mots de passe.",
    ),
    Rule(
        "GO-WEAKCIPHER", GO,
        _r(r"\b(des\.NewCipher|des\.NewTripleDESCipher|rc4\.NewCipher)\("),
        "Chiffrement faible", "CWE-327", M,
        "DES / RC4 sont cassés.",
        "Utiliser AES-GCM (crypto/cipher.NewGCM) avec un nonce aléatoire.",
    ),
    Rule(
        "GO-TLS", GO,
        _r(r"InsecureSkipVerify\s*:\s*true"),
        "Vérification TLS désactivée", "CWE-295", H,
        "Tous les certificats sont acceptés : une interception (homme du milieu) passe inaperçue.",
        "Supprimer InsecureSkipVerify ; pour une autorité interne, la fournir dans RootCAs.",
    ),
    Rule(
        "GO-RANDOM", GO,
        _r(r"\brand\.(Int|Intn|Int63|Read|Uint32)\("),
        "Générateur aléatoire non cryptographique", "CWE-338", L,
        "math/rand est prévisible et ne doit pas générer de valeurs sensibles.",
        "Utiliser crypto/rand.",
        context_requires=_SENSITIVE,
        file_excludes=_r(r"\"crypto/rand\""),
    ),
]
