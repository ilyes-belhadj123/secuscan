"""Infrastructure en code : Dockerfile, Kubernetes, docker-compose, Terraform.

Deux sortes de contrôles :
- `IAC_RULES` : une ligne suffit (privileged: true, acl = "public-read"…), moteur de règles commun ;
- `file_findings` : il faut le fichier entier (aucune instruction USER → conteneur en root, aucun
  runAsNonRoot, règle d'entrée ouverte à Internet dans un bloc ingress…).
Les secrets écrits dans ces fichiers sont détectés par la couche secrets, comme pour le code.
"""
import re

from ..ingest import SourceFile
from ..models import Severity
from .rule_model import Rule

C, H, M, L = Severity.critical, Severity.high, Severity.medium, Severity.low
DOCKER, K8S, COMPOSE, TF = ("dockerfile",), ("kubernetes",), ("compose",), ("terraform",)
IAC_LANGUAGES = {"dockerfile", "kubernetes", "compose", "terraform"}


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


_IMAGE_LATEST = _r(r"^\s*(-\s*)?image:\s*[\"']?[^\s\"':@]+(:latest)?[\"']?\s*$")
_PRIVILEGED = _r(r"^\s*privileged:\s*true\b")
_DANGEROUS_CAPS = _r(r"^\s*-\s*[\"']?(CAP_)?(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|ALL)[\"']?\s*$")

IAC_RULES: list[Rule] = [
    # ------------------------------------------------------------------ Dockerfile
    Rule(
        "DOCKER-SECRET", DOCKER,
        _r(r"^\s*(ENV|ARG)\s+[\w.]*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)[\w.]*\s*[= ]\s*"
           r"[\"']?(?!\$)[^\s\"']{3,}", re.I),
        "Secret écrit dans l'image Docker", "CWE-798", H,
        "La valeur fait partie de l'image : quiconque peut la télécharger lit le secret (docker history).",
        "Passer le secret à l'exécution (variable d'environnement, secret Docker/Kubernetes) ou au build avec "
        "RUN --mount=type=secret.",
    ),
    Rule(
        "DOCKER-ADD-URL", DOCKER,
        _r(r"^\s*ADD\s+(--\S+\s+)*https?://", re.I),
        "Téléchargement sans vérification d'intégrité", "CWE-494", M,
        "ADD télécharge un fichier distant sans en vérifier l'empreinte : un serveur compromis livre un fichier piégé.",
        "Télécharger avec une empreinte vérifiée (ADD --checksum=sha256:…) ou copier un fichier versionné.",
        line_excludes=_r(r"--checksum="),
    ),
    Rule(
        "DOCKER-PIPE-SHELL", DOCKER,
        _r(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|ash)\b"),
        "Script distant exécuté sans vérification", "CWE-494", H,
        "Un script téléchargé est exécuté directement : la moindre compromission du serveur s'exécute dans l'image.",
        "Télécharger le script, vérifier son empreinte (sha256sum -c), puis l'exécuter ; ou utiliser un paquet signé.",
    ),
    Rule(
        "DOCKER-CHMOD-777", DOCKER,
        _r(r"\bchmod\s+(-R\s+)?0?777\b"),
        "Droits trop larges", "CWE-732", M,
        "Les fichiers deviennent modifiables par tous les utilisateurs du conteneur.",
        "Donner les fichiers à l'utilisateur de l'application (chown) avec des droits minimaux (755 / 644).",
    ),
    # ------------------------------------------------------------------ Kubernetes et docker-compose
    Rule(
        "IAC-PRIVILEGED", K8S + COMPOSE, _PRIVILEGED,
        "Conteneur privilégié", "CWE-250", H,
        "Un conteneur privilégié a presque tous les droits de la machine hôte : s'en échapper est trivial.",
        "Retirer privileged ; n'ajouter que la capacité Linux strictement nécessaire.",
    ),
    Rule(
        "K8S-PRIV-ESCALATION", K8S,
        _r(r"^\s*allowPrivilegeEscalation:\s*true\b"),
        "Élévation de privilèges autorisée", "CWE-250", M,
        "Un processus du conteneur peut obtenir plus de droits que son parent (binaires setuid).",
        "allowPrivilegeEscalation: false dans le securityContext de chaque conteneur.",
    ),
    Rule(
        "K8S-HOST-NAMESPACE", K8S,
        _r(r"^\s*host(Network|PID|IPC):\s*true\b"),
        "Espace de noms de l'hôte partagé", "CWE-668", H,
        "Le pod voit le réseau (ou les processus) de la machine hôte et peut les espionner ou s'y attaquer.",
        "Retirer hostNetwork / hostPID / hostIPC, sauf composant système qui l'exige.",
    ),
    Rule(
        "COMPOSE-HOST-NAMESPACE", COMPOSE,
        _r(r"^\s*(network_mode|pid|ipc):\s*[\"']?host\b"),
        "Espace de noms de l'hôte partagé", "CWE-668", H,
        "Le conteneur voit le réseau (ou les processus) de la machine hôte.",
        "Utiliser un réseau Docker dédié ; ne partager l'hôte que si c'est indispensable.",
    ),
    Rule(
        "IAC-CAPABILITIES", K8S + COMPOSE, _DANGEROUS_CAPS,
        "Capacité Linux dangereuse ajoutée", "CWE-250", H,
        "SYS_ADMIN (ou ALL) donne au conteneur des droits proches de root sur l'hôte.",
        "Supprimer toutes les capacités (drop: [ALL]) et n'ajouter que celle qui est nécessaire.",
        context_requires=_r(r"\badd:|cap_add:"),
    ),
    Rule(
        "K8S-RUN-AS-ROOT", K8S,
        _r(r"^\s*runAsUser:\s*0\b|^\s*runAsNonRoot:\s*false\b"),
        "Conteneur exécuté en root", "CWE-250", M,
        "Le conteneur tourne en root : une faille dans l'application donne root dans le conteneur.",
        "runAsNonRoot: true et un runAsUser non nul.",
    ),
    Rule(
        "K8S-DOCKER-SOCKET", K8S,
        _r(r"^\s*path:\s*[\"']?/var/run/docker\.sock"),
        "Socket Docker de l'hôte exposé", "CWE-668", H,
        "Accéder au socket Docker revient à être root sur la machine hôte.",
        "Ne pas monter /var/run/docker.sock ; utiliser un outil de build sans démon (Kaniko, BuildKit rootless).",
    ),
    Rule(
        "COMPOSE-DOCKER-SOCKET", COMPOSE,
        _r(r"^\s*-\s*[\"']?/var/run/docker\.sock:"),
        "Socket Docker de l'hôte exposé", "CWE-668", H,
        "Accéder au socket Docker revient à être root sur la machine hôte.",
        "Ne pas monter /var/run/docker.sock ; à défaut, passer par un proxy qui filtre l'API Docker.",
    ),
    Rule(
        "IAC-IMAGE-LATEST", K8S + COMPOSE, _IMAGE_LATEST,
        "Image sans version figée", "CWE-1104", L,
        "« latest » (ou l'absence de version) change sans prévenir : le déploiement n'est ni reproductible ni vérifiable.",
        "Figer une version (acme/api:1.4.2), idéalement par empreinte (@sha256:…).",
    ),
    # ------------------------------------------------------------------ Terraform
    Rule(
        "TF-PUBLIC-ACL", TF,
        _r(r"\bacl\s*=\s*\"(public-read|public-read-write|authenticated-read)\""),
        "Stockage accessible publiquement", "CWE-732", H,
        "Le bucket est lisible par tout Internet : une fuite de données n'attend qu'un lien.",
        "ACL privée et aws_s3_bucket_public_access_block avec les quatre options à true.",
    ),
    Rule(
        "TF-PUBLIC-BLOCK-OFF", TF,
        _r(r"\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b"),
        "Protection d'accès public désactivée", "CWE-732", M,
        "Le blocage de l'accès public du bucket est désactivé.",
        "Passer les quatre options de aws_s3_bucket_public_access_block à true.",
    ),
    Rule(
        "TF-PUBLIC-DB", TF,
        _r(r"\bpublicly_accessible\s*=\s*true\b"),
        "Base de données exposée sur Internet", "CWE-284", H,
        "La base reçoit une adresse publique : seuls ses identifiants la protègent encore.",
        "publicly_accessible = false ; accès par le réseau privé (VPC) ou un bastion.",
    ),
    Rule(
        "TF-UNENCRYPTED", TF,
        _r(r"\b(storage_encrypted|encrypted|enable_encryption)\s*=\s*false\b|\benable_key_rotation\s*=\s*false\b"),
        "Stockage non chiffré", "CWE-311", M,
        "Les données sont stockées sans chiffrement (ou la clé n'est jamais renouvelée).",
        "Activer le chiffrement (storage_encrypted = true, clé KMS) et la rotation des clés.",
    ),
    Rule(
        "TF-IAM-WILDCARD", TF,
        _r(r"\b[Aa]ctions?\"?\s*[=:]\s*(\[\s*)?\"\*\""),
        "Permissions IAM illimitées", "CWE-269", H,
        "La politique autorise toutes les actions : un jeton volé donne le contrôle complet du compte.",
        "Lister uniquement les actions nécessaires, sur des ressources précises.",
    ),
    Rule(
        "TF-SECRET", TF,
        _r(r"^\s*(password|master_password|admin_password|secret_key|access_key|client_secret|api_key|token)\s*=\s*"
           r"\"(?!\$\{)[^\"]{4,}\""),
        "Secret écrit dans le code d'infrastructure", "CWE-798", H,
        "Le secret est versionné et copié dans l'état Terraform.",
        "Utiliser une variable sensible, un gestionnaire de secrets, ou manage_master_user_password = true.",
    ),
]


def _find(lines: list[str], pattern: re.Pattern, default: int = 1) -> int:
    return next((i for i, line in enumerate(lines, start=1) if pattern.search(line)), default)


def _dockerfile(lines: list[str]) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    stages: set[str] = set()
    last_from = 0
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^\s*FROM\s+(--\S+\s+)*(\S+)(\s+AS\s+(\S+))?", line, re.I)
        if not m:
            continue
        last_from = i
        image = m.group(2)
        if m.group(4):
            stages.add(m.group(4).lower())
        if image.lower() in stages or image == "scratch" or "$" in image or "@sha256:" in image:
            continue
        tag = image.rsplit("/", 1)[-1].partition(":")[2]
        if not tag or tag == "latest":
            out.append(("DOCKER-LATEST", i))
    if last_from:
        final = lines[last_from:]
        users = [line.split(None, 1)[1].strip() for line in final
                 if re.match(r"^\s*USER\s+\S", line, re.I)]
        if not users or users[-1].split(":")[0] in ("root", "0"):
            start = _find(final, re.compile(r"^\s*(CMD|ENTRYPOINT)\b", re.I), len(final))
            out.append(("DOCKER-ROOT", last_from + start))
    return out


_WORKLOAD = re.compile(r"^\s*kind:\s*(Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob|ReplicaSet)\b", re.M)


def _kubernetes(content: str, lines: list[str]) -> list[tuple[str, int]]:
    if not _WORKLOAD.search(content):
        return []
    anchor = _find(lines, re.compile(r"^\s*containers:"))
    out = []
    if not re.search(r"runAsNonRoot:\s*true", content):
        out.append(("K8S-NO-NONROOT", anchor))
    if not re.search(r"^\s*limits:", content, re.M):
        out.append(("K8S-NO-LIMITS", anchor))
    return out


def _terraform(lines: list[str]) -> list[tuple[str, int]]:
    """Règle d'entrée ouverte à tout Internet (bloc ingress, ou ressource de règle de type ingress)."""
    out = []
    depth, ingress_depth = 0, None
    for i, line in enumerate(lines, start=1):
        if ingress_depth is None and (re.match(r"^\s*ingress\s*\{", line)
                                      or re.search(r"resource\s+\"aws_(vpc_security_group_ingress_rule|"
                                                   r"security_group_rule)\"", line)):
            ingress_depth = depth
        open_to_all = re.search(r"cidr", line) and re.search(r"\"0\.0\.0\.0/0\"|\"::/0\"", line)
        if ingress_depth is not None and open_to_all:
            around = "\n".join(lines[max(0, i - 8):i + 8])
            if not re.search(r"type\s*=\s*\"egress\"", around):  # aws_security_group_rule de sortie
                out.append(("TF-OPEN-INGRESS", i))
        depth += line.count("{") - line.count("}")
        if ingress_depth is not None and depth <= ingress_depth:
            ingress_depth = None
    return out


FILE_RULES = {
    "DOCKER-LATEST": Rule(
        "DOCKER-LATEST", DOCKER, _r(r"(?!)"), "Image de base sans version figée", "CWE-1104", L,
        "L'image de base change sans prévenir : la construction n'est ni reproductible ni vérifiable.",
        "Figer une version (FROM node:22.11-alpine), idéalement par empreinte (@sha256:…).",
    ),
    "DOCKER-ROOT": Rule(
        "DOCKER-ROOT", DOCKER, _r(r"(?!)"), "Conteneur exécuté en root", "CWE-250", M,
        "Aucune instruction USER : l'application tourne en root dans le conteneur, ce qui aggrave toute faille.",
        "Créer un utilisateur dédié et finir par USER (ex. USER node, ou USER 10001).",
    ),
    "K8S-NO-NONROOT": Rule(
        "K8S-NO-NONROOT", K8S, _r(r"(?!)"), "Conteneurs autorisés à tourner en root", "CWE-250", M,
        "Aucun runAsNonRoot: true : les conteneurs peuvent démarrer en root.",
        "securityContext: runAsNonRoot: true et runAsUser non nul, au niveau du pod.",
    ),
    "K8S-NO-LIMITS": Rule(
        "K8S-NO-LIMITS", K8S, _r(r"(?!)"), "Conteneurs sans limite de ressources", "CWE-770", L,
        "Sans limites, un conteneur emballé (ou attaqué) peut épuiser le processeur et la mémoire du nœud.",
        "Fixer resources.limits (cpu, memory) pour chaque conteneur.",
    ),
    "TF-OPEN-INGRESS": Rule(
        "TF-OPEN-INGRESS", TF, _r(r"(?!)"), "Accès réseau ouvert à tout Internet", "CWE-284", H,
        "Une règle d'entrée autorise 0.0.0.0/0 : le service (SSH, base…) est joignable par n'importe qui.",
        "Restreindre aux adresses de l'entreprise, ou passer par un VPN / bastion.",
    ),
}


def file_findings(source: SourceFile) -> list[tuple[Rule, int]]:
    lines = source.content.split("\n")
    if source.language == "dockerfile":
        found = _dockerfile(lines)
    elif source.language == "kubernetes":
        found = _kubernetes(source.content, lines)
    elif source.language == "terraform":
        found = _terraform(lines)
    else:
        found = []
    return [(FILE_RULES[rule_id], line) for rule_id, line in found]
