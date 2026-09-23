"""Prompts de l'enrichissement IA (validation + explication + correctif en un seul appel)."""

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = """Tu es un expert en sécurité applicative (AppSec) qui accompagne des équipes de \
développement francophones dans des PME et des ESN. Tu analyses des alertes produites par un \
outil d'analyse statique et tu réponds UNIQUEMENT en JSON valide, sans texte autour.

Règles impératives :
- Rédige en français clair, pédagogique, sans jargon inutile.
- Décris les scénarios d'attaque de façon CONCEPTUELLE uniquement : jamais de charge utile \
(payload), de chaîne d'exploitation, de commande ou de requête offensive prête à l'emploi.
- Juge l'alerte d'après le code fourni : si la donnée n'est pas contrôlable par un attaquant \
ou si une protection est déjà en place, c'est un faux positif. En cas de doute réel, "uncertain".
- Le correctif doit être minimal, idiomatique, conserver le comportement métier et la même \
portion de code (mêmes fonctions, même indentation). Ne pas ajouter de numéros de ligne.
- Les valeurs de secrets apparaissent masquées ("****") : un vrai secret a été détecté à cet \
endroit dans le code source, la valeur a seulement été retirée avant l'envoi. Ne tente jamais \
de la deviner ; le correctif doit la charger depuis l'environnement ou un coffre-fort de secrets."""

FINDING_TEMPLATE = """Alerte à analyser
- Règle : {rule_id} — {title}
- CWE : {cwe}
- Langage : {language}
- Fichier : {file}
- Ligne(s) signalée(s) : {lines}
- Description de la règle : {message}

En-tête du fichier (imports et constantes de niveau module) :
```
{header}
```

Extrait concerné (lignes {start}-{end}, numérotées pour référence) :
```
{numbered}
```

Réponds avec exactement cet objet JSON :
{{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": nombre entre 0 et 1,
  "reason": "1 à 2 phrases justifiant le verdict",
  "definition": "ce qu'est cette faille, en 2 à 3 phrases",
  "attack_scenario": "comment un attaquant pourrait l'exploiter ici, conceptuellement, en 2 à 4 phrases",
  "business_impact": "conséquences concrètes pour l'entreprise (données, argent, image, RGPD)",
  "difficulty": "facile" | "moyenne" | "difficile",
  "patched_code": "l'extrait complet (lignes {start}-{end}) réécrit avec le correctif, sans numéros de ligne",
  "fix_explanation": "ce que change le correctif et pourquoi il protège",
  "best_practices": ["2 à 4 bonnes pratiques courtes"]
}}"""

LOGIC_TEMPLATE = """Revue de logique de sécurité d'un fichier complet
- Fichier : {file}
- Langage : {language}
- Lignes déjà signalées par les règles statiques (ne pas les signaler à nouveau) : {flagged}

Code (lignes numérotées pour référence) :
```
{numbered}
```

Cherche UNIQUEMENT les failles exploitables qu'une règle par motif ne peut pas détecter :
contrôle d'accès (accès à la ressource d'un autre utilisateur, vérification de propriétaire ou
de rôle absente), authentification, logique métier (prix, montant ou quantité fournis par le
client, étape contournable), SSRF, redirection ouverte, affectation de masse, exposition de
données sensibles, conditions de course.
Ne signale rien de spéculatif : uniquement ce que le code montre, avec une confiance >= 0,7.
Au maximum 5 failles ; liste vide s'il n'y en a pas.

Réponds avec exactement cet objet JSON :
{{
  "findings": [
    {{
      "title": "titre court en français",
      "cwe": "CWE-xxx",
      "severity": "critical" | "high" | "medium" | "low",
      "start_line": numéro,
      "end_line": numéro,
      "confidence": nombre entre 0 et 1,
      "message": "une phrase décrivant le problème dans ce code"
    }}
  ]
}}"""

DEPENDENCY_TEMPLATE = """Dépendance vulnérable détectée
- Écosystème : {ecosystem}
- Paquet : {package} version {version}
- Version corrigée conseillée : {fixed_version}
- Advisories connues :
{advisories}

Explique ce risque à une équipe de développement. Réponds avec exactement cet objet JSON :
{{
  "definition": "ce que sont ces vulnérabilités, en 2 à 3 phrases",
  "attack_scenario": "comment elles pourraient être exploitées, conceptuellement, en 2 à 4 phrases",
  "business_impact": "conséquences concrètes pour l'entreprise",
  "difficulty": "facile" | "moyenne" | "difficile",
  "fix_explanation": "comment mettre à jour et ce qu'il faut vérifier (changements cassants, tests)",
  "best_practices": ["2 à 4 bonnes pratiques courtes"]
}}"""
