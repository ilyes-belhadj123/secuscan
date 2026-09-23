# Moteurs SAST externes (SS-5) : choix et licences

SecuScan combine ses règles maison (41 règles, 4 langages) avec des moteurs open source. Le critère
décisif pour un produit commercial vendu en SaaS est la **licence des règles**, pas seulement celle
du moteur.

| Option | Licence du moteur | Licence des règles | Usage dans SecuScan (SaaS commercial) |
|---|---|---|---|
| Semgrep | LGPL 2.1 (Community Edition) | Semgrep Rules License v1.0 (propriétaire, depuis décembre 2024) | ❌ Règles non utilisables dans un produit commercial / SaaS concurrent |
| Opengrep | LGPL 2.1 (fork de Semgrep CE 1.100) | Commons Clause + LGPL 2.1 (fork des anciennes règles) | ⚠️ Moteur utilisable comme programme séparé ; **règles à éviter** : la Commons Clause interdit de vendre un service dont la valeur repose sur elles |
| Bandit (Python) | Apache 2.0 | Intégrées au moteur, Apache 2.0 | ✅ Intégré |

> Analyse à faire valider par un juriste avant la commercialisation : ce tableau résume les licences
> publiées, il ne constitue pas un avis juridique.

## Ce qui est intégré

- **Bandit** (activé par défaut, `SECUSCAN_EXTERNAL_ENGINES=["bandit"]`) sur les fichiers Python :
  seuls les résultats de sévérité et de confiance au moins moyennes sont gardés, les alertes « import »
  (B4xx) sont ignorées, les CWE approximatifs sont corrigés (ex. `eval` → CWE-95), et une ligne déjà
  signalée par une règle maison n'est pas dupliquée.
- **Adaptateur SARIF générique** (`analyzers/external.py`) : importe les résultats de tout moteur qui
  produit du SARIF 2.1.0 (sévérité via `security-severity`, CWE via les tags).
- **Opengrep avec les règles de l'éditeur** (`SECUSCAN_EXTERNAL_ENGINES=["bandit","opengrep"]` et
  `SECUSCAN_OPENGREP_RULES=<dossier de règles SecuScan>`) : le moteur LGPL est appelé comme programme
  séparé, avec uniquement des règles écrites pour SecuScan. Non activé tant qu'aucune règle maison au
  format Opengrep n'existe.

## Mesures

- Benchmark (règles + Bandit) : 98 % de détection, 5 % de faux positifs ; Bandit n'ajoute ni
  détection ni faux positif sur le corpus, que les règles maison couvrent déjà.
- Projet réel DVPWA (Damn Vulnerable Python Web App) : Bandit a révélé un cas manqué (MD5 importé
  directement, `from hashlib import md5`), et l'analyse de ce projet a conduit à corriger deux
  défauts : requêtes SQL écrites sur plusieurs lignes et bibliothèques JavaScript tierces minifiées
  (10 fausses alertes sur 13). Résultat : 2 alertes, toutes réelles, dont l'injection SQL du projet.

## Sources

- Licence des règles Semgrep : https://github.com/semgrep/semgrep-rules/blob/develop/LICENSE
- Opengrep et licences : https://socket.dev/blog/opengrep-forks-semgrep ,
  https://github.com/opengrep/opengrep , https://semgrep.dev/docs/faq/comparisons/opengrep
- Bandit (Apache 2.0) : https://github.com/PyCQA/bandit
