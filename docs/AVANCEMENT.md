# Avancement — SecuScan

Dernière mise à jour : 23/09/2026 · Objectif en cours : **démo client** (avant le 30/09/2026)

Légende : ✅ fait · 🟡 partiel (voir « reste à faire ») · ⬜ à faire · 🔒 bloqué

## Synthèse

| | Tickets |
|---|---|
| ✅ Fait | 11 |
| 🟡 Partiel | 6 |
| ⬜ À faire | 7 |

## Qualité de détection (benchmark SS-8)

Mesure du 23/09/2026 sur 83 failles annotées (4 langages) — rapport complet :
[benchmark/results/latest-rules.md](../benchmark/results/latest-rules.md)

| Mode | Taux de détection | Taux de faux positifs | Objectif cahier des charges |
|---|---|---|---|
| Règles seules | **98 %** (81/83) | **5 %** (4) | > 85 % / < 15 % |
| Règles + IA | à mesurer (clé requise) | à mesurer | |

Les 2 failles manquées en règles seules sont des failles logiques (IDOR, prix fourni par le client)
que seule la revue IA peut trouver ; les 4 faux positifs sont des cas que la validation IA doit écarter.
⚠️ Le corpus a été écrit par l'équipe qui écrit les règles : ces chiffres sont optimistes. Prochaine
étape : ajouter des applications vulnérables open source externes (NodeGoat, DVWA, WebGoat) annotées.

Réalisé en plus des tickets : **revue logique par l'IA** (couche 4 du cahier des charges : failles
qu'aucune règle ne détecte, ex. IDOR), **commande de préparation de la démo**, projet de démonstration
volontairement vulnérable « Acme Shop » (4 langages).

🔒 **Point bloquant** : aucun test avec le vrai modèle Claude tant que la clé OpenRouter n'est pas
renseignée dans `.env` (tout a été validé avec une IA simulée).

## Sprint 1 — Socle

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-1 | Initialiser repos, CI et workers | 🟡 | Monorepo `apps/api` + `apps/web`, CI GitHub Actions (lint, tests, build) | Workers ARQ + Redis, images Docker (tâches en thread pour la démo) |
| SS-2 | Comptes et organisations | ⬜ | — | Organisations, rôles, invitations, isolation multi-tenant |
| SS-3 | Upload ZIP et collage de code | ✅ | Limite 100 Mo, protection zip-slip / zip-bomb, détection des langages, suppression après analyse | Chiffrement du stockage temporaire |
| SS-4 | Sandbox d'analyse éphémère | ⬜ | Le code analysé n'est jamais exécuté | Conteneur par scan sans réseau (Docker absent du poste de démo) |

## Sprint 2 — Analyse

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-5 | Moteur de règles statiques | 🟡 | 41 règles maison (Python, JS/TS, PHP, Java) avec exclusions par ligne, findings normalisés (fichier, lignes, CWE, OWASP), interface d'adaptateur | Brancher un moteur SAST open source (SARIF) |
| SS-6 | Détection de secrets | ✅ | Motifs + entropie, valeur jamais stockée ni envoyée à l'IA (masque + empreinte), testé | — |
| SS-7 | Analyse des dépendances (SCA) | ✅ | requirements / pyproject, package.json / lock, composer, pom.xml ; base OSV.dev + cache ; version corrigée | — |
| SS-8 | Jeu de référence (benchmark) | ✅ | Corpus annoté 4 langages (cas vulnérables + cas sûrs), `python -m secuscan.benchmark` (détection, faux positifs, mode `--ai`), job CI nocturne + garde-fou de non-régression | Corpus externes (NodeGoat, DVWA, WebGoat) |

## Sprint 3 — IA

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-9 | Validation contextuelle des alertes | 🟡 | Extraction de la fonction englobante, verdict JSON, faux positifs masqués | Mesure < 15 % de faux positifs : `benchmark --ai` avec le vrai modèle |
| SS-10 | Explication pédagogique | 🟡 | Prompt français, scénario conceptuel, filtre de sortie anti-charge offensive | Relecture de 30 explications générées par le vrai modèle |
| SS-11 | Proposition de correctif | 🟡 | Diff avant/après, bouton copier, vérification syntaxique (Python) | Vérification JS/PHP/Java, mesure 80 % de correctifs valides |
| SS-12 | Maîtrise des coûts IA | 🟡 | Cache par empreinte, extraits ciblés, compteur d'appels / jetons par scan | Budget et plafonds par offre |
| SS-13 | Classification et sévérité | ✅ | Mapping CWE → OWASP Top 10 2025, 4 niveaux, règles de scoring documentées | — |

## Sprint 4 — Produit

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-14 | Vue détaillée d'une faille | ✅ | Code surligné, explication / correctif / références, navigation clavier | — |
| SS-15 | Tableau de bord projet | ✅ | Score 0-100 + note, graphiques sévérité et OWASP, évolution, comparaison avec l'analyse précédente | — |
| SS-16 | Ignorer une alerte avec justification | ✅ | Justification obligatoire, empreinte stable entre analyses, audit | — |
| SS-17 | Connexion GitHub / GitLab | 🟡 | Analyse d'un dépôt **public** par URL (clone superficiel sécurisé) | OAuth, dépôts privés, jetons chiffrés, choix de branche via liste |
| SS-18 | Export PDF et JSON | ✅ | PDF (marque blanche : client / société), JSON + schéma publié | Logo de l'organisation |
| SS-19 | Journal d'audit | ✅ | Ajout seul, écran filtrable (analyses, alertes ignorées, exports) | Restreindre à l'admin (dépend de SS-2) |
| SS-20 | Offres Free / Pro / Business | ⬜ | — | Plans, quotas, paiement |

## Bêta et V2

| Ticket | Titre | Statut |
|---|---|---|
| SS-21 | Bêta 10 équipes pilotes | ⬜ |
| SS-22 | Commentaires automatiques sur pull requests (V2) | ⬜ |
| SS-23 | Job CI/CD bloquant (V2) | ⬜ |
| SS-24 | Mode formation (V2) | ⬜ |

## Prochaines étapes

1. Test avec le vrai modèle (dès que la clé est dans `.env`) : `prepare_demo`, puis
   `benchmark --ai` pour mesurer SS-9 / SS-10 / SS-11.
2. SS-12 — plafonds de coût IA par analyse.
3. SS-11 — vérification syntaxique des correctifs JS / PHP / Java.

## Historique

| Date | Commit | Contenu |
|---|---|---|
| 23/09/2026 | (ce commit) | Correctif SCA trouvé sur un vrai projet (OWASP NodeGoat, 1 108 dépendances) : envoi par lots à OSV, lockfile v1, limites de l'analyse affichées (écran + PDF) au lieu d'échecs silencieux |
| 23/09/2026 | `0e3a279` | SS-8 benchmark + règles améliorées (détection 82 % → 98 %, faux positifs 9 % → 5 %) |
| 23/09/2026 | `f4aeb82` | Tableau de suivi des tickets |
| 23/09/2026 | `4e31375` | Revue logique IA, import Git, marque blanche PDF, journal d'audit |
| 23/09/2026 | `28f40da` | Version démo initiale (analyse 4 couches, tableau de bord, rapports) |
