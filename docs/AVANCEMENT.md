# Avancement — SecuScan

Dernière mise à jour : 23/09/2026 · Objectif en cours : **démo client** (avant le 30/09/2026)

Légende : ✅ fait · 🟡 partiel (voir « reste à faire ») · ⬜ à faire · 🔒 bloqué

## Synthèse

| | Tickets |
|---|---|
| ✅ Fait | 18 |
| 🟡 Partiel | 3 |
| ⬜ À faire | 3 |

## Qualité de détection (benchmark SS-8)

Mesure du 23/09/2026 sur 83 failles annotées (4 langages) — rapport complet :
[benchmark/results/latest-rules.md](../benchmark/results/latest-rules.md)

| Mode | Taux de détection | Taux de faux positifs | Objectif cahier des charges |
|---|---|---|---|
| Règles seules | **98 %** (81/83) | **5 %** (4) | > 85 % / < 15 % |
| Règles + IA (Claude, réel) | **100 %** (83/83) | **7 %** (6) | > 85 % / < 15 % |
| Correctifs syntaxiquement valides | **100 %** (89/89) | | > 80 % |

Rapport IA : [benchmark/results/latest-ai.md](../benchmark/results/latest-ai.md). L'IA trouve les 2 failles
logiques hors de portée des règles et écarte les faux positifs de construction de requête avec une
constante. Sur les 6 faux positifs restants, 5 sont des failles logiques signalées par l'IA dans les
fichiers « sûrs » et la plupart sont défendables (ex. route sans contrôle d'accès) ; le 6e est un MD5
utilisé comme somme de contrôle (cas discutable).
Coût mesuré : analyse complète d'Acme Shop ≈ 85 000 jetons, 85 s.
⚠️ Le corpus a été écrit par l'équipe qui écrit les règles : ces chiffres sont optimistes. Prochaine
étape : ajouter des applications vulnérables open source externes (NodeGoat, DVWA, WebGoat) annotées.

Réalisé en plus des tickets : **revue logique par l'IA** (couche 4 du cahier des charges : failles
qu'aucune règle ne détecte, ex. IDOR), **commande de préparation de la démo**, projet de démonstration
volontairement vulnérable « Acme Shop » (4 langages).

✅ **IA réelle active** depuis le 23/09/2026 (Claude via OpenRouter) : validée sur la démo et le benchmark.

## Sprint 1 — Socle

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-1 | Initialiser repos, CI et workers | 🟡 | Monorepo `apps/api` + `apps/web`, CI GitHub Actions (lint, tests, build) | Workers ARQ + Redis, images Docker (tâches en thread pour la démo) |
| SS-2 | Comptes et organisations | ✅ | Inscription / connexion (scrypt, session en cookie HttpOnly, jetons stockés par empreinte, limitation des tentatives, protection CSRF), organisations, rôles propriétaire / admin / membre, invitations par lien à usage unique liées à l'e-mail, changement d'organisation ; **isolation multi-tenant testée** (analyses, alertes, rapports, coûts, audit, alertes ignorées) ; invitations et **mot de passe oublié par e-mail** (SMTP, ou boîte d'envoi locale sans serveur) | Configurer un serveur SMTP réel ; SSO (offre Business) |
| SS-3 | Upload ZIP et collage de code | ✅ | Limite 100 Mo, protection zip-slip / zip-bomb, détection des langages, suppression après analyse | Chiffrement du stockage temporaire |
| SS-4 | Sandbox d'analyse éphémère | ⬜ | Le code analysé n'est jamais exécuté | Conteneur par scan sans réseau (Docker absent du poste de démo) |

## Sprint 2 — Analyse

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-5 | Moteur de règles statiques | ✅ | 41 règles maison (Python, JS/TS, PHP, Java) ; **Bandit** intégré (Apache 2.0) ; adaptateur **SARIF** générique ; Opengrep branchable avec des règles propres ; bibliothèques tierces minifiées ignorées ; [choix et licences](moteurs-sast.md) | Écrire des règles maison au format Opengrep ; faire valider l'analyse de licences |
| SS-6 | Détection de secrets | ✅ | Motifs + entropie, valeur jamais stockée ni envoyée à l'IA (masque + empreinte), testé | — |
| SS-7 | Analyse des dépendances (SCA) | ✅ | requirements / pyproject, package.json / lock, composer, pom.xml ; base OSV.dev + cache ; version corrigée | — |
| SS-8 | Jeu de référence (benchmark) | ✅ | Corpus annoté 4 langages (cas vulnérables + cas sûrs), `python -m secuscan.benchmark` (détection, faux positifs, mode `--ai`), job CI nocturne + garde-fou de non-régression | Corpus externes (NodeGoat, DVWA, WebGoat) |

## Sprint 3 — IA

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-9 | Validation contextuelle des alertes | ✅ | Fonction englobante + imports + constantes du module, verdict JSON, faux positifs masqués ; **7 % de faux positifs mesurés avec le vrai modèle** | — |
| SS-10 | Explication pédagogique | ✅ | Prompt français, scénario conceptuel, filtre de sortie anti-charge offensive ; [relecture de 30 explications réelles](qa/relecture-SS-10.md) : 26/30 sans remarque, 4 défauts corrigés (prompt v2) | Contre-relecture par un expert sécurité humain avant la bêta |
| SS-11 | Proposition de correctif | ✅ | Diff avant/après, bouton copier, vérification syntaxique dans les 4 langages (tree-sitter + ast), correctif replacé dans le fichier complet ; **89/89 correctifs valides (100 %)** sur le benchmark | Relance automatique de l'IA si un correctif est invalide |
| SS-12 | Maîtrise des coûts IA | ✅ | Budget par analyse et par offre (Free 40 / Pro 150 / Business 500 appels), priorisation par gravité, revue logique limitée aux fichiers exposés, dépendances peu graves expliquées sans IA (base OSV), cache par empreinte, coût estimé par analyse + page « Coûts IA ». Mesuré : NodeGoat (3 087 lignes) **0,97 $** | Regrouper plusieurs alertes d'un même fichier par appel |
| SS-13 | Classification et sévérité | ✅ | Mapping CWE → OWASP Top 10 2025, 4 niveaux, règles de scoring documentées | — |

## Sprint 4 — Produit

| Ticket | Titre | Statut | Réalisé | Reste à faire |
|---|---|---|---|---|
| SS-14 | Vue détaillée d'une faille | ✅ | Code surligné, explication / correctif / références, navigation clavier | — |
| SS-15 | Tableau de bord projet | ✅ | Score 0-100 + note, graphiques sévérité et OWASP, évolution, comparaison avec l'analyse précédente | — |
| SS-16 | Ignorer une alerte avec justification | ✅ | Justification obligatoire, empreinte stable entre analyses, audit | — |
| SS-17 | Connexion GitHub / GitLab | 🟡 | Dépôts publics par URL ; **OAuth GitHub et GitLab** (état anti-CSRF à usage unique), dépôts privés, jetons chiffrés AES-256-GCM liés à l'organisation et à l'utilisateur, jeton transmis à git hors ligne de commande, choix du dépôt et de la branche, rafraîchissement des jetons GitLab ; testé avec GitHub simulé ([guide](connexion-github.md)) | **Créer l'application OAuth GitHub** (à faire par le propriétaire du compte) puis valider sur le vrai GitHub ; GitHub App pour une lecture seule stricte |
| SS-18 | Export PDF et JSON | ✅ | PDF (marque blanche : client / société), JSON + schéma publié | Logo de l'organisation |
| SS-19 | Journal d'audit | ✅ | Ajout seul, par organisation, réservé aux administrateurs, auteur de chaque action ; analyses, alertes ignorées, exports, membres (invitation, arrivée, rôle, départ) | — |
| SS-20 | Offres Free / Pro / Business | 🟡 | Offre par organisation ; quotas appliqués côté serveur (Free : 5 analyses / mois, 1 projet, 3 membres ; Pro : 100 ; Business : 500 + marque blanche), budget IA selon l'offre, changement d'offre par le propriétaire avec contrôle de l'usage, factures pro forma, webhook de paiement signé (HMAC), page « Offre et facturation » | Brancher un vrai prestataire de paiement (Stripe…) ; **valider les tarifs** (29 € / 79 € HT par membre et par mois : provisoires) |

## Bêta et V2

| Ticket | Titre | Statut |
|---|---|---|
| SS-21 | Bêta 10 équipes pilotes | 🟡 outillage prêt : retours sur chaque correctif (taux d'acceptation), suivi des copies, questionnaire à J+14 (NPS), tableau de bord opérateur ; [guide des équipes](beta/guide-equipes-pilotes.md) et [plan de bêta](beta/plan-beta.md) — **reste : recruter les équipes et mener la bêta** (hébergement en ligne requis) |
| SS-22 | Commentaires automatiques sur pull requests (V2) | ⬜ |
| SS-23 | Job CI/CD bloquant (V2) | ✅ commande `secuscan scan` (seuil, codes retour documentés, `.secuscan.yml`, SARIF, suppression justifiée dans le code) ; [doc d'intégration](integration-ci.md) GitHub / GitLab ; SecuScan s'analyse lui-même en CI |
| SS-24 | Mode formation (V2) | ⬜ |

## Prochaines étapes

1. SS-17 — OAuth GitHub / GitLab pour les dépôts privés (application OAuth à créer sur GitHub).
2. SS-5 — adaptateur SARIF pour brancher un moteur SAST open source (attention aux licences des règles).
3. SS-5 — brancher un moteur SAST open source en complément des règles maison.
4. Mise en ligne (hébergement HTTPS) : désormais possible grâce aux comptes.

## Historique

| Date | Commit | Contenu |
|---|---|---|
| 23/09/2026 | (ce commit) | SS-21 outillage de la bêta (retours sur les correctifs, questionnaire, tableau de bord opérateur, guide et plan) |
| 23/09/2026 | `9ce0946` | Sécurité : pom.xml lus avec defusedxml (trouvé par SecuScan sur lui-même) |
| 23/09/2026 | `afb0922` | SS-5 Bandit + adaptateur SARIF ; testé sur le projet réel DVPWA : SQL sur plusieurs lignes détecté, bibliothèques minifiées ignorées |
| 23/09/2026 | `f559e5e` | SS-17 OAuth GitHub / GitLab, dépôts privés, jetons chiffrés ; script `configure-secrets.ps1` |
| 23/09/2026 | `21aacd3` | SS-23 CLI + SARIF + CI ; SecuScan s'analyse lui-même : correctif SCA (plages de package.json ignorées si lockfile) et react-router 6 → 7 (vulnérabilité GHSA-337j-9hxr-rhxg) |
| 23/09/2026 | `5be0ed6` | E-mails (SMTP ou boîte d'envoi locale), invitations par e-mail, mot de passe oublié |
| 23/09/2026 | `a1b2e98` | SS-20 offres, quotas, changement d'offre, factures pro forma, webhook signé |
| 23/09/2026 | `4132b5d` | SS-2 comptes, organisations, rôles, invitations, isolation multi-tenant ; SS-19 audit réservé aux admins ; interrupteur `SECUSCAN_AI_DISABLED` |
| 23/09/2026 | `312720e` | SS-10 relecture de 30 explications IA, prompt v2 (environnement d'exécution, rien d'inventé, CWE précis), extraits sans accolade du bloc parent |
| 23/09/2026 | `746bdce` | SS-11 vérification syntaxique des correctifs dans les 4 langages (89/89 valides) |
| 23/09/2026 | `783b6ed` | SS-12 coûts IA : budget par offre, priorisation, dépendances sans IA, page « Coûts IA » ; robustesse aux réponses vides / tronquées. Vrai projet NodeGoat avec IA : 25 failles logiques trouvées pour 0,97 $ |
| 23/09/2026 | `5842133` | IA réelle validée : benchmark règles + IA (100 % / 7 %), contexte IA enrichi des constantes du module, script `configure-ia.ps1` |
| 23/09/2026 | `26622da` | Correctif SCA trouvé sur un vrai projet (OWASP NodeGoat, 1 108 dépendances) : envoi par lots à OSV, lockfile v1, limites de l'analyse affichées (écran + PDF) au lieu d'échecs silencieux |
| 23/09/2026 | `0e3a279` | SS-8 benchmark + règles améliorées (détection 82 % → 98 %, faux positifs 9 % → 5 %) |
| 23/09/2026 | `f4aeb82` | Tableau de suivi des tickets |
| 23/09/2026 | `4e31375` | Revue logique IA, import Git, marque blanche PDF, journal d'audit |
| 23/09/2026 | `28f40da` | Version démo initiale (analyse 4 couches, tableau de bord, rapports) |
