# Tickets — SecuScan — Analyse de sécurité du code

24 tickets · 128 story points · 289 h estimées

## Sommaire par epic

- **Socle technique** : SS-1
- **Authentification** : SS-2
- **Import** : SS-3
- **Sécurité plateforme** : SS-4
- **Analyse** : SS-5, SS-6, SS-7, SS-8
- **IA** : SS-9, SS-10, SS-11, SS-12
- **Scoring** : SS-13
- **Interface** : SS-14, SS-15, SS-16
- **Intégrations** : SS-17
- **Rapports** : SS-18
- **Traçabilité** : SS-19
- **Monétisation** : SS-20
- **Bêta** : SS-21
- **Intégrations (V2)** : SS-22, SS-23
- **Formation (V2)** : SS-24


---

## Epic : Socle technique

### SS-1 · Initialiser repos, CI et workers

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Tâche | Critique | 5 | S1 | 11 h | devops |

**Description**

FastAPI, React/Vite, Redis, workers d'analyse Docker éphémères.

**Spécifications techniques**

Monorepo `apps/api` (FastAPI 3.12), `apps/web` (React 18 + Vite), `workers/scanner` (ARQ + Redis). CI : lint, tests, build d'images. Image scanner séparée contenant les outils d'analyse.

**Critères d'acceptation**

- [ ] CI verte
- [ ] Un worker exécute une tâche isolée

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-1.1 | DevOps | Structure monorepo + lint | 3 h |
| SS-1.2 | DevOps | Workers ARQ + Redis | 4 h |
| SS-1.3 | DevOps | CI + build des images | 4 h |


---

## Epic : Authentification

### SS-2 · Comptes et organisations

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Critique | 5 | S1 | 18 h | backend |

**Description**

En tant que CTO, je crée une organisation et invite mon équipe.

**Spécifications techniques**

`organizations`, `memberships` (role: owner|admin|member), `invitations` (token, expiry). Toutes les requêtes filtrées par `org_id` via dépendance FastAPI `current_org()`. Tests d'isolation cross-tenant.

**Critères d'acceptation**

- [ ] Rôles admin/membre
- [ ] Invitations e-mail
- [ ] Isolation multi-tenant testée

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-2.1 | Backend | Modèles + endpoints organisations et invitations | 6 h |
| SS-2.2 | Backend | Middleware d'isolation multi-tenant | 4 h |
| SS-2.3 | Frontend web | Écrans organisation, membres, invitations | 5 h |
| SS-2.4 | QA | Tests d'isolation | 3 h |


---

## Epic : Import

### SS-3 · Upload d'archive ZIP et collage de code

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Haute | 3 | S1 | 11 h | backend, web |

**Description**

En tant que développeur, j'importe mon code par ZIP ou collage.

**Spécifications techniques**

`POST /projects/{id}/uploads` (ZIP ≤ 100 Mo, protection zip-slip et zip-bomb) ou `POST /snippets`. Détection langages par extensions + fichiers manifestes. Stockage temporaire chiffré, suppression après scan.

**Critères d'acceptation**

- [ ] Limite de taille
- [ ] Détection des langages
- [ ] Archive supprimée après analyse

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-3.1 | Backend | Upload sécurisé (zip-slip, taille, ratio) | 5 h |
| SS-3.2 | Backend | Détection des langages | 2 h |
| SS-3.3 | Frontend web | Écran d'import (drag & drop + éditeur) | 4 h |


---

## Epic : Sécurité plateforme

### SS-4 · Sandbox d'analyse éphémère

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Tâche | Critique | 8 | S1 | 15 h | sécurité, devops |

**Description**

Chaque analyse tourne dans un conteneur isolé, sans réseau sortant, détruit ensuite.

**Spécifications techniques**

Conteneur par scan : utilisateur non-root, FS en lecture seule sauf `/work`, `--network none`, limites CPU/RAM/temps, destruction en fin de job. Aucune exécution du code analysé.

**Critères d'acceptation**

- [ ] Aucun accès réseau
- [ ] Suppression vérifiée
- [ ] Test d'isolation

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-4.1 | DevOps | Profil de conteneur durci | 6 h |
| SS-4.2 | Backend | Orchestration job → conteneur → résultats | 6 h |
| SS-4.3 | QA | Tests d'isolation réseau et FS | 3 h |


---

## Epic : Analyse

### SS-5 · Intégrer le moteur de règles statiques

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Critique | 8 | S2 | 18 h | analyse |

**Description**

Exécuter un moteur SAST open source sur Python, JS/TS, PHP, Java.

**Spécifications techniques**

Adaptateur autour d'un moteur SAST open source (sortie SARIF) + jeux de règles par langage + règles maison. Normalisation vers `findings` : rule_id, cwe, owasp, file, start_line, end_line, snippet_hash, raw_severity.

**Critères d'acceptation**

- [ ] Findings normalisés (fichier, lignes, règle, CWE)

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-5.1 | Backend | Adaptateur moteur + parsing SARIF | 6 h |
| SS-5.2 | Backend | Normalisation des findings | 4 h |
| SS-5.3 | Backend | Premières règles maison | 4 h |
| SS-5.4 | QA | Tests par langage | 4 h |

### SS-6 · Détection de secrets

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Critique | 5 | S2 | 9 h | analyse, sécurité |

**Description**

Détecter clés d'API, mots de passe et jetons commités.

**Spécifications techniques**

Détection par motifs + entropie. Stockage : type, fichier, ligne, empreinte SHA-256 tronquée ; **jamais la valeur**. Affichage masqué (`sk_****`).

**Critères d'acceptation**

- [ ] Valeurs jamais stockées en clair
- [ ] Affichage masqué
- [ ] Emplacement précis

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-6.1 | Backend | Intégration d'un détecteur de secrets open source | 4 h |
| SS-6.2 | Backend | Masquage et stockage par empreinte | 3 h |
| SS-6.3 | QA | Tests : aucune valeur en base ni en logs | 2 h |

### SS-7 · Analyse des dépendances (SCA)

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Haute | 5 | S2 | 12 h | analyse |

**Description**

Identifier les bibliothèques avec CVE connues.

**Spécifications techniques**

Parsing requirements.txt / pyproject, package.json + lockfile, composer.json/lock, pom.xml. Croisement avec une base publique d'advisories (API open source). Sortie : package, version, advisory, fixed_version.

**Critères d'acceptation**

- [ ] Lecture des manifests (requirements, package.json, composer, pom)
- [ ] Version corrigée indiquée

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-7.1 | Backend | Parsers de manifests | 5 h |
| SS-7.2 | Backend | Client base d'advisories + cache | 4 h |
| SS-7.3 | Frontend web | Affichage des dépendances vulnérables | 3 h |

### SS-8 · Jeu de référence de vulnérabilités

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Tâche | Haute | 5 | S2 | 14 h | qa |

**Description**

Constituer un benchmark à partir d'applications volontairement vulnérables open source.

**Spécifications techniques**

Corpus d'applications volontairement vulnérables open source + annotations de vérité terrain (fichier, ligne, CWE). Script `benchmark.py` calculant rappel, précision, faux positifs, exécuté en CI nocturne.

**Critères d'acceptation**

- [ ] Rappel et faux positifs calculés automatiquement en CI

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-8.1 | QA | Sélection du corpus + annotations | 8 h |
| SS-8.2 | QA | Script de benchmark + rapport | 4 h |
| SS-8.3 | DevOps | Job CI nocturne | 2 h |


---

## Epic : IA

### SS-9 · Validation contextuelle des alertes

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Critique | 8 | S3 | 18 h | ia |

**Description**

L'IA analyse l'extrait et son contexte pour confirmer ou écarter l'alerte.

**Spécifications techniques**

Pour chaque finding : extraction du contexte (fonction englobante + imports + appels, ≤ 150 lignes). Prompt Claude → JSON {verdict: true_positive|false_positive|uncertain, confidence, reason}. Findings `false_positive` à haute confiance masqués par défaut.

**Critères d'acceptation**

- [ ] Sortie JSON structurée
- [ ] Faux positifs < 15 % sur le benchmark

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-9.1 | Backend | Extracteur de contexte (AST par langage) | 8 h |
| SS-9.2 | IA / prompts | Prompt de validation + schéma JSON | 4 h |
| SS-9.3 | Backend | Intégration pipeline + parallélisation | 3 h |
| SS-9.4 | QA | Mesure faux positifs sur benchmark | 3 h |

### SS-10 · Explication pédagogique de la faille

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Critique | 5 | S3 | 9 h | ia |

**Description**

En tant que développeur, je comprends la faille, le scénario d'attaque conceptuel et l'impact métier.

**Spécifications techniques**

Prompt pédagogique en français : définition, scénario d'attaque **conceptuel** (sans exploit ni payload fonctionnel), impact métier, niveau de difficulté, références OWASP/CWE. Filtre de sortie bloquant les charges offensives.

**Critères d'acceptation**

- [ ] Explication en français
- [ ] Aucune charge offensive exploitable
- [ ] Référence OWASP/CWE

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-10.1 | IA / prompts | Prompt d'explication + garde-fous | 4 h |
| SS-10.2 | Backend | Filtre de sortie | 2 h |
| SS-10.3 | QA | Relecture de 30 explications | 3 h |

### SS-11 · Proposition de correctif

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Critique | 8 | S3 | 16 h | ia |

**Description**

En tant que développeur, je vois un diff avant/après avec explication.

**Spécifications techniques**

Prompt correctif → JSON {patched_code, diff, explanation, best_practices[]}. Vérification syntaxique du correctif (parseur du langage). Diff unifié affiché côté front.

**Critères d'acceptation**

- [ ] Diff affiché
- [ ] Correctif compilable sur 80 % du benchmark
- [ ] Bouton copier

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-11.1 | IA / prompts | Prompt correctif + schéma | 4 h |
| SS-11.2 | Backend | Vérification syntaxique du patch | 5 h |
| SS-11.3 | Frontend web | Composant diff avant/après + copier | 4 h |
| SS-11.4 | QA | Taux de correctifs valides sur benchmark | 3 h |

### SS-12 · Maîtrise des coûts IA

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Tâche | Haute | 3 | S3 | 8 h | ia, backend |

**Description**

Envoyer uniquement les extraits pertinents et mettre en cache.

**Spécifications techniques**

Budget de tokens par scan selon l'offre ; regroupement des findings d'un même fichier ; cache par (snippet_hash, rule_id, model_version). Métriques de coût par scan.

**Critères d'acceptation**

- [ ] Coût moyen par analyse mesuré et plafonné par offre

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-12.1 | Backend | Cache par empreinte | 3 h |
| SS-12.2 | Backend | Budget et plafonds par offre | 3 h |
| SS-12.3 | Données | Tableau de coûts | 2 h |


---

## Epic : Scoring

### SS-13 · Classification et sévérité

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Haute | 3 | S3 | 7 h | analyse |

**Description**

Chaque finding a une catégorie OWASP, un CWE et une sévérité.

**Spécifications techniques**

Mapping règle → CWE → catégorie OWASP Top 10. Sévérité = f(raw_severity, verdict IA, exposition). Documentation publique du scoring.

**Critères d'acceptation**

- [ ] 4 niveaux de sévérité
- [ ] Règles de scoring documentées

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-13.1 | Backend | Tables de mapping CWE / OWASP | 3 h |
| SS-13.2 | Backend | Fonction de scoring | 2 h |
| SS-13.3 | Produit | Documentation du scoring | 2 h |


---

## Epic : Interface

### SS-14 · Vue détaillée d'une faille

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Haute | 5 | S4 | 11 h | web |

**Description**

En tant que développeur, je vois le code surligné, l'explication et le correctif.

**Spécifications techniques**

Page `/scans/{id}/findings/{fid}` : code surligné (bibliothèque de coloration), panneaux explication / correctif / références, navigation clavier.

**Critères d'acceptation**

- [ ] Coloration syntaxique
- [ ] Navigation entre findings

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-14.1 | Frontend web | Vue code avec surlignage des lignes | 5 h |
| SS-14.2 | Frontend web | Panneaux explication et correctif | 4 h |
| SS-14.3 | Frontend web | Navigation entre findings | 2 h |

### SS-15 · Tableau de bord projet

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Haute | 5 | S4 | 13 h | web |

**Description**

En tant que CTO, je vois le score, la répartition par sévérité et l'évolution.

**Spécifications techniques**

Score projet 0-100 = pénalités pondérées par sévérité. Graphiques (recharts) : répartition sévérité, top catégories OWASP, évolution. Comparaison avec le scan précédent (nouveaux / corrigés).

**Critères d'acceptation**

- [ ] Graphiques
- [ ] Comparaison avec l'analyse précédente

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-15.1 | Backend | Calcul du score + agrégations | 4 h |
| SS-15.2 | Frontend web | Dashboard et graphiques | 6 h |
| SS-15.3 | Backend | Diff entre deux scans | 3 h |

### SS-16 · Ignorer une alerte avec justification

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Moyenne | 3 | S4 | 7 h | web, backend |

**Description**

En tant que développeur, je marque un faux positif avec un motif.

**Spécifications techniques**

`POST /findings/{id}/dismiss {reason, justification}`. Empreinte stable (rule_id + chemin + snippet normalisé) pour retrouver le finding aux scans suivants.

**Critères d'acceptation**

- [ ] Justification obligatoire
- [ ] Alerte masquée aux analyses suivantes
- [ ] Audit log

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-16.1 | Backend | Empreinte stable + endpoint dismiss | 4 h |
| SS-16.2 | Frontend web | Modale de justification | 2 h |
| SS-16.3 | Backend | Écriture dans l'audit log | 1 h |


---

## Epic : Intégrations

### SS-17 · Connexion GitHub / GitLab

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Haute | 5 | S4 | 14 h | intégration |

**Description**

En tant que développeur, je connecte un dépôt via OAuth et lance une analyse.

**Spécifications techniques**

Applications OAuth GitHub / GitLab (scopes lecture minimale). Jetons chiffrés (AES-GCM, clé en variable d'environnement référencée par nom). Clone shallow dans le conteneur de scan.

**Critères d'acceptation**

- [ ] Choix du dépôt et de la branche
- [ ] Jetons chiffrés

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-17.1 | Backend | OAuth GitHub + GitLab | 6 h |
| SS-17.2 | Backend | Stockage chiffré des jetons | 2 h |
| SS-17.3 | Frontend web | Sélection dépôt / branche | 3 h |
| SS-17.4 | Backend | Clone shallow dans la sandbox | 3 h |


---

## Epic : Rapports

### SS-18 · Export PDF et JSON

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Haute | 5 | S4 | 10 h | backend |

**Description**

En tant que CTO, j'exporte un rapport pour un audit ou un client.

**Spécifications techniques**

PDF via template HTML + WeasyPrint (logo de l'organisation, résumé, findings par sévérité). JSON conforme à un schéma publié (JSON Schema).

**Critères d'acceptation**

- [ ] PDF brandé
- [ ] JSON conforme à un schéma documenté

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-18.1 | Backend | Template et génération PDF | 5 h |
| SS-18.2 | Backend | Export JSON + schéma | 3 h |
| SS-18.3 | Frontend web | Bouton d'export + options | 2 h |


---

## Epic : Traçabilité

### SS-19 · Journal d'audit

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Moyenne | 3 | S4 | 6 h | backend, sécurité |

**Description**

Tracer analyses, ignorés, exports et invitations.

**Spécifications techniques**

Collection `audit_logs` en append-only (org_id, actor, action, target, ts, ip). Consultation filtrable par l'admin.

**Critères d'acceptation**

- [ ] Consultable par l'admin
- [ ] Non modifiable

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-19.1 | Backend | Middleware d'audit | 3 h |
| SS-19.2 | Frontend web | Écran de consultation | 3 h |


---

## Epic : Monétisation

### SS-20 · Offres Free / Pro / Business

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Story | Moyenne | 5 | S4 | 14 h | backend, web |

**Description**

Limites par offre et paiement en ligne.

**Spécifications techniques**

Plans : free (1 projet, 5 scans/mois), pro (par développeur), business (SSO, marque blanche). Paiement via prestataire + webhooks. Dépendance `require_plan()`.

**Critères d'acceptation**

- [ ] Quotas appliqués
- [ ] Upgrade/downgrade
- [ ] Facturation

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-20.1 | Backend | Plans, quotas, gating | 5 h |
| SS-20.2 | Backend | Paiement + webhooks | 5 h |
| SS-20.3 | Frontend web | Pages tarifs + facturation | 4 h |


---

## Epic : Bêta

### SS-21 · Bêta 10 équipes pilotes

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Tâche | Haute | 5 | Bêta | 10 h | produit |

**Description**

Onboarding et suivi de 10 équipes.

**Spécifications techniques**

10 équipes pilotes (organisations de test), onboarding guidé, sondage après 2 semaines, mesure du taux de correctifs acceptés.

**Critères d'acceptation**

- [ ] Feedback collecté
- [ ] Taux de correctifs acceptés mesuré

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-21.1 | Produit | Recrutement et onboarding | 6 h |
| SS-21.2 | Produit | Analyse des retours | 4 h |


---

## Epic : Intégrations (V2)

### SS-22 · Commentaires automatiques sur pull requests

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Epic | Basse | 8 | V2 | 16 h | intégration |

**Description**

Commenter les PR avec les nouvelles failles introduites.

**Spécifications techniques**

GitHub App : webhook `pull_request` → scan incrémental sur le diff → commentaires de review sur les lignes concernées.

**Critères d'acceptation**

- [ ] Analyse incrémentale sur le diff
- [ ] Commentaire par finding

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-22.1 | Backend | GitHub App + webhooks | 8 h |
| SS-22.2 | Backend | Scan incrémental sur diff | 8 h |

### SS-23 · Job CI/CD bloquant

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Epic | Basse | 5 | V2 | 8 h | devops |

**Description**

Bloquer un pipeline au-delà d'un seuil de sévérité.

**Spécifications techniques**

CLI `secuscan` + fichier `.secuscan.yml` (seuil, exclusions). Code retour ≠ 0 si seuil dépassé.

**Critères d'acceptation**

- [ ] Configuration par fichier
- [ ] Code retour documenté

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-23.1 | Backend | CLI + configuration | 6 h |
| SS-23.2 | Produit | Documentation d'intégration CI | 2 h |


---

## Epic : Formation (V2)

### SS-24 · Mode formation code sécurisé

| Type | Priorité | Story points | Sprint | Charge | Labels |
|---|---|---|---|---|---|
| Epic | Basse | 8 | V2 | 14 h | formation |

**Description**

Exercices de code vulnérable à corriger avec correction IA.

**Spécifications techniques**

Catalogue d'exercices (code vulnérable + tests), correction IA, progression par apprenant.

**Critères d'acceptation**

- [ ] 10 exercices
- [ ] Suivi de progression

**Sous-tâches**

| ID | Rôle | Sous-tâche | Estimation |
|---|---|---|---|
| SS-24.1 | Produit | Conception de 10 exercices | 8 h |
| SS-24.2 | Frontend web | Interface d'exercice | 6 h |
