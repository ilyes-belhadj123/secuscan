# Cahier des charges — Projet 3 : Analyse de sécurité du code assistée par IA

**Nom de travail :** SecuScan
**Version :** 0.1 (draft)
**Type :** Produit commercial / startup SaaS (PME, ESN, équipes de développement)

---

## 1. Contexte et problématique

Les PME et ESN produisent beaucoup de code, souvent sans équipe sécurité dédiée. Les outils d'analyse statique (SAST) existants produisent des rapports volumineux, en anglais, avec beaucoup de faux positifs et peu d'explications pédagogiques. Les développeurs ignorent alors les alertes.

**Proposition de valeur :** un outil qui détecte les failles de sécurité, **explique le danger concrètement** (scénario d'attaque, impact métier) et **propose un correctif prêt à appliquer**, en français, directement dans le flux de travail (plateforme web, pull requests, CI).

## 2. Objectifs

| Objectif | Indicateur | Cible MVP |
|---|---|---|
| Détection fiable | Rappel sur un jeu de tests de vulnérabilités connues | > 85 % |
| Réduction du bruit | Taux de faux positifs après validation IA | < 15 % |
| Utilité des correctifs | Correctifs acceptés par les développeurs | > 50 % |
| Rapidité | Analyse d'un dépôt de 50 000 lignes | < 10 min |

## 3. Cibles et personas

- **Développeur** : veut comprendre et corriger rapidement, sans jargon inutile.
- **Lead tech / CTO de PME** : veut une vue globale du risque et des priorités.
- **ESN** : doit prouver la qualité sécurité du code livré à ses clients.
- **Centre de formation** : outil pédagogique pour enseigner le code sécurisé.

## 4. Périmètre fonctionnel

### 4.1 MVP
1. **Import du code** : upload d'archive ZIP, collage de code, connexion à un dépôt Git (GitHub / GitLab via OAuth).
2. **Langages supportés au lancement** : Python, JavaScript/TypeScript, PHP, Java.
3. **Moteur d'analyse hybride** :
   - **Couche 1 — règles statiques** : moteur SAST open source intégré (règles personnalisables) ;
   - **Couche 2 — détection de secrets** : clés d'API, mots de passe, jetons commités (valeurs masquées dans les rapports) ;
   - **Couche 3 — dépendances (SCA)** : bibliothèques avec vulnérabilités connues (CVE) ;
   - **Couche 4 — IA (Claude via OpenRouter)** : validation contextuelle des alertes pour éliminer les faux positifs, détection de failles logiques non couvertes par les règles.
4. **Classification** : référentiels OWASP Top 10 et CWE, score de sévérité (critique, élevée, moyenne, faible) inspiré du CVSS.
5. **Explication pédagogique** pour chaque faille : ce qu'est la faille, comment un attaquant l'exploiterait (description conceptuelle, sans charge offensive fonctionnelle), impact métier, niveau de difficulté.
6. **Proposition de correctif** : diff avant/après, explication du correctif, bonnes pratiques associées.
7. **Tableau de bord** : score de sécurité du projet, répartition par sévérité et catégorie, évolution dans le temps.
8. **Rapport exportable** : PDF et JSON (pour audit ou client).
9. **Gestion des faux positifs** : marquer une alerte comme ignorée avec justification.

### 4.2 V2 et au-delà
- Commentaires automatiques sur les pull requests.
- Intégration CI/CD (action / job bloquant selon un seuil de sévérité).
- Extension IDE (VS Code).
- Application automatique du correctif via une pull request générée.
- Mode formation : exercices de code vulnérable à corriger.
- Conformité : rapports orientés RGPD, ISO 27001, référentiels ANSSI.

### 4.3 Hors périmètre
- Tests d'intrusion dynamiques (DAST) sur des applications en production.
- Génération d'exploits fonctionnels.

## 5. Parcours utilisateurs clés

1. Je connecte mon dépôt GitHub → je lance une analyse → en 5 minutes je vois 12 failles, dont 2 critiques.
2. J'ouvre une injection SQL critique → je lis l'explication et l'impact → je copie le correctif proposé.
3. Le CTO exporte le rapport PDF pour le transmettre au client.

## 6. Exigences non fonctionnelles

- **Confidentialité du code (critique)** : code analysé dans des conteneurs isolés et éphémères, supprimé après analyse, jamais utilisé pour entraîner un modèle ; chiffrement au repos et en transit ; option d'hébergement dédié ou on-premise pour les grands comptes.
- **Secrets détectés** : jamais stockés ni affichés en clair, uniquement l'emplacement et une empreinte masquée.
- **Performance** : analyses en tâche de fond avec file d'attente, progression en temps réel.
- **Coût IA maîtrisé** : l'IA n'analyse que les extraits pertinents (fonction + contexte), pas le dépôt entier.
- **Multi-tenant** : isolation stricte des organisations.
- **Traçabilité** : journal d'audit des actions (analyses, ignorés, exports).

## 7. Architecture technique

| Couche | Choix |
|---|---|
| Frontend | React 18 + TypeScript + Vite |
| API | FastAPI (Python 3.12) |
| Workers d'analyse | Workers Python (Celery ou ARQ) dans conteneurs Docker éphémères |
| File de tâches | Redis |
| Base de données | MongoDB (projets, analyses, findings, organisations) |
| SAST | Moteur de règles open source intégré + règles maison |
| SCA | Base de vulnérabilités publique (CVE / advisories open source) |
| IA | Claude API via OpenRouter : validation, explication, correctif (sorties JSON structurées) |
| Intégrations | OAuth GitHub / GitLab, webhooks |
| Export | Génération PDF côté serveur |

**Pipeline d'analyse :** clone/upload → détection des langages → règles statiques + secrets + dépendances → regroupement des findings → enrichissement IA (validation, explication, correctif) → scoring → stockage → notification.

**Modèle de données principal :** `Organization`, `User`, `Project`, `Repository`, `Scan`, `Finding` (CWE, OWASP, sévérité, fichier, lignes, statut), `FixSuggestion`, `Report`, `AuditLog`.

## 8. Risques

| Risque | Impact | Mitigation |
|---|---|---|
| Méfiance sur la confidentialité du code | Bloquant | Isolation, suppression, engagement contractuel, offre on-premise |
| Faux positifs ou correctifs erronés | Élevé | Validation IA + règles, correctif présenté comme suggestion, tests sur jeux de référence |
| Coûts IA élevés sur gros dépôts | Moyen | Analyse incrémentale (diff), extraits ciblés, cache |
| Concurrence forte d'acteurs SAST établis | Moyen | Pédagogie en français, cible PME/ESN, prix accessible |

## 9. Modèle économique

- **Freemium** : 1 projet, analyses limitées par mois.
- **Pro** : abonnement par développeur (intégrations PR/CI, rapports).
- **Business / ESN** : multi-projets, rapports clients en marque blanche, SSO.
- **Formation** : licence pour écoles et centres de formation.

## 10. Planning indicatif

| Phase | Durée | Livrables |
|---|---|---|
| Sprint 1 | 2 semaines | Auth, organisations, upload, pipeline de base |
| Sprint 2 | 2 semaines | Règles statiques, secrets, dépendances |
| Sprint 3 | 2 semaines | Enrichissement IA (validation, explication, correctif) |
| Sprint 4 | 2 semaines | Tableau de bord, rapports PDF, connexion GitHub |
| Bêta | 2 semaines | 10 équipes pilotes |

## 11. Critères de réussite du MVP

- Rappel > 85 % sur le jeu de référence interne (applications volontairement vulnérables open source).
- Au moins 5 équipes pilotes qui relancent une analyse la semaine suivante.
- Premier client payant à l'issue de la bêta.
