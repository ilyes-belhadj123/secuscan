# Plan de la bêta — 10 équipes pilotes (SS-21)

Document interne. Le guide à remettre aux équipes est [guide-equipes-pilotes.md](guide-equipes-pilotes.md).

## Critères de réussite (cahier des charges)

| Indicateur | Objectif | Où le lire |
|---|---|---|
| Équipes pilotes actives | 10 | Tableau de bord « Bêta » |
| Équipes qui relancent une analyse la semaine suivante | ≥ 5 | « Revenues la semaine suivante » |
| Correctifs acceptés (appliqués ou jugés utiles) | > 50 % | « Correctifs acceptés », détail par type |
| Premier client payant à l'issue de la bêta | 1 | Page « Offre et facturation » des organisations |
| Faux positifs après validation IA | < 15 % | Benchmark (`benchmark/results/latest-ai.md`) et alertes ignorées |

Accès au tableau de bord : ajouter votre e-mail à `SECUSCAN_OPERATOR_EMAILS` dans `.env`
(ex. `SECUSCAN_OPERATOR_EMAILS=["vous@votre-societe.fr"]`), redémarrer l'API, puis menu « Bêta ».

## Prérequis techniques avant d'inviter des équipes

- [ ] SecuScan hébergé en ligne en HTTPS (les équipes ne peuvent pas utiliser l'instance locale),
      `SECUSCAN_PUBLIC_URL` et `SECUSCAN_COOKIE_SECURE=true`.
- [ ] Serveur SMTP configuré (invitations, mot de passe oublié).
- [ ] Application OAuth GitHub créée pour l'adresse publique (docs/connexion-github.md).
- [ ] Clé OpenRouter avec une limite de crédit adaptée (≈ 1 $ par analyse d'un projet moyen).
- [ ] Offre des organisations pilotes : Pro offert pendant la bêta (page « Offre », propriétaire).

## Calendrier indicatif (4 semaines)

| Semaine | Action | Indicateur suivi |
|---|---|---|
| S0 | Recrutement : PME / ESN du réseau, un référent technique par équipe | 10 accords |
| S1 | Envoi du guide, appel de 30 minutes par équipe, première analyse accompagnée | Équipes actives |
| S2 | Relance : « relancez une analyse après vos corrections » | Équipes revenues |
| S3 | Questionnaire (proposé automatiquement à J+14), entretiens courts | NPS, commentaires |
| S4 | Synthèse, priorisation des améliorations, proposition commerciale | Taux d'acceptation, 1er client |

## Recrutement : profil des équipes

- 5 à 50 développeurs, au moins un projet actif en Python, JavaScript / TypeScript, PHP ou Java.
- Mélange souhaité : 4 PME éditrices, 4 ESN (rapports clients, marque blanche), 2 centres de formation.
- Un référent disponible 30 minutes par semaine.

## Synthèse de fin de bêta

Le tableau de bord « Bêta » fournit les chiffres ; compléter avec les commentaires sur les correctifs
(regroupés par règle : ceux jugés « Pas utile » indiquent les règles ou prompts à améliorer) et les
réponses « Que manque-t-il ? » du questionnaire.
