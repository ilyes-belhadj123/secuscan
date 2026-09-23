# SS-10 — Relecture de 30 explications générées par l'IA

Date : 23/09/2026 · Modèle : Claude Sonnet 5 via OpenRouter · Prompt relu : v1 → corrigé en v2

Échantillon : [explications-echantillon.md](explications-echantillon.md). 30 explications réelles,
diversifiées par CWE (22 CWE différents) et par langage (Python, JavaScript, TypeScript, PHP, Java),
issues d'Acme Shop (démo) et d'OWASP NodeGoat (projet open source réel). Régénérable avec
`uv run python -m secuscan.qa_explanations`.

## Grille de relecture

| Critère | Question |
|---|---|
| Exactitude | La faille décrite est-elle réelle et correctement expliquée pour ce code ? |
| Pédagogie | Un développeur non spécialiste comprend-il le risque ? |
| Scénario conceptuel | L'attaque est-elle décrite sans charge utile exploitable ? |
| Impact métier | L'impact est-il concret (données, argent, RGPD) et proportionné ? |
| Classification | Le CWE est-il le bon ? |
| Correctif | Le correctif est-il correct, applicable dans l'environnement du fichier, sans invention ? |

## Résultats

Contrôles automatiques (complétude, français, absence de charge offensive, références, longueur,
correctif valide) : **30/30**.

Relecture : **26/30 sans remarque**, 4 défauts relevés.

| # | Explication | Défaut | Gravité | Action |
|---|---|---|---|---|
| 20 | Générateur aléatoire — `reviews.ts:16` | Correctif avec `crypto.randomBytes` (Node.js) dans un fichier exécuté par le navigateur : ne fonctionnerait pas | Réelle | Prompt v2 : correctif adapté à l'environnement d'exécution → corrigé (`crypto.getRandomValues`) |
| 23 | Désérialisation Java — `InvoiceService.java:36` | Correctif s'appuyant sur une classe inventée (`LegacyInvoiceRecord`) | Mineure | Prompt v2 : ne rien inventer, signaler l'élément à ajouter → corrigé (`ALLOWED_CLASSES` signalé explicitement) |
| 15 | Comparaison de mot de passe en clair — NodeGoat | CWE-297 (validation de certificat) au lieu de CWE-256 | Mineure | Prompt v2 : exemples de CWE précis |
| 16 | Données sensibles restituées — NodeGoat | CWE-311 approximatif (CWE-200 plus juste) | Mineure | Prompt v2 : exemples de CWE précis |

Points forts constatés : explications adaptées au code réel (noms de paramètres, contexte métier,
secrets présents dans le même fichier), impacts RGPD pertinents, scénarios d'attaque restés
conceptuels (le filtre de sortie n'a jamais eu à intervenir), niveaux de difficulté cohérents,
correctifs minimaux qui réutilisent l'existant (ex. bcrypt déjà présent en commentaire).

## Défaut découvert au passage (SS-11)

En revalidant avec le prompt v2, un correctif Java a été signalé invalide par la vérification
syntaxique : l'extrait envoyé à l'IA incluait l'accolade fermante de la classe (dernière méthode
du fichier), que l'IA a omise. L'extraction du contexte s'arrête désormais à la fin du bloc
englobant. Après correction : 89/89 correctifs valides.

## Non-régression après correction (prompt v2)

| Mesure | Avant (v1) | Après (v2) |
|---|---|---|
| Taux de détection (benchmark, règles + IA) | 100 % | 100 % |
| Taux de faux positifs | 7 % | 7 % |
| Correctifs syntaxiquement valides | 89/89 | 89/89 |

## Limites

- Relecture effectuée par l'assistant de développement (une IA qui relit une IA) avec la grille
  ci-dessus : une contre-relecture par un expert sécurité humain, sur un échantillon, reste
  recommandée avant la bêta (SS-21).
- La vérification des correctifs est syntaxique : elle ne détecte pas les erreurs de compilation
  (ex. exception Java non déclarée) ni les erreurs de logique.
