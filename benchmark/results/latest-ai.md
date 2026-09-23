# Benchmark SecuScan — règles + IA

Exécuté le 23/09/2026 11:19 UTC · 83 failles attendues · tolérance ±2 lignes

| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |
|---|---|---|---|---|---|
| java | 16 | 0 | 1 | 100 % | 6 % |
| javascript | 17 | 0 | 2 | 100 % | 11 % |
| php | 18 | 0 | 2 | 100 % | 10 % |
| python | 25 | 0 | 1 | 100 % | 4 % |
| typescript | 7 | 0 | 0 | 100 % | 0 % |
| **Total** | **83** | **0** | **6** | **100 %** | **7 %** |

Alertes écartées par la validation IA : 3 · doublons : 0

## Correctifs proposés (SS-11)

89 correctifs · syntaxe valide : **89/89** (100 %) · non vérifiables : 0


## Failles manquées

Aucune.

## Faux positifs

- `php/account_safe.php:6` AI-LOGIC (CWE-639) — Accès à un compte par identifiant sans contrôle de propriétaire
- `php/account_safe.php:11` AI-LOGIC (CWE-918) — Hôte de commande ping non validé (risque de sondage réseau interne)
- `python/orders_api_safe.py:36` AI-LOGIC (CWE-22) — Traversée de chemin dans la liste de fichiers
- `javascript/shop_server_safe.js:15` AI-LOGIC (CWE-639) — Accès aux données d'un utilisateur sans contrôle d'autorisation
- `billing-java/src/main/java/com/acme/billing/InvoiceService.java:47` JAVA-WEAKHASH (CWE-328) — Algorithme de hachage faible
- `frontend-js/server.js:42` AI-LOGIC (CWE-20) — Absence de validation de quantité et d'existence du produit
