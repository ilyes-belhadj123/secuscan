# Benchmark SecuScan — règles + IA

Exécuté le 23/09/2026 11:28 UTC · 83 failles attendues · tolérance ±2 lignes

| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |
|---|---|---|---|---|---|
| java | 16 | 0 | 1 | 100 % | 6 % |
| javascript | 17 | 0 | 3 | 100 % | 15 % |
| php | 18 | 0 | 1 | 100 % | 5 % |
| python | 25 | 0 | 1 | 100 % | 4 % |
| typescript | 7 | 0 | 0 | 100 % | 0 % |
| **Total** | **83** | **0** | **6** | **100 %** | **7 %** |

Alertes écartées par la validation IA : 4 · doublons : 0

## Correctifs proposés (SS-11)

89 correctifs · syntaxe valide : **89/89** (100 %) · non vérifiables : 0


## Failles manquées

Aucune.

## Faux positifs

- `python/orders_api_safe.py:36` AI-LOGIC (CWE-22) — Listage arbitraire de répertoires via le paramètre 'folder'
- `javascript/shop_server_safe.js:15` AI-LOGIC (CWE-639) — Absence de contrôle d'accès sur la ressource utilisateur
- `javascript/shop_server_safe.js:16` AI-LOGIC (CWE-200) — Exposition potentielle de données sensibles via SELECT *
- `php/account_safe.php:6` AI-LOGIC (CWE-639) — Accès direct à un compte par identifiant sans contrôle de propriétaire
- `billing-java/src/main/java/com/acme/billing/InvoiceService.java:47` JAVA-WEAKHASH (CWE-328) — Algorithme de hachage faible
- `frontend-js/server.js:41` AI-LOGIC (CWE-306) — Absence de contrôle d'authentification sur la création de commande
