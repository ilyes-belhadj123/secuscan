# Benchmark SecuScan — règles + IA

Exécuté le 20/10/2026 10:27 UTC · 151 failles attendues · tolérance ±2 lignes

| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |
|---|---|---|---|---|---|
| compose | 3 | 0 | 0 | 100 % | 0 % |
| csharp | 9 | 0 | 1 | 100 % | 10 % |
| dockerfile | 6 | 0 | 0 | 100 % | 0 % |
| go | 8 | 0 | 0 | 100 % | 0 % |
| java | 22 | 0 | 1 | 100 % | 4 % |
| javascript | 23 | 0 | 4 | 100 % | 15 % |
| kubernetes | 8 | 0 | 0 | 100 % | 0 % |
| php | 23 | 0 | 1 | 100 % | 4 % |
| python | 36 | 0 | 3 | 100 % | 8 % |
| terraform | 6 | 0 | 0 | 100 % | 0 % |
| typescript | 7 | 0 | 0 | 100 % | 0 % |
| **Total** | **151** | **0** | **10** | **100 %** | **6 %** |

Alertes écartées par la validation IA : 4 · doublons : 2

Appels IA : 47 · coût estimé : 1.33 $

## Correctifs proposés (SS-11)

163 correctifs · syntaxe valide : **139/139** (100 %) · non vérifiables : 24

Correctifs invalides relancés auprès de l'IA : 1 · rendus valides : 1


## Failles manquées

Aucune.

## Faux positifs

- `python/flows_api_safe.py:36` BANDIT-B108 (CWE-377) — Hardcoded tmp directory
- `python/orders_api_safe.py:36` AI-LOGIC (CWE-22) — Listage arbitraire de répertoires via le paramètre 'folder'
- `javascript/shop_server_safe.js:15` AI-LOGIC (CWE-639) — Absence de contrôle d'accès sur la ressource utilisateur
- `javascript/shop_server_safe.js:16` AI-LOGIC (CWE-200) — Exposition potentielle de données sensibles via SELECT *
- `php/account_safe.php:6` AI-LOGIC (CWE-639) — Accès direct à un compte par identifiant sans contrôle de propriétaire
- `javascript/flows_server_safe.js:23` AI-LOGIC (CWE-287) — Authentification contournée : absence de vérification de mot de passe
- `python/flows_api_safe.py:54` AI-LOGIC (CWE-384) — Identifiant de session accepté depuis la requête du client
- `csharp/OrdersControllerSafe.cs:39` AI-LOGIC (CWE-639) — Accès à une facture arbitraire sans vérification de propriétaire
- `billing-java/src/main/java/com/acme/billing/InvoiceService.java:47` JAVA-WEAKHASH (CWE-328) — Algorithme de hachage faible
- `frontend-js/server.js:41` AI-LOGIC (CWE-306) — Absence de contrôle d'authentification sur la création de commande
