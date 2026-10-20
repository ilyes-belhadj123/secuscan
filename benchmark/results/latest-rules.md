# Benchmark SecuScan — règles seules

Exécuté le 20/10/2026 09:32 UTC · 111 failles attendues · tolérance ±2 lignes

| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |
|---|---|---|---|---|---|
| java | 22 | 0 | 1 | 100 % | 4 % |
| javascript | 22 | 1 | 0 | 96 % | 0 % |
| php | 23 | 0 | 1 | 100 % | 4 % |
| python | 35 | 1 | 3 | 97 % | 8 % |
| typescript | 7 | 0 | 0 | 100 % | 0 % |
| **Total** | **109** | **2** | **5** | **98 %** | **4 %** |

Alertes écartées par la validation IA : 0 · doublons : 1

## Failles manquées

- `acme-shop/backend-python/app.py:100` CWE-639 — `FROM invoices WHERE id = ?`
- `acme-shop/frontend-js/server.js:43` CWE-602 — `const total = quantity * unitPrice;`

## Faux positifs

- `php/account_safe.php:16` PHP-LFI (CWE-98) — Inclusion de fichier dynamique
- `python/orders_api_safe.py:32` PY-SQLI (CWE-89) — Injection SQL
- `python/flows_api_safe.py:36` BANDIT-B108 (CWE-377) — Hardcoded tmp directory
- `backend-python/app.py:42` PY-SQLI (CWE-89) — Injection SQL
- `billing-java/src/main/java/com/acme/billing/InvoiceService.java:47` JAVA-WEAKHASH (CWE-328) — Algorithme de hachage faible
