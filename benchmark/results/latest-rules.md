# Benchmark SecuScan — règles seules

Exécuté le 23/09/2026 14:52 UTC · 83 failles attendues · tolérance ±2 lignes

| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |
|---|---|---|---|---|---|
| java | 16 | 0 | 1 | 100 % | 6 % |
| javascript | 16 | 1 | 0 | 94 % | 0 % |
| php | 18 | 0 | 1 | 100 % | 5 % |
| python | 24 | 1 | 2 | 96 % | 8 % |
| typescript | 7 | 0 | 0 | 100 % | 0 % |
| **Total** | **81** | **2** | **4** | **98 %** | **5 %** |

Alertes écartées par la validation IA : 0 · doublons : 0

## Failles manquées

- `acme-shop/backend-python/app.py:100` CWE-639 — `FROM invoices WHERE id = ?`
- `acme-shop/frontend-js/server.js:43` CWE-602 — `const total = quantity * unitPrice;`

## Faux positifs

- `php/account_safe.php:16` PHP-LFI (CWE-98) — Inclusion de fichier dynamique
- `python/orders_api_safe.py:32` PY-SQLI (CWE-89) — Injection SQL
- `backend-python/app.py:42` PY-SQLI (CWE-89) — Injection SQL
- `billing-java/src/main/java/com/acme/billing/InvoiceService.java:47` JAVA-WEAKHASH (CWE-328) — Algorithme de hachage faible
