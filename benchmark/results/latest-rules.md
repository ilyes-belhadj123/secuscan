# Benchmark SecuScan — règles seules

Exécuté le 21/10/2026 14:33 UTC · 161 failles attendues · tolérance ±2 lignes

| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |
|---|---|---|---|---|---|
| compose | 3 | 0 | 0 | 100 % | 0 % |
| csharp | 9 | 0 | 0 | 100 % | 0 % |
| dockerfile | 6 | 0 | 0 | 100 % | 0 % |
| go | 10 | 0 | 0 | 100 % | 0 % |
| java | 24 | 0 | 1 | 100 % | 4 % |
| javascript | 24 | 1 | 0 | 96 % | 0 % |
| kubernetes | 8 | 0 | 0 | 100 % | 0 % |
| php | 25 | 0 | 0 | 100 % | 0 % |
| python | 37 | 1 | 2 | 97 % | 5 % |
| terraform | 6 | 0 | 0 | 100 % | 0 % |
| typescript | 7 | 0 | 0 | 100 % | 0 % |
| **Total** | **159** | **2** | **3** | **99 %** | **2 %** |

Alertes écartées par la validation IA : 0 · doublons : 2

## Failles manquées

- `acme-shop/backend-python/app.py:100` CWE-639 — `FROM invoices WHERE id = ?`
- `acme-shop/frontend-js/server.js:43` CWE-602 — `const total = quantity * unitPrice;`

## Faux positifs

- `python/orders_api_safe.py:32` PY-SQLI (CWE-89) — Injection SQL
- `backend-python/app.py:42` PY-SQLI (CWE-89) — Injection SQL
- `billing-java/src/main/java/com/acme/billing/InvoiceService.java:47` JAVA-WEAKHASH (CWE-328) — Algorithme de hachage faible
