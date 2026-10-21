# Benchmark SecuScan — règles seules · projets externes

Exécuté le 21/10/2026 14:33 UTC · 89 failles attendues · tolérance ±2 lignes

| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |
|---|---|---|---|---|---|
| java | 34 | 1 | 0 | 97 % | 0 % |
| javascript | 8 | 4 | 0 | 67 % | 0 % |
| php | 38 | 4 | 7 | 90 % | 16 % |
| **Total** | **80** | **9** | **7** | **90 %** | **8 %** |

Alertes écartées par la validation IA : 0 · doublons : 1

## Failles manquées

- `DVWA/vulnerabilities/sqli/source/high.php:11` CWE-89 — `mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something`
- `DVWA/vulnerabilities/sqli/source/high.php:31` CWE-89 — `$results = $sqlite_db_connection->query($query);`
- `DVWA/vulnerabilities/sqli/source/high.php:20` CWE-79 — `$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";`
- `DVWA/vulnerabilities/sqli/source/high.php:44` CWE-79 — `$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";`
- `NodeGoat/app/routes/index.js:56` CWE-285 — `app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);`
- `NodeGoat/app/routes/session.js:64` CWE-117 — `console.log("Error: attempt to login with invalid user: ", userName);`
- `NodeGoat/app/routes/allocations.js:18` CWE-639 — `} = req.params;`
- `NodeGoat/app/data/user-dao.js:25` CWE-256 — `password //received from request param`
- `WebGoat/src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadBase.java:51` CWE-22 — `var uploadedFile = new File(uploadDirectory, fullName);`

## Faux positifs

- `vulnerabilities/brute/source/high.php:28` PHP-XSS-FLOW (CWE-79) — Cross-site scripting (XSS)
- `vulnerabilities/brute/source/impossible.php:67` PHP-XSS-FLOW (CWE-79) — Cross-site scripting (XSS)
- `vulnerabilities/brute/source/medium.php:23` PHP-XSS-FLOW (CWE-79) — Cross-site scripting (XSS)
- `vulnerabilities/exec/source/impossible.php:22` PHP-CMDI (CWE-78) — Injection de commande système
- `vulnerabilities/exec/source/impossible.php:26` PHP-CMDI (CWE-78) — Injection de commande système
- `vulnerabilities/upload/source/impossible.php:45` PHP-XSS-FLOW (CWE-79) — Cross-site scripting (XSS)
- `vulnerabilities/upload/source/impossible.php:54` PHP-PATH-FLOW (CWE-22) — Traversée de répertoire
