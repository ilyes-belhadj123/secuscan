# Benchmark externe : projets publics volontairement vulnérables

Le benchmark principal (`benchmark/ground_truth.json`) est écrit par l'équipe qui écrit les règles :
ses chiffres sont optimistes. Ce second benchmark mesure SecuScan sur du code **qu'il n'a jamais vu
pendant l'écriture des règles** : trois applications open source conçues pour enseigner la sécurité,
dont les failles sont documentées par leurs auteurs.

| Projet | Langage | Commit figé | Périmètre annoté |
|---|---|---|---|
| [DVWA](https://github.com/digininja/DVWA) | PHP | `a1978a2` | modules SQL, SQL aveugle, commande, XSS réfléchie, inclusion, envoi de fichier, redirection, force brute (niveaux low / medium / high vulnérables ; « impossible » = version corrigée, qui mesure les faux positifs) |
| [NodeGoat](https://github.com/OWASP/NodeGoat) | JavaScript (Express) | `c5cb68a` | `app/routes/`, `app/data/`, `server.js` (tutoriel OWASP Top 10, failles logiques comprises) |
| [WebGoat](https://github.com/WebGoat/WebGoat) | Java (Spring) | `e7b1313` | leçons SQL, chemins, XXE, désérialisation, SSRF, redirection, cryptographie, JWT, composants vulnérables |

La vérité terrain est dans [benchmark/external.json](../benchmark/external.json) : chaque faille est
repérée par un extrait de la ligne (pas un numéro, qui changerait au moindre ajout), avec son CWE.
**Seuls les fichiers du périmètre comptent** : une alerte ailleurs n'est ni une faille trouvée ni un faux
positif, car ces projets sont trop grands pour être annotés entièrement.

## Lancer la mesure

```bash
cd apps/api
uv run python -m secuscan.benchmark --external          # règles seules (gratuit, ~1 min)
uv run python -m secuscan.benchmark --external --ai     # avec l'IA (clé OpenRouter requise, payant)
```

Les projets sont téléchargés une fois, au commit indiqué, dans un dossier temporaire (`--cache` pour
en choisir un autre). Le rapport est écrit dans
[benchmark/results/latest-external-rules.md](../benchmark/results/latest-external-rules.md).

## Résultats (règles seules, 21/10/2026)

| Langage | Détectées | Manquées | Faux positifs | Détection | Faux positifs |
|---|---|---|---|---|---|
| Java (WebGoat) | 34 | 1 | 0 | 97 % | 0 % |
| JavaScript (NodeGoat) | 8 | 4 | 0 | 67 % | 0 % |
| PHP (DVWA) | 38 | 4 | 7 | 90 % | 16 % |
| **Total** | **80** | **9** | **7** | **90 %** | **8 %** |

Première mesure, avant les corrections : **74 % de détection, 27 % de faux positifs**. Les écarts
relevés ont été corrigés **par des règles générales** (testées dans
`tests/test_external_precision.py`), jamais par des exceptions propres à ces projets : variables
interpolées dans les chaînes, nettoyage propre à chaque faille, échappement SQL sans guillemets,
code mis en commentaire, instructions sur plusieurs lignes, paramètres Spring, JWT `parse()`,
XStream, Zip Slip, dépôt de fichier, redirections…

## Ce que les règles ne voient pas (et pourquoi)

- **Failles logiques** (NodeGoat : contrôle d'accès absent, identifiant pris dans l'URL au lieu de la
  session, mot de passe stocké en clair, journal injectable) : aucune règle par motif ne peut les
  voir ; c'est le rôle de la **revue logique par l'IA**, à mesurer avec `--external --ai`.
- **Entrée stockée puis relue** (DVWA « high » : identifiant saisi sur une page, mis en session, relu
  ailleurs) : la session n'est pas considérée comme une entrée utilisateur, sinon les faux positifs
  exploseraient.
- **Validation par condition** (7 faux positifs restants, DVWA) : `is_numeric` sur chaque octet d'une
  adresse IP, liste d'extensions autorisées, affichage seulement après une connexion réussie. L'analyse
  ne suit pas les conditions ; l'IA, elle, les lit et écarte ces alertes.
- **Méthode héritée au nom générique** (WebGoat `execute()` de la classe parente) : volontairement non
  suivie entre fichiers, pour ne pas confondre des fonctions homonymes.
