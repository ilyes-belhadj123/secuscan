# Relecture des explications IA (SS-10)

Échantillon : 30 explications générées par le modèle, diversifiées par CWE et langage.

## Contrôles automatiques

| Contrôle | Réussis |
|---|---|
| complète | 30/30 |
| français | 30/30 |
| sans charge offensive | 30/30 |
| références | 30/30 |
| longueur | 30/30 |
| correctif | 30/30 |

## Échantillon

### 1. Journalisation de données non maîtrisées — `billing-java/src/main/java/com/acme/billing/InvoiceService.java:57`
java · CWE-117 · low · verdict true_positive (85%) · ✓ contrôles automatiques

- **Le problème** : L'injection dans les journaux (Log Injection, CWE-117) survient lorsqu'une donnée externe non filtrée est écrite dans les logs. Un attaquant peut y insérer des caractères spéciaux (retours à la ligne, séquences d'échappement) pour falsifier l'apparence des entrées de log ou perturber leur analyse automatisée.
- **Attaque** : Un attaquant envoie une requête avec un en-tête User-Agent contenant des caractères de retour à la ligne et du texte imitant une nouvelle entrée de log. Cela peut permettre de fabriquer de fausses lignes de log (par exemple simulant une connexion réussie d'un autre utilisateur), trompant les outils de supervision ou les analystes lors d'un audit de sécurité.
- **Impact** : Des journaux falsifiés compromettent la fiabilité des preuves lors d'un incident de sécurité, peuvent masquer une intrusion réelle et fausser les alertes de monitoring, avec un risque de non-conformité RGPD si les logs servent de preuve d'accès aux données personnelles.
- **Difficulté** : facile
- **Correctif** : Le correctif neutralise les caractères de retour chariot et de nouvelle ligne dans la donnée avant journalisation, empêchant l'injection de fausses entrées de log, et utilise le mécanisme de paramétrage de log4j (placeholder {}) qui est plus sûr et performant qu'une concaténation directe.

### 2. Injection de template côté serveur — `backend-python/app.py:74`
python · CWE-1336 · critical · verdict true_positive (98%) · ✓ contrôles automatiques

- **Le problème** : Le SSTI (Server-Side Template Injection) survient quand une entrée utilisateur est interprétée comme du code de template plutôt que comme une simple donnée à afficher. Le moteur de template (ici Jinja2 via Flask) évalue alors des expressions injectées, ce qui peut conduire à de la divulgation d'informations voire à l'exécution de code arbitraire sur le serveur.
- **Attaque** : Un attaquant modifie le paramètre 'name' dans l'URL pour y insérer une syntaxe de template Jinja2 au lieu d'un simple texte. Le moteur de rendu interprète cette syntaxe comme du code exécutable côté serveur, permettant potentiellement d'accéder à des objets internes de l'application, de lire des fichiers ou d'exécuter des commandes système selon les capacités exposées par l'environnement Jinja2.
- **Impact** : Une exploitation réussie peut mener à une prise de contrôle complète du serveur, à la fuite de secrets (clés AWS, mots de passe base de données visibles dans le code), à l'exfiltration de données clients et à une atteinte grave à la réputation de l'entreprise, avec des implications RGPD en cas de fuite de données personnelles.
- **Difficulté** : facile
- **Correctif** : Le correctif utilise la syntaxe native de Jinja2 ({{ name }}) avec passage de la variable en paramètre nommé, au lieu de concaténer la donnée utilisateur dans le template. Ainsi, 'name' est traité comme une simple donnée à afficher (échappée automatiquement par Jinja2) et non comme du code de template interprétable, éliminant le risque de SSTI.

### 3. Dépendance vulnérable : org.apache.logging.log4j:log4j-core 2.14.1 — `billing-java/pom.xml:12`
java · CWE-1395 · critical · verdict true_positive (100%) · ✓ contrôles automatiques

- **Le problème** : Log4j-core 2.14.1 est une bibliothèque de journalisation Java affectée par plusieurs failles critiques, dont la fameuse 'Log4Shell'. Ces vulnérabilités permettent notamment l'exécution de code arbitraire à distance via des mécanismes de recherche de messages (JNDI Lookup) mal contrôlés, ainsi que des déni de service et des problèmes de configuration TLS. Elles figurent parmi les vulnérabilités les plus exploitées au monde depuis fin 2021.
- **Attaque** : Un attaquant envoie une donnée spécialement construite (par exemple dans un en-tête HTTP, un champ de formulaire ou tout autre élément journalisé par l'application) qui, une fois interprétée par Log4j, déclenche une résolution de ressource distante. Cela peut conduire l'application à charger et exécuter du code arbitraire fourni par l'attaquant, sans authentification préalable. D'autres variantes permettent de saturer les ressources serveur (déni de service) via une récursion incontrôlée, ou d'intercepter des communications à cause d'une vérification TLS défaillante.
- **Impact** : Une prise de contrôle totale du serveur applicatif est possible, exposant les données clients, la propriété intellectuelle et l'infrastructure interne à un vol ou une destruction. Cela peut entraîner des interruptions de service prolongées, des obligations légales de notification de fuite de données (RGPD), des sanctions financières et une perte de confiance durable des clients et partenaires.
- **Difficulté** : facile
- **Correctif** : Mettez à jour la dépendance org.apache.logging.log4j:log4j-core vers la version 2.25.4 (ou supérieure) dans votre fichier pom.xml, ainsi que log4j-api si présent en dépendance associée. Vérifiez la compatibilité avec votre code existant : les API principales de journalisation sont stables entre 2.14 et 2.25, mais testez particulièrement les configurations personnalisées (Lookups, Appenders, layouts XML/JSON) et les intégrations avec d'autres frameworks (Spring, etc.). Exécutez la suite de tests automatisés et effectuez une revue manuelle des fichiers de configuration log4j2.xml/properties pour vérifier qu'aucun Lookup dangereux n'est activé.

### 4. Dépendance vulnérable : bson 1.0.9 — `package-lock.json:897`
javascript · CWE-1395 · critical · verdict true_positive (100%) · ✓ contrôles automatiques

- **Le problème** : Ces vulnérabilités concernent la bibliothèque bson, utilisée pour sérialiser et désérialiser des données au format BSON (notamment avec MongoDB). Elles permettent à un attaquant de fournir des données BSON spécialement construites qui provoquent un comportement anormal lors de leur analyse, comme une consommation excessive de mémoire ou un déni de service. Le problème vient d'une insuffisance de contrôle des données lors de la phase de désérialisation.
- **Attaque** : Si l'application accepte des données BSON provenant d'une source non fiable (par exemple une API exposée, un formulaire, ou des données transmises par un client), un attaquant peut envoyer une structure BSON malveillante conçue pour exploiter une faille de parsing. Cela peut entraîner un plantage du processus, un ralentissement important du serveur, ou une consommation anormale de ressources (mémoire ou CPU), affectant la disponibilité du service pour les utilisateurs légitimes.
- **Impact** : Une exploitation réussie peut entraîner une interruption de service (déni de service), affectant la disponibilité de l'application pour les clients et partenaires. Cela peut se traduire par une perte de revenus, une atteinte à la réputation, et potentiellement des pénalités contractuelles (SLA) si le service est indisponible. Selon le contexte, cela peut aussi ouvrir la porte à des attaques plus larges si le service est un composant critique de l'infrastructure.
- **Difficulté** : moyenne
- **Correctif** : Il faut mettre à jour le paquet bson vers la version 1.1.4 ou une version plus récente compatible, via le gestionnaire de paquets npm (npm update bson ou en modifiant la version dans package.json puis npm install). Il est important de vérifier que les autres dépendances (comme le driver MongoDB) restent compatibles avec cette nouvelle version de bson, car des changements d'API mineurs sont possibles. Après mise à jour, il est recommandé de relancer la suite de tests automatisés, en particulier les tests touchant à la sérialisation/désérialisation de documents et aux interactions avec la base de données, pour s'assurer qu'aucune régression n'a été introduite.

### 5. Dépendance vulnérable : guzzlehttp/guzzle 7.4.0 — `legacy-php/composer.json:5`
php · CWE-1395 · high · verdict true_positive (100%) · ✓ contrôles automatiques

- **Le problème** : Le paquet guzzlehttp/guzzle en version 7.4.0 est concerné par de multiples failles de sécurité connues, principalement liées à une mauvaise gestion des en-têtes sensibles (Authorization, Cookie, Proxy-Authorization) et des domaines de cookies lors de redirections HTTP. Ces failles peuvent entraîner la fuite d'informations sensibles vers des serveurs non prévus initialement.
- **Attaque** : Lorsqu'une application utilise Guzzle pour effectuer des requêtes HTTP suivant des redirections (changement de domaine, de port ou passage HTTPS vers HTTP), des en-têtes sensibles comme les jetons d'authentification ou les cookies peuvent être transmis par erreur au nouveau serveur de destination. Un attaquant capable d'influencer une redirection (par exemple via un serveur tiers malveillant ou compromis, ou via une réponse HTTP manipulée) pourrait ainsi intercepter des identifiants de session ou des jetons d'authentification destinés uniquement au domaine d'origine. Ce type de fuite est particulièrement critique dans les architectures faisant des appels vers des API tierces ou des services partenaires.
- **Impact** : Fuite de jetons d'authentification, de cookies de session ou de credentials vers des tiers non autorisés, pouvant conduire à une usurpation de compte, un accès non autorisé à des API internes ou partenaires, voire une compromission de données. Cela peut engendrer une perte de confidentialité des données clients, une atteinte à la conformité réglementaire (RGPD) et une dégradation de la confiance des partenaires ou clients.
- **Difficulté** : moyenne
- **Correctif** : Mettre à jour guzzlehttp/guzzle vers la version 7.15.2 ou supérieure via composer (composer require guzzlehttp/guzzle:^7.15.2), puis exécuter composer update en vérifiant le composer.lock. Il est recommandé de relancer l'ensemble des tests d'intégration touchant les appels HTTP sortants (notamment ceux impliquant des redirections, des proxys ou des cookies), car le comportement de gestion des en-têtes sensibles change entre les versions. Vérifier particulièrement les scénarios de redirection cross-domain et l'utilisation de CookieJar si présents dans le code.

### 6. Dépendance vulnérable : flask 0.12.2 — `backend-python/requirements.txt:1`
python · CWE-1395 · high · verdict true_positive (100%) · ✓ contrôles automatiques

- **Le problème** : Flask 0.12.2 est une version très ancienne qui cumule plusieurs vulnérabilités connues : des risques de déni de service liés à un traitement incorrect des données JSON ou à une consommation mémoire excessive, ainsi qu'un problème de cache HTTP qui peut exposer le cookie de session permanent à d'autres utilisateurs via des caches intermédiaires (proxies, CDN). Ces failles sont documentées publiquement (CVE) et corrigées dans les versions récentes de Flask.
- **Attaque** : Un attaquant pourrait envoyer des requêtes spécialement construites (JSON volumineux ou malformé) pour saturer la mémoire ou le CPU du serveur et provoquer une interruption de service. Concernant le problème de cache, si l'application est derrière un cache partagé (proxy, CDN) sans l'en-tête Vary: Cookie, le cookie de session d'un utilisateur authentifié pourrait être mis en cache et servi à un autre visiteur, entraînant une usurpation de session. Ces scénarios ne nécessitent pas d'accès privilégié, seulement la capacité d'envoyer des requêtes HTTP à l'application.
- **Impact** : Interruption du service (indisponibilité de l'application, perte de chiffre d'affaires, insatisfaction client), risque de compromission de comptes utilisateurs via vol de session, atteinte à la réputation et non-conformité potentielle avec des exigences réglementaires (RGPD si des données personnelles sont exposées via une session détournée).
- **Difficulté** : moyenne
- **Correctif** : Mettre à jour Flask vers la version 3.1.3 (ou la dernière version stable). Attention : il s'agit d'un saut majeur (0.12 → 3.x) qui inclut de nombreux changements cassants (API Werkzeug, gestion des blueprints, suppression de certaines fonctions dépréciées, changements dans la gestion des sessions et du contexte applicatif). Il faut : 1) vérifier la compatibilité des dépendances associées (Werkzeug, Jinja2, itsdangerous, click), 2) relire le changelog officiel de Flask pour chaque version majeure traversée, 3) exécuter l'ensemble des tests automatisés et effectuer des tests manuels sur les routes critiques, la gestion des sessions et les réponses JSON, 4) tester en environnement de staging avant la mise en production.

### 7. Date de début des avantages non validée (paramètre métier arbitraire) — `app/data/benefits-dao.js:23`
javascript · CWE-20 · medium · verdict true_positive (75%) · ✓ contrôles automatiques

- **Le problème** : Il s'agit d'un défaut de validation des données d'entrée (CWE-20) : une valeur métier sensible est acceptée et persistée sans contrôle de type, de format ou de plage acceptable, ce qui peut permettre de contourner des règles métier.
- **Attaque** : Un utilisateur authentifié pourrait envoyer une date de début d'avantages arbitraire (passée, aberrante ou dans un format inattendu) via le formulaire ou l'API qui appelle updateBenefits. Cela permettrait par exemple d'activer des avantages immédiatement alors que la politique métier impose un délai de carence, ou d'injecter une valeur qui casse la logique de calcul des dates ailleurs dans l'application.
- **Impact** : Cela peut entraîner l'octroi indu d'avantages (impact financier direct), des incohérences dans les données RH/paie, et des difficultés de conformité si les avantages sont liés à des obligations légales ou contractuelles envers les salariés.
- **Difficulté** : facile
- **Correctif** : Le correctif ajoute une validation explicite de startDate avant toute écriture en base : vérification que la valeur correspond bien à une date valide (via Date et isNaN), puis contrôle métier basique que la date n'est pas antérieure à aujourd'hui. Si la validation échoue, le callback est appelé avec une erreur au lieu de persister une valeur incohérente, ce qui empêche l'injection d'une date arbitraire non conforme à la logique métier.

### 8. Énumération d'utilisateurs via messages d'erreur distincts — `app/data/user-dao.js:70`
javascript · CWE-203 · medium · verdict true_positive (85%) · ✓ contrôles automatiques

- **Le problème** : L'énumération d'utilisateurs (CWE-203) se produit quand une application révèle, via des messages ou comportements différents, si un identifiant existe dans le système. Cela facilite les attaques de brute force ou de credential stuffing en réduisant l'espace de recherche des attaquants.
- **Attaque** : Un attaquant soumet une liste de noms d'utilisateurs au formulaire de connexion. En observant si l'erreur retournée correspond au flag noSuchUser ou invalidPassword (directement ou indirectement via le message affiché en amont), il peut déterminer quels comptes existent réellement, sans même connaître le mot de passe.
- **Impact** : Une fois les comptes valides identifiés, l'attaquant peut concentrer ses tentatives de brute force ou de credential stuffing sur ces cibles précises, augmentant le risque de compromission de comptes. Cela peut aussi révéler des informations personnelles (ex: email existant en base) posant un problème de conformité RGPD.
- **Difficulté** : facile
- **Correctif** : Le correctif unifie les deux cas d'erreur (utilisateur inexistant et mot de passe invalide) en une seule erreur générique avec un flag unique (authFailed) et un message identique. Ainsi, l'appelant ne peut plus distinguer les deux situations, ce qui empêche l'énumération d'utilisateurs tout en conservant la logique de rejet d'authentification.

### 9. Exposition d'informations sensibles via l'objet erreur transmis à la vue — `app/routes/error.js:10`
javascript · CWE-209 · medium · verdict true_positive (85%) · ✓ contrôles automatiques

- **Le problème** : L'exposition d'informations sensibles via les messages d'erreur (CWE-209) consiste à révéler des détails internes de l'application (stack trace, chemins de fichiers, versions de dépendances, requêtes SQL, etc.) à l'utilisateur final. Ces informations facilitent la reconnaissance pour un attaquant.
- **Attaque** : Un attaquant déclenche volontairement une erreur applicative (entrée invalide, ressource inexistante, etc.) pour observer la page d'erreur rendue. Si le template 'error-template' affiche des propriétés de l'objet err (stack, message technique, chemins internes), l'attaquant obtient des indices sur l'architecture, les technologies utilisées ou la structure du code, ce qui facilite la préparation d'attaques ultérieures.
- **Impact** : Fuite d'informations techniques pouvant aider un attaquant à cartographier l'infrastructure et préparer des attaques ciblées, atteinte à l'image de l'entreprise, et non-conformité potentielle avec le RGPD si des données personnelles transitent par les messages d'erreur (ex: requêtes SQL contenant des données utilisateur).
- **Difficulté** : facile
- **Correctif** : Le correctif ne transmet plus l'objet err brut au template, mais un objet minimal contenant uniquement un message générique destiné à l'utilisateur. Les détails techniques (message réel, stack trace) restent uniquement dans les logs serveur via console.error, sans jamais atteindre le rendu HTML côté client.

### 10. Traversée de répertoire — `frontend-js/server.js:33`
javascript · CWE-22 · high · verdict true_positive (97%) · ✓ contrôles automatiques

- **Le problème** : La traversée de répertoire (Path Traversal) est une faille qui permet à un attaquant de manipuler un chemin de fichier pour accéder à des fichiers situés hors du répertoire prévu, en utilisant des séquences comme les retours au dossier parent.
- **Attaque** : Un attaquant modifie le paramètre 'page' dans l'URL pour inclure des séquences de remontée de répertoire, permettant de sortir du dossier 'docs' et d'accéder à des fichiers sensibles du système comme des fichiers de configuration ou de code source contenant des secrets.
- **Impact** : Cette faille peut exposer des fichiers sensibles (configuration, code source, clés d'API comme celle Stripe visible dans ce fichier), entraînant une fuite de données confidentielles, des risques financiers et une non-conformité RGPD si des données personnelles sont exposées.
- **Difficulté** : facile
- **Correctif** : Le correctif utilise path.basename pour extraire uniquement le nom du fichier (éliminant toute séquence de traversée) et vérifie que le chemin final reste bien dans le dossier 'docs' avant d'envoyer le fichier, empêchant ainsi tout accès à des fichiers hors de ce répertoire.

### 11. Traversée de répertoire — `backend-python/app.py:49`
python · CWE-22 · high · verdict true_positive (97%) · ✓ contrôles automatiques

- **Le problème** : La traversée de répertoire (path traversal) est une faille qui permet à un attaquant de manipuler un chemin de fichier pour accéder à des fichiers situés hors du répertoire prévu par l'application, en utilisant des séquences comme les remontées de dossier.
- **Attaque** : Un attaquant modifie le paramètre 'file' dans l'URL pour y insérer des séquences de remontée de répertoire, ce qui lui permet de sortir du dossier des factures et d'accéder à des fichiers sensibles du système, comme des fichiers de configuration ou des données d'autres utilisateurs.
- **Impact** : Divulgation de fichiers confidentiels (configurations, secrets, données clients), risque de non-conformité RGPD en cas de fuite de données personnelles, atteinte à la réputation de l'entreprise et potentiel rebond vers d'autres attaques si des fichiers systèmes sensibles sont exposés.
- **Difficulté** : facile
- **Correctif** : Le correctif extrait uniquement le nom de fichier (sans chemin) via os.path.basename, normalise le chemin final et vérifie qu'il reste bien dans le répertoire autorisé avant d'ouvrir le fichier, empêchant ainsi toute tentative de sortie du dossier des factures.

### 12. Mot de passe stocké en clair — `app/data/user-dao.js:20`
javascript · CWE-256 · critical · verdict true_positive (98%) · ✓ contrôles automatiques

- **Le problème** : Le stockage de mots de passe en clair (CWE-256) signifie que les mots de passe des utilisateurs sont sauvegardés sans transformation cryptographique. En cas d'accès non autorisé à la base de données, tous les mots de passe sont immédiatement exploitables.
- **Attaque** : Un attaquant qui obtient un accès à la base de données (fuite, sauvegarde mal protégée, injection, employé malveillant) récupère directement tous les mots de passe en clair sans effort de cassage. Il peut ensuite se connecter aux comptes utilisateurs et tester ces mêmes identifiants sur d'autres services, exploitant la réutilisation de mots de passe.
- **Impact** : Compromission immédiate de tous les comptes utilisateurs, risque de fraude et d'usurpation d'identité, atteinte grave à la réputation de l'entreprise, non-conformité RGPD (obligation de protéger les données personnelles sensibles) pouvant entraîner des sanctions financières importantes.
- **Difficulté** : facile
- **Correctif** : Le correctif décommente et active le hachage bcrypt déjà présent dans le code, remplaçant le stockage en clair par un hachage avec sel (salt) unique. Cela garantit qu'en cas de fuite de la base, les mots de passe ne sont pas directement exploitables et nécessitent une attaque par force brute coûteuse.

### 13. Absence de contrôle d'accès sur les mémos affichés — `app/routes/memos.js:19`
javascript · CWE-284 · high · verdict true_positive (90%) · ✓ contrôles automatiques

- **Le problème** : Il s'agit d'une faille de contrôle d'accès (Broken Access Control / IDOR) : l'application ne vérifie pas que l'utilisateur demandant une ressource est bien autorisé à y accéder, permettant de consulter des données appartenant à d'autres comptes.
- **Attaque** : Un utilisateur authentifié avec un compte légitime appelle la route affichant les mémos. Comme aucun filtre par userId n'est appliqué côté serveur, il reçoit dans la réponse les mémos de tous les autres utilisateurs, y compris des informations confidentielles qui ne lui sont pas destinées.
- **Impact** : Fuite de données personnelles ou sensibles entre utilisateurs, violation potentielle du RGPD (accès non autorisé aux données d'autrui), perte de confiance des clients et risque de sanctions réglementaires si des mémos contiennent des informations personnelles.
- **Difficulté** : facile
- **Correctif** : Le correctif remplace l'appel à getAllMemos() (qui retourne tous les mémos sans distinction) par un appel à une méthode du DAO filtrant explicitement par userId (getMemos(userId, callback)), garantissant que seuls les mémos de l'utilisateur authentifié sont renvoyés.

### 14. Vérification TLS désactivée — `backend-python/app.py:82`
python · CWE-295 · high · verdict true_positive (97%) · ✓ contrôles automatiques

- **Le problème** : La vérification TLS garantit que le serveur distant présente un certificat valide et de confiance, prouvant son identité. Désactiver cette vérification permet à n'importe quel serveur, y compris malveillant, de se faire passer pour la destination légitime sans être détecté.
- **Attaque** : Un attaquant positionné sur le réseau (Wi-Fi public, proxy compromis, DNS spoofing) peut intercepter la connexion vers rates.example.com et présenter un faux certificat. Comme la vérification est désactivée, l'application acceptera la réponse falsifiée sans alerte, permettant d'injecter des taux de change erronés ou d'espionner les échanges.
- **Impact** : Des taux de change falsifiés peuvent fausser des calculs financiers (facturation, conversion de devises) et causer des pertes monétaires directes. Cela expose aussi l'entreprise à un risque de compromission de données transitant par cette connexion, avec un impact potentiel sur la confiance des clients et la conformité si des données sensibles sont concernées.
- **Difficulté** : moyenne
- **Correctif** : Le correctif remplace verify=False par verify=True (comportement par défaut de la librairie requests), ce qui réactive la vérification du certificat serveur et empêche toute interception silencieuse par un tiers non authentifié.

### 15. Vérification du mot de passe par comparaison en clair — `app/data/user-dao.js:60`
javascript · CWE-297 · critical · verdict true_positive (98%) · ✓ contrôles automatiques

- **Le problème** : Cette faille (CWE-297) désigne une vérification d'identité incorrecte : ici, les mots de passe ne sont pas hachés lors de la comparaison, ce qui signifie qu'ils sont probablement aussi stockés en clair ou que la vérification ne protège pas contre le vol de la base de données.
- **Attaque** : Si la base de données est compromise (fuite, injection, accès non autorisé), les mots de passe apparaissent directement en clair, permettant à l'attaquant de les réutiliser immédiatement sans effort de cassage. Un attaquant interne (administrateur système, employé malveillant) peut également lire les mots de passe des utilisateurs sans avoir besoin de les déchiffrer.
- **Impact** : Fuite immédiate et massive des mots de passe utilisateurs en cas de compromission de la base, avec risque de réutilisation sur d'autres services (attaques en cascade), atteinte à la réputation de l'entreprise, non-conformité RGPD (absence de mesures de sécurité appropriées pour les données personnelles) et sanctions potentielles de la CNIL.
- **Difficulté** : facile
- **Correctif** : Le correctif remplace la comparaison directe des chaînes par bcrypt.compareSync, qui compare le mot de passe fourni par l'utilisateur avec le hash stocké en base de manière sécurisée, sans jamais exposer ou comparer les mots de passe en clair.

### 16. Restitution en clair de données sensibles au client — `app/data/profile-dao.js:94`
javascript · CWE-311 · high · verdict true_positive (85%) · ✓ contrôles automatiques

- **Le problème** : Il s'agit d'une exposition excessive de données sensibles (CWE-311/CWE-213) : une fonction censée fournir un profil utilisateur retourne l'intégralité des attributs stockés, y compris des données personnelles ou financières sensibles, sans contrôle sur ce qui est réellement nécessaire au consommateur de l'API.
- **Attaque** : Un attaquant ayant un accès légitime ou détourné à l'API (session volée, IDOR sur userId, faille d'autorisation en amont) peut appeler getByUserId et récupérer en une seule réponse le numéro de sécurité sociale, la date de naissance et les coordonnées bancaires de l'utilisateur ciblé. Même sans exploiter une autre faille, tout composant ou log qui manipule cette réponse (frontend, middleware, outil de monitoring) se retrouve à traiter ces données sensibles inutilement, augmentant la surface de fuite.
- **Impact** : Fuite de données personnelles et financières sensibles pouvant entraîner une usurpation d'identité ou une fraude bancaire, une sanction RGPD (amende, mise en demeure de la CNIL) et une perte de confiance des clients ainsi qu'un préjudice d'image pour l'entreprise.
- **Difficulté** : facile
- **Correctif** : Le correctif retire du bloc renvoyé au client les champs sensibles (ssn, dob, coordonnées bancaires) au lieu de tenter un déchiffrement incomplet, ce qui garantit qu'aucune donnée critique ne transite vers l'appelant sans nécessité métier explicite ; si ces champs sont réellement nécessaires, ils doivent être exposés via un endpoint dédié avec contrôle d'accès et masquage partiel.

### 17. Algorithme de hachage faible — `billing-java/src/main/java/com/acme/billing/InvoiceService.java:47`
java · CWE-328 · medium · verdict true_positive (75%) · ✓ contrôles automatiques

- **Le problème** : MD5 est un algorithme de hachage obsolète, vulnérable aux collisions : il est possible de créer deux fichiers différents produisant le même haché. Il ne doit plus être utilisé dès qu'une garantie d'intégrité ou d'authenticité est requise.
- **Attaque** : Si ce checksum sert à vérifier qu'une facture PDF n'a pas été altérée (par exemple stockée puis recontrôlée, ou comparée à une valeur envoyée par un client), un attaquant pourrait fabriquer un second PDF au contenu différent mais partageant le même MD5, contournant ainsi le contrôle d'intégrité. Le risque dépend de l'usage réel fait de ce checksum en aval (simple identifiant vs contrôle de sécurité).
- **Impact** : Si le checksum est utilisé comme preuve d'intégrité d'une facture (valeur légale/comptable), une falsification non détectée pourrait entraîner des litiges commerciaux, des pertes financières ou des problèmes de conformité comptable/fiscale. L'impact réputationnel reste modéré si l'usage est purement technique (déduplication, cache).
- **Difficulté** : moyenne
- **Correctif** : Remplacer MD5 par SHA-256, un algorithme robuste et largement supporté par le JDK, sans changer la signature ni le comportement de la méthode (retourne toujours une chaîne hexadécimale).

### 18. Algorithme de hachage faible — `backend-python/app.py:78`
python · CWE-328 · medium · verdict true_positive (97%) · ✓ contrôles automatiques

- **Le problème** : Un algorithme de hachage faible comme MD5 est rapide à calculer et vulnérable aux attaques par force brute, tables arc-en-ciel et collisions. Il n'est pas conçu pour protéger des secrets comme des mots de passe car il ne dispose pas de coût calculatoire adaptatif ni de sel intégré.
- **Attaque** : Si la base de données contenant les hachages de mots de passe est compromise (fuite, injection SQL, sauvegarde mal protégée), un attaquant peut utiliser des tables précalculées ou du calcul massif sur GPU pour retrouver les mots de passe en clair très rapidement. Les utilisateurs ayant réutilisé leur mot de passe sur d'autres services deviennent alors vulnérables à des prises de contrôle de compte en cascade.
- **Impact** : Compromission massive des comptes utilisateurs, atteinte à la réputation de l'entreprise, obligations de notification RGPD en cas de fuite de données personnelles, et risques financiers liés à la fraude ou aux sanctions réglementaires.
- **Difficulté** : facile
- **Correctif** : Le correctif remplace MD5 par une fonction de hachage dédiée aux mots de passe (via werkzeug.security, déjà présent dans l'écosystème Flask), qui intègre un sel aléatoire et un algorithme lent (PBKDF2 ou scrypt selon la version), rendant les attaques par force brute et les tables précalculées inefficaces.

### 19. Générateur aléatoire non cryptographique — `billing-java/src/main/java/com/acme/billing/InvoiceService.java:52`
java · CWE-338 · low · verdict true_positive (85%) · ✓ contrôles automatiques

- **Le problème** : CWE-338 concerne l'utilisation d'un générateur pseudo-aléatoire non cryptographique pour produire des valeurs sensibles (tokens, identifiants, clés). java.util.Random utilise un algorithme déterministe et prévisible dont la sortie peut être reconstituée si l'on connaît ou devine la graine (seed) ou quelques valeurs précédentes.
- **Attaque** : Un attaquant observant plusieurs références de paiement générées par l'application pourrait, en analysant le comportement de java.util.Random, prédire les prochaines valeurs ou reconstituer la graine utilisée. Il pourrait alors deviner ou anticiper des références de paiement valides, ce qui pourrait faciliter des attaques de fraude, de collision d'identifiants, ou de manipulation de transactions si ces références servent de clé de recherche ou de validation côté métier.
- **Impact** : Risque de fraude financière (usurpation ou collision de références de paiement), incohérences comptables, perte de confiance des clients et partenaires, et exposition potentielle à des obligations réglementaires si des données de paiement sont compromises ou falsifiées.
- **Difficulté** : moyenne
- **Correctif** : Le remplacement de java.util.Random par java.security.SecureRandom garantit une génération de nombres imprévisible et cryptographiquement sûre, empêchant un attaquant de deviner ou reconstituer les références de paiement.

### 20. Générateur aléatoire non cryptographique — `frontend-js/src/reviews.ts:16`
typescript · CWE-338 · low · verdict true_positive (97%) · ✓ contrôles automatiques

- **Le problème** : Math.random() utilise un générateur pseudo-aléatoire non conçu pour la sécurité : ses valeurs peuvent être prédites ou reconstituées, notamment en connaissant l'état interne ou en observant plusieurs sorties. Utiliser ce type de générateur pour des jetons sensibles (session, reset de mot de passe, clé) expose à une prédiction ou une falsification du jeton.
- **Attaque** : Un attaquant qui observe plusieurs jetons générés (ou qui connaît l'algorithme et l'horodatage approximatif) peut réduire l'espace de valeurs possibles et deviner ou reconstruire un jeton de réinitialisation valide. Il pourrait alors usurper une demande de réinitialisation de mot de passe pour un compte cible et en prendre le contrôle sans connaître le mot de passe original.
- **Impact** : Compromission de comptes utilisateurs, prise de contrôle de comptes sensibles (admin, clients), atteinte à la confidentialité des données personnelles avec risque de sanction RGPD, et perte de confiance des clients envers la plateforme.
- **Difficulté** : moyenne
- **Correctif** : Le correctif remplace Math.random() par crypto.randomBytes (module 'crypto' de Node.js), un générateur cryptographiquement sûr, garantissant que les jetons ne sont pas prévisibles ni reconstructibles par un attaquant.

### 21. Absence de régénération de session après authentification (fixation de session) — `app/routes/session.js:104`
javascript · CWE-384 · high · verdict true_positive (90%) · ✓ contrôles automatiques

- **Le problème** : La fixation de session est une faille où l'identifiant de session reste identique avant et après authentification. Un attaquant qui connaît ou impose cet identifiant à sa victime peut ensuite l'utiliser pour accéder au compte une fois que la victime s'est authentifiée.
- **Attaque** : Un attaquant obtient ou impose un identifiant de session à la victime (par exemple via un lien contenant un identifiant de session non sécurisé, ou en interceptant le cookie avant le login). La victime se connecte avec cet identifiant sans qu'il soit régénéré, l'attaquant peut alors utiliser ce même identifiant pour accéder à la session désormais authentifiée avec les privilèges de la victime.
- **Impact** : Un attaquant pourrait usurper l'identité d'un utilisateur légitime, y compris potentiellement un administrateur, accédant ainsi à des données personnelles ou métier sensibles. Cela expose l'entreprise à des risques de fuite de données, de fraude, et à des sanctions RGPD en cas de compromission de données personnelles.
- **Difficulté** : moyenne
- **Correctif** : Le correctif enveloppe l'affectation de req.session.userId dans un appel à req.session.regenerate(), ce qui force la création d'un nouvel identifiant de session lors de la connexion. Ainsi, tout identifiant de session préalablement fixé ou intercepté par un attaquant devient invalide après l'authentification, alignant ce flux sur les bonnes pratiques déjà appliquées lors de l'inscription.

### 22. Mode debug activé — `backend-python/app.py:108`
python · CWE-489 · high · verdict true_positive (95%) · ✓ contrôles automatiques

- **Le problème** : Le mode debug de Flask active un débogueur interactif (Werkzeug) qui affiche la trace complète des erreurs et permet, via un PIN, d'exécuter du code Python arbitraire dans le contexte du serveur. Il s'agit d'une exposition d'informations sensibles et d'une fonctionnalité de débogage dangereuse en production (CWE-489).
- **Attaque** : Un attaquant provoque une erreur applicative (par exemple via une requête malformée) pour faire apparaître la page de débogage Werkzeug, qui révèle la structure du code, les chemins serveur et parfois des variables d'environnement. S'il parvient à accéder à la console interactive du débogueur, il peut exécuter du code sur le serveur, ce qui équivaut à une prise de contrôle complète.
- **Impact** : Fuite d'informations sensibles (code source, secrets, configuration), possibilité d'exécution de code arbitraire menant à une compromission totale du serveur, vol de données clients (factures, adresses), atteinte à la réputation et non-conformité RGPD en cas de fuite de données personnelles.
- **Difficulté** : facile
- **Correctif** : Le correctif désactive le mode debug par défaut et le rend contrôlable uniquement via une variable d'environnement explicite (FLASK_DEBUG), ce qui permet de l'activer localement en développement sans risquer de le laisser actif en production.

### 23. Désérialisation non sécurisée — `billing-java/src/main/java/com/acme/billing/InvoiceService.java:36`
java · CWE-502 · critical · verdict true_positive (90%) · ✓ contrôles automatiques

- **Le problème** : La désérialisation non sécurisée consiste à reconstruire des objets Java à partir d'un flux de données sans contrôler leur type ou leur origine. Comme le processus de désérialisation exécute du code (constructeurs, méthodes readObject personnalisées), un attaquant peut forger un flux qui déclenche l'exécution de code arbitraire sur le serveur.
- **Attaque** : Un attaquant fournit un flux de données binaire spécialement conçu (par exemple via un fichier d'import légal détourné) contenant une chaîne d'objets malveillante utilisant des classes présentes dans les dépendances de l'application (gadget chain). Lors de l'appel à readObject(), la JVM instancie ces objets et déclenche l'exécution de code arbitraire côté serveur, sans que l'application n'ait de contrôle sur ce qui est exécuté.
- **Impact** : Une exploitation réussie permet une exécution de code à distance (RCE) complète sur le serveur de facturation, ouvrant la voie au vol de données clients et financières, à l'installation de portes dérobées, à l'interruption du service de facturation, et à des sanctions RGPD en cas de fuite de données personnelles.
- **Difficulté** : moyenne
- **Correctif** : Le correctif ajoute un filtre de désérialisation (ObjectInputFilter, disponible depuis Java 9) qui restreint explicitement les classes autorisées à être reconstruites à une liste blanche (ici LegacyInvoiceRecord, à adapter selon le format métier réel). Toute autre classe est rejetée avant instanciation, ce qui neutralise les chaînes d'exploitation basées sur des classes tierces (gadget chains) tout en conservant la fonctionnalité d'import légitime.

### 24. Désérialisation non sécurisée — `legacy-php/admin.php:23`
php · CWE-502 · critical · verdict true_positive (98%) · ✓ contrôles automatiques

- **Le problème** : La désérialisation non sécurisée survient lorsqu'une application reconstruit des objets PHP à partir de données non fiables. Si des classes du projet possèdent des méthodes magiques (__wakeup, __destruct, etc.), un attaquant peut fabriquer une chaîne sérialisée qui déclenche des comportements imprévus lors de la désérialisation.
- **Attaque** : Un attaquant modifie la valeur du cookie 'prefs' envoyé à son propre navigateur pour y placer une chaîne sérialisée forgée représentant un objet PHP arbitraire. Si une classe chargée par l'application dispose de méthodes magiques exploitables, l'appel à unserialize() peut déclencher l'exécution de code, la suppression de fichiers, ou d'autres effets de bord selon les classes disponibles (chaîne de gadgets POP chain).
- **Impact** : Une exploitation réussie peut conduire à une exécution de code arbitraire sur le serveur, une compromission complète de l'application, une fuite ou altération de données sensibles (RGPD), et une atteinte grave à la réputation de l'entreprise ainsi que des coûts de remédiation et de notification.
- **Difficulté** : moyenne
- **Correctif** : On remplace unserialize() par json_decode(), qui ne permet pas d'instancier des objets PHP arbitraires ni de déclencher des méthodes magiques. Les préférences utilisateur (structure simple de type tableau/clé-valeur) restent lisibles de la même façon côté métier, mais la surface d'attaque liée à l'injection d'objets est supprimée.

### 25. Désérialisation non sécurisée — `backend-python/app.py:61`
python · CWE-502 · critical · verdict true_positive (98%) · ✓ contrôles automatiques

- **Le problème** : La désérialisation non sécurisée survient lorsqu'une application reconstruit des objets à partir de données provenant d'une source non fiable. Avec pickle, ce processus peut exécuter du code arbitraire car le format permet d'encoder des instructions d'instanciation d'objets et d'appels de méthodes.
- **Attaque** : Un attaquant envoie une requête POST vers l'endpoint de restauration de panier avec un contenu pickle spécialement construit à la place d'un panier légitime. Lors de l'appel à pickle.loads, le processus de désérialisation exécute le code malveillant embarqué, ce qui peut permettre à l'attaquant de prendre le contrôle du serveur.
- **Impact** : Une exécution de code à distance sur le serveur backend peut conduire à un vol de données clients, à l'exfiltration de secrets (identifiants base de données, clés cloud), à une compromission complète de l'infrastructure et à des obligations de notification RGPD en cas de fuite de données personnelles, avec un impact fort sur la réputation.
- **Difficulté** : facile
- **Correctif** : Le correctif remplace pickle.loads par json.loads, un format de sérialisation qui ne permet pas d'exécuter du code arbitraire lors de la désérialisation, tout en conservant la logique métier (compter les éléments du panier). Il faut également valider que le résultat est bien une liste/structure attendue avant de l'utiliser.

### 26. Politique de mot de passe insuffisante à l'inscription — `app/routes/session.js:144`
javascript · CWE-521 · medium · verdict true_positive (97%) · ✓ contrôles automatiques

- **Le problème** : CWE-521 concerne une politique de mot de passe insuffisante, qui permet aux utilisateurs de choisir des mots de passe faibles (courts, simples, prévisibles). Cela réduit la résistance des comptes aux attaques de type brute-force ou dictionnaire.
- **Attaque** : Un attaquant pourrait créer ou cibler des comptes utilisant des mots de passe très simples (comme une seule lettre ou un mot commun), rendant les attaques par force brute ou par dictionnaire beaucoup plus rapides et efficaces. Combiné à une absence de limitation de tentatives, cela facilite la compromission de comptes utilisateurs.
- **Impact** : Des comptes utilisateurs faciles à compromettre peuvent entraîner des accès non autorisés aux données personnelles, des usurpations d'identité, une atteinte à la réputation de l'entreprise et des risques de non-conformité RGPD (obligation de sécuriser les données par des mesures appropriées, article 32).
- **Difficulté** : facile
- **Correctif** : Le correctif active la règle PASS_RE robuste déjà présente en commentaire, qui impose au minimum 8 caractères avec au moins un chiffre, une minuscule et une majuscule. Cela aligne le comportement réel avec le message d'erreur affiché et renforce la résistance des mots de passe aux attaques par force brute.

### 27. Exposition de données sensibles dans les logs — `config/config.js:12`
javascript · CWE-532 · high · verdict true_positive (95%) · ✓ contrôles automatiques

- **Le problème** : L'exposition de données sensibles dans les logs (CWE-532) survient lorsque des informations confidentielles comme des mots de passe, clés API ou tokens sont écrites dans des journaux applicatifs. Ces logs sont souvent moins protégés que les bases de données de production et peuvent être accessibles à un large public (développeurs, outils de supervision, CI/CD).
- **Attaque** : Un attaquant ayant accès aux journaux applicatifs (via un service de logging centralisé, un accès serveur compromis, ou une fuite de logs dans un pipeline CI/CD) peut y retrouver l'intégralité de la configuration, incluant des secrets de connexion à la base de données ou des clés d'API tierces. Ces secrets peuvent ensuite être réutilisés pour accéder directement aux systèmes backend ou aux services externes, sans avoir besoin d'exploiter l'application elle-même.
- **Impact** : Fuite de secrets pouvant conduire à une compromission complète de la base de données ou des services tiers, avec risque de vol de données personnelles (impact RGPD), de fraude financière si des clés de paiement sont exposées, et d'atteinte à la réputation de l'entreprise en cas d'incident rendu public.
- **Difficulté** : facile
- **Correctif** : Le correctif conditionne l'affichage de la configuration à une variable d'environnement explicite (DEBUG_CONFIG) pour éviter les logs en production, et filtre les clés sensibles connues avant tout affichage grâce à underscore (déjà importé). Ainsi, même en cas d'activation du debug, les secrets ne sont jamais écrits dans les journaux.

### 28. Redirection ouverte — `app/routes/index.js:72`
javascript · CWE-601 · medium · verdict true_positive (98%) · ✓ contrôles automatiques

- **Le problème** : Une redirection ouverte (Open Redirect, CWE-601) survient lorsqu'une application redirige un utilisateur vers une URL fournie par lui sans vérifier qu'elle est légitime. Cela permet de rediriger vers des sites malveillants tout en conservant la confiance associée au domaine d'origine.
- **Attaque** : Un attaquant élabore un lien vers le site légitime avec un paramètre 'url' pointant vers un site frauduleux, puis le diffuse par email ou message. La victime, faisant confiance au domaine initial, clique et est redirigée vers une page de phishing imitant le service, où ses identifiants ou données sensibles peuvent être volés.
- **Impact** : Ce type de faille facilite des campagnes de phishing ciblant les utilisateurs de l'application, portant atteinte à la réputation de l'entreprise et pouvant entraîner des violations de données personnelles, avec des implications RGPD si des identifiants ou informations sensibles sont compromis.
- **Difficulté** : facile
- **Correctif** : Le correctif remplace la redirection directe vers une URL arbitraire par une vérification stricte contre une liste blanche de chemins internes autorisés. Si la valeur fournie n'est pas dans cette liste, l'utilisateur est redirigé vers une page par défaut sécurisée, empêchant toute redirection vers un domaine externe non maîtrisé.

### 29. Entités XML externes (XXE) — `billing-java/src/main/java/com/acme/billing/InvoiceService.java:41`
java · CWE-611 · high · verdict true_positive (95%) · ✓ contrôles automatiques

- **Le problème** : Une faille XXE survient lorsqu'un parseur XML mal configuré résout les entités externes déclarées dans un document, permettant de lire des fichiers locaux, d'effectuer des requêtes réseau internes ou de provoquer un déni de service.
- **Attaque** : Un attaquant envoie un fichier XML de facture contenant une déclaration d'entité externe pointant vers une ressource sensible du serveur. Lors du parsing, le parseur va tenter de résoudre cette entité et inclure son contenu dans le document traité, exposant potentiellement des données confidentielles ou déclenchant des appels réseau non désirés.
- **Impact** : Fuite de données sensibles (fichiers système, secrets de configuration, données clients soumises au RGPD), possibilité de rebond vers des services internes (SSRF), et risque de déni de service, avec un impact sur la réputation et une possible sanction réglementaire.
- **Difficulté** : facile
- **Correctif** : Le correctif désactive complètement le traitement des DOCTYPE et des entités externes (générales et paramétrées) ainsi que l'inclusion XInclude, ce qui empêche tout mécanisme d'entité externe d'être résolu par le parseur, neutralisant la faille XXE sans changer la logique métier de parsing.

### 30. Référence directe non sécurisée à un objet (IDOR) sur les allocations utilisateur — `app/routes/allocations.js:16`
javascript · CWE-639 · high · verdict true_positive (98%) · ✓ contrôles automatiques

- **Le problème** : Une IDOR (Insecure Direct Object Reference) survient quand une application expose une référence directe à une ressource interne (comme un identifiant utilisateur) sans vérifier que l'utilisateur courant est autorisé à y accéder. Cela permet de contourner les contrôles d'accès simplement en modifiant un paramètre dans la requête.
- **Attaque** : Un attaquant authentifié observe que l'URL contient son propre identifiant utilisateur dans le paramètre d'URL. Il modifie cet identifiant pour celui d'un autre utilisateur (par exemple en l'incrémentant ou en le devinant) et renvoie la requête. L'application ne vérifie pas que ce userId correspond à la session active, donc elle retourne les allocations financières de la victime.
- **Impact** : Fuite de données personnelles et financières sensibles (allocations) entre utilisateurs, violation du RGPD (accès non autorisé à des données personnelles), risque de perte de confiance des clients et sanctions réglementaires potentielles.
- **Difficulté** : facile
- **Correctif** : Le correctif remplace la lecture du userId depuis req.params (modifiable par l'attaquant) par une lecture depuis req.session, qui est établie côté serveur lors de l'authentification et ne peut pas être falsifiée par le client. Ainsi, chaque utilisateur ne peut consulter que ses propres allocations.

