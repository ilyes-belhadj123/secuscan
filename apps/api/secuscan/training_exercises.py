"""SS-24 — catalogue des exercices du mode formation.

Chaque exercice donne un code vulnérable à corriger. La correction n'est jamais exécutée : elle est
validée par les règles de SecuScan (la faille ne doit plus être détectée, aucune autre introduite),
la syntaxe, et des contrôles de structure (`required` : l'idiome sûr est présent ; `forbidden` :
la construction dangereuse a disparu). `solution` n'est montrée qu'une fois l'exercice réussi.
"""
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Check:
    label: str
    pattern: re.Pattern


@dataclass(frozen=True)
class Exercise:
    id: str
    title: str
    language: str
    filename: str
    cwe: str
    difficulty: str  # facile | moyenne | difficile
    brief: str
    code: str
    solution: str
    rules: tuple[str, ...]  # règles qui détectent la faille dans le code d'origine
    hints: tuple[str, ...]
    required: tuple[Check, ...] = field(default_factory=tuple)
    forbidden: tuple[Check, ...] = field(default_factory=tuple)


def _c(label: str, pattern: str) -> Check:
    return Check(label, re.compile(pattern, re.MULTILINE))


EXERCISES: tuple[Exercise, ...] = (
    Exercise(
        id="py-sqli", title="Recherche d'un client par e-mail", language="python", filename="customers.py",
        cwe="CWE-89", difficulty="facile",
        brief="La recherche insère l'e-mail saisi directement dans la requête SQL : un attaquant peut modifier "
              "la requête et lire toute la table. Corrigez la fonction sans changer son résultat.",
        code='''import sqlite3


def find_customer(conn: sqlite3.Connection, email: str):
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name FROM customers WHERE email = '{email}'")
    return cursor.fetchone()
''',
        solution='''import sqlite3


def find_customer(conn: sqlite3.Connection, email: str):
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM customers WHERE email = ?", (email,))
    return cursor.fetchone()
''',
        rules=("PY-SQLI", "PY-SQLI-BUILD"),
        hints=("Le pilote sqlite3 accepte des paramètres séparés de la requête.",
               "Utilisez un marqueur « ? » dans la requête et passez la valeur dans un tuple."),
        required=(_c("La fonction find_customer existe toujours", r"def\s+find_customer\s*\("),
                  _c("La requête utilise un paramètre « ? » passé séparément",
                     r"\.execute\(\s*(\"|')[^\"']*\?[^\"']*\1\s*,")),
        forbidden=(_c("L'e-mail n'est plus concaténé ni formaté dans la requête",
                      r"execute\(\s*f[\"']|\+\s*email|%\s*\(?\s*email|\.format\("),),
    ),
    Exercise(
        id="py-cmdi", title="Test de connectivité d'un serveur", language="python", filename="network.py",
        cwe="CWE-78", difficulty="facile",
        brief="Le nom d'hôte saisi est ajouté à une commande passée au shell : « example.com; rm -rf / » "
              "exécuterait une seconde commande. Lancez ping sans passer par le shell.",
        code='''import os


def ping(host: str) -> int:
    return os.system("ping -c 1 " + host)
''',
        solution='''import subprocess


def ping(host: str) -> int:
    return subprocess.run(["ping", "-c", "1", host], check=False).returncode
''',
        rules=("PY-CMDI",),
        hints=("Le module subprocess peut lancer un programme sans shell.",
               "Passez la commande sous forme de liste : chaque argument reste un argument."),
        required=(_c("La fonction ping existe toujours", r"def\s+ping\s*\("),
                  _c("La commande est lancée avec une liste d'arguments", r"subprocess\.(run|call|check_call)\(\s*\[")),
        forbidden=(_c("Plus d'appel au shell (os.system, os.popen, shell=True)",
                      r"os\.system|os\.popen|shell\s*=\s*True"),),
    ),
    Exercise(
        id="py-yaml", title="Lecture d'un fichier de configuration", language="python", filename="settings.py",
        cwe="CWE-502", difficulty="facile",
        brief="Le chargeur YAML complet peut créer n'importe quel objet Python décrit dans le fichier : un "
              "fichier piégé suffit à exécuter du code. Chargez la configuration de façon sûre.",
        code='''import yaml


def load_config(text: str) -> dict:
    return yaml.load(text, Loader=yaml.Loader)
''',
        solution='''import yaml


def load_config(text: str) -> dict:
    return yaml.safe_load(text)
''',
        rules=("PY-YAML",),
        hints=("PyYAML propose une fonction qui ne crée que des types simples (dict, list, str…).",),
        required=(_c("La fonction load_config existe toujours", r"def\s+load_config\s*\("),
                  _c("Le chargement est sûr (safe_load ou SafeLoader)", r"yaml\.safe_load\(|SafeLoader")),
        forbidden=(_c("Plus de chargeur complet (Loader, FullLoader, UnsafeLoader)",
                      r"Loader\s*=\s*yaml\.(Loader|FullLoader|UnsafeLoader)|unsafe_load"),),
    ),
    Exercise(
        id="py-hash", title="Stockage des mots de passe", language="python", filename="accounts.py",
        cwe="CWE-328", difficulty="moyenne",
        brief="Les mots de passe sont hachés avec MD5 : un attaquant qui vole la base retrouve la plupart "
              "d'entre eux en quelques minutes. Utilisez une fonction de dérivation lente et salée.",
        code='''import hashlib


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
''',
        solution='''import hashlib
import os


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + ":" + digest.hex()
''',
        rules=("PY-WEAKHASH",),
        hints=("hashlib propose scrypt et pbkdf2_hmac, conçus pour les mots de passe.",
               "Chaque mot de passe doit avoir son propre sel aléatoire (os.urandom)."),
        required=(_c("La fonction hash_password existe toujours", r"def\s+hash_password\s*\("),
                  _c("Fonction de dérivation adaptée (scrypt, pbkdf2_hmac, bcrypt, argon2)",
                     r"scrypt|pbkdf2_hmac|bcrypt|argon2"),
                  _c("Sel aléatoire", r"os\.urandom|secrets\.token_bytes|gensalt|argon2")),
        forbidden=(_c("Plus de MD5 ni de SHA-1", r"hashlib\.(md5|sha1)\("),),
    ),
    Exercise(
        id="js-xss", title="Message de bienvenue", language="javascript", filename="welcome.js",
        cwe="CWE-79", difficulty="facile",
        brief="Le prénom (issu de l'adresse de la page) est inséré comme du HTML : un prénom contenant une "
              "balise script exécuterait du code dans le navigateur de la victime. Affichez-le comme du texte.",
        code='''function showWelcome(name) {
  const banner = document.getElementById("welcome");
  banner.innerHTML = "Bonjour " + name + " !";
}
''',
        solution='''function showWelcome(name) {
  const banner = document.getElementById("welcome");
  banner.textContent = `Bonjour ${name} !`;
}
''',
        rules=("JS-XSS",),
        hints=("Le DOM sait insérer une chaîne comme texte brut, sans l'interpréter.",),
        required=(_c("La fonction showWelcome existe toujours", r"function\s+showWelcome\s*\("),
                  _c("Le texte est inséré avec textContent (ou innerText)", r"\.(textContent|innerText)\s*=")),
        forbidden=(_c("Plus d'insertion HTML (innerHTML, outerHTML, insertAdjacentHTML, document.write)",
                      r"innerHTML|outerHTML|insertAdjacentHTML|document\.write"),),
    ),
    Exercise(
        id="js-eval", title="Règle de remise envoyée par le client", language="javascript", filename="discount.js",
        cwe="CWE-95", difficulty="facile",
        brief="La règle de remise reçue en JSON est évaluée comme du code JavaScript : un client malveillant "
              "peut envoyer du code au lieu d'une règle. Lisez-la comme une simple donnée.",
        code='''function applyDiscount(price, ruleJson) {
  const rule = eval("(" + ruleJson + ")");
  return price * (1 - rule.percent / 100);
}
''',
        solution='''function applyDiscount(price, ruleJson) {
  const rule = JSON.parse(ruleJson);
  return price * (1 - rule.percent / 100);
}
''',
        rules=("JS-EVAL",),
        hints=("JavaScript dispose d'un analyseur JSON qui n'exécute jamais de code.",),
        required=(_c("La fonction applyDiscount existe toujours", r"function\s+applyDiscount\s*\("),
                  _c("La règle est lue avec JSON.parse", r"JSON\.parse\(")),
        forbidden=(_c("Plus d'évaluation de code (eval, new Function)", r"\beval\s*\(|new\s+Function\s*\("),),
    ),
    Exercise(
        id="js-sqli", title="Commandes d'un client (Node.js)", language="javascript", filename="orders.js",
        cwe="CWE-89", difficulty="moyenne",
        brief="L'identifiant du client, reçu dans l'URL, est concaténé à la requête SQL : il suffit de le "
              "remplacer par une condition toujours vraie pour lister les commandes de tout le monde.",
        code='''async function listOrders(db, customerId) {
  const [rows] = await db.query("SELECT * FROM orders WHERE customer_id = " + customerId);
  return rows;
}
''',
        solution='''async function listOrders(db, customerId) {
  const [rows] = await db.query("SELECT * FROM orders WHERE customer_id = ?", [customerId]);
  return rows;
}
''',
        rules=("JS-SQLI", "JS-SQLI-BUILD"),
        hints=("mysql2 accepte un tableau de valeurs en second argument.",
               "Remplacez la valeur par « ? » dans la requête."),
        required=(_c("La fonction listOrders existe toujours", r"function\s+listOrders\s*\("),
                  _c("La requête utilise un paramètre « ? » et un tableau de valeurs",
                     r"\.(query|execute)\(\s*([\"'`])[^\"'`]*\?[^\"'`]*\2\s*,\s*\[")),
        forbidden=(_c("L'identifiant n'est plus concaténé ni interpolé", r"\+\s*customerId|\$\{\s*customerId"),),
    ),
    Exercise(
        id="php-sqli", title="Fiche produit", language="php", filename="product.php",
        cwe="CWE-89", difficulty="moyenne",
        brief="L'identifiant du produit est concaténé à la requête : un attaquant peut ajouter une seconde "
              "requête ou lire d'autres tables. Utilisez une requête préparée.",
        code='''<?php
function findProduct(mysqli $db, string $id) {
    $result = mysqli_query($db, "SELECT * FROM products WHERE id = " . $id);
    return mysqli_fetch_assoc($result);
}
''',
        solution='''<?php
function findProduct(mysqli $db, string $id) {
    $stmt = $db->prepare("SELECT * FROM products WHERE id = ?");
    $stmt->bind_param("s", $id);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}
''',
        rules=("PHP-SQLI",),
        hints=("mysqli propose prepare() et bind_param().",),
        required=(_c("La fonction findProduct existe toujours", r"function\s+findProduct\s*\("),
                  _c("Requête préparée (prepare + paramètre lié)", r"prepare\(\s*\"[^\"]*\?")),
        forbidden=(_c("L'identifiant n'est plus concaténé ni interpolé dans la requête",
                      r"\.\s*\$id\b|(?i:select|where)[^;\n]*\$id\b"),),
    ),
    Exercise(
        id="php-xss", title="Page de résultats de recherche", language="php", filename="search.php",
        cwe="CWE-79", difficulty="facile",
        brief="Le terme recherché est réaffiché tel quel dans la page : un lien piégé peut injecter du "
              "JavaScript dans la session de la victime. Échappez-le avant de l'afficher.",
        code='''<?php
echo "<p>Résultats pour : " . $_GET['q'] . "</p>";
''',
        solution='''<?php
echo "<p>Résultats pour : " . htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') . "</p>";
''',
        rules=("PHP-XSS",),
        hints=("PHP dispose d'une fonction qui convertit < > & \" ' en entités HTML.",),
        required=(_c("Le terme est échappé avec htmlspecialchars (ou htmlentities)",
                     r"htmlspecialchars\(|htmlentities\("),),
        forbidden=(_c("Le terme n'est plus affiché sans échappement",
                      r"\.\s*\$_(GET|POST|REQUEST)\[|echo\s+\$_(GET|POST|REQUEST)\["),),
    ),
    Exercise(
        id="java-sqli", title="Connexion d'un utilisateur (JDBC)", language="java", filename="UserRepository.java",
        cwe="CWE-89", difficulty="moyenne",
        brief="Le login est concaténé à la requête : « admin' -- » permettrait de se connecter sans mot de "
              "passe. Utilisez une requête préparée JDBC.",
        code='''import java.sql.*;

public class UserRepository {
    public ResultSet findByLogin(Connection conn, String login) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE login = '" + login + "'");
    }
}
''',
        solution='''import java.sql.*;

public class UserRepository {
    public ResultSet findByLogin(Connection conn, String login) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE login = ?");
        stmt.setString(1, login);
        return stmt.executeQuery();
    }
}
''',
        rules=("JAVA-SQLI", "JAVA-SQLI-BUILD"),
        hints=("JDBC propose PreparedStatement et ses méthodes setString, setInt…",),
        required=(_c("La méthode findByLogin existe toujours", r"findByLogin\s*\("),
                  _c("Requête préparée (prepareStatement + setString)", r"prepareStatement\(\s*\"[^\"]*\?"),
                  _c("Le login est lié comme paramètre", r"\.set(String|Object)\(\s*\d+\s*,\s*login\s*\)")),
        forbidden=(_c("Le login n'est plus concaténé à la requête", r"\+\s*login\b|login\s*\+"),),
    ),
    Exercise(
        id="py-ssrf", title="Aperçu d'un flux partenaire", language="python", filename="preview.py",
        cwe="CWE-918", difficulty="moyenne",
        brief="Le serveur télécharge n'importe quelle adresse fournie par le navigateur : un attaquant peut lui "
              "faire lire des services internes (métadonnées du cloud, interfaces d'administration). Ne laissez "
              "l'utilisateur choisir qu'un partenaire parmi une liste connue.",
        code='''import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/preview")
def preview():
    url = request.args.get("url", "")
    response = requests.get(url, timeout=5)
    return response.text[:500]
''',
        solution='''import requests
from flask import Flask, request

app = Flask(__name__)
PARTNER_FEEDS = {
    "meteo": "https://meteo.example.com/today.json",
    "news": "https://news.example.com/feed.json",
}


@app.get("/preview")
def preview():
    source = request.args.get("source", "")
    partner = source if source in PARTNER_FEEDS else "meteo"
    response = requests.get(PARTNER_FEEDS[partner], timeout=5, allow_redirects=False)
    return response.text[:500]
''',
        rules=("PY-SSRF",),
        hints=("Plutôt que de filtrer une adresse libre (les contournements sont nombreux), faites choisir "
               "une clé : le serveur connaît déjà les adresses autorisées.",
               "Un dictionnaire « nom → adresse » et l'idiome « valeur if valeur in LISTE else défaut » suffisent.",
               "Pensez aussi à refuser les redirections : allow_redirects=False."),
        required=(_c("La route /preview existe toujours", r"def\s+preview\s*\("),
                  _c("L'adresse appelée vient d'une liste fixée par le serveur",
                     r"\bin\s+[A-Z_][A-Z0-9_]*\b")),
        forbidden=(_c("L'adresse fournie par le navigateur n'est plus appelée telle quelle",
                      r"requests\.\w+\(\s*url\b"),),
    ),
    Exercise(
        id="js-path", title="Téléchargement d'une facture", language="javascript", filename="invoices.js",
        cwe="CWE-22", difficulty="facile",
        brief="Le nom de fichier demandé est ajouté au chemin du dossier des factures : « ../../.env » ferait "
              "télécharger un fichier hors du dossier. Ne gardez que le nom du fichier.",
        code='''const express = require("express");
const path = require("path");

const app = express();

app.get("/invoices", (req, res) => {
  const file = path.join(__dirname, "invoices", req.query.name);
  res.sendFile(file);
});
''',
        solution='''const express = require("express");
const path = require("path");

const app = express();

app.get("/invoices", (req, res) => {
  const name = path.basename(String(req.query.name || ""));
  res.sendFile(path.join(__dirname, "invoices", name));
});
''',
        rules=("JS-PATH", "JS-PATH-FLOW"),
        hints=("Les séquences « ../ » permettent de remonter dans l'arborescence.",
               "path.basename() ne garde que le dernier élément d'un chemin."),
        required=(_c("Le nom est réduit au seul nom de fichier", r"path\.basename\("),),
        forbidden=(_c("La saisie n'est plus ajoutée telle quelle au chemin",
                      r"path\.(join|resolve)\([^)]*req\.query\.name"),),
    ),
    Exercise(
        id="js-cmdi", title="Conversion d'une image", language="javascript", filename="thumbnails.js",
        cwe="CWE-78", difficulty="moyenne",
        brief="Le nom du fichier envoyé est inséré dans une commande passée au shell : « a.png; curl … » "
              "lancerait une autre commande sur le serveur. Lancez le programme sans shell, avec ses "
              "arguments séparés.",
        code='''const { exec } = require("child_process");
const express = require("express");

const app = express();

app.post("/thumbnail", (req, res) => {
  exec("convert uploads/" + req.body.file + " -resize 200x200 thumbs/out.png", (err) => {
    res.sendStatus(err ? 500 : 204);
  });
});
''',
        solution='''const { execFile } = require("child_process");
const express = require("express");
const path = require("path");

const app = express();

app.post("/thumbnail", (req, res) => {
  const file = path.basename(String(req.body.file || ""));
  execFile("convert", [path.join("uploads", file), "-resize", "200x200", "thumbs/out.png"], (err) => {
    res.sendStatus(err ? 500 : 204);
  });
});
''',
        rules=("JS-CMDI", "JS-CMDI-FLOW"),
        hints=("exec() passe toute la chaîne à /bin/sh, qui interprète « ; », « | », « $( ) ».",
               "execFile() lance directement le programme : chaque argument est un élément d'un tableau.",
               "Le nom de fichier lui-même ne doit pas sortir du dossier uploads : path.basename()."),
        required=(_c("Le programme est lancé avec execFile (ou spawn) et des arguments séparés",
                     r"\b(execFile|spawn)\(\s*\"convert\"\s*,\s*\["),),
        forbidden=(_c("Plus aucune commande passée au shell", r"\bexec\(|shell\s*:\s*true"),),
    ),
    Exercise(
        id="cs-sqli", title="Recherche de produits (ADO.NET)", language="csharp", filename="ProductRepository.cs",
        cwe="CWE-89", difficulty="moyenne",
        brief="Le nom recherché est concaténé à la requête SQL : « ' OR 1=1 -- » renverrait tout le "
              "catalogue, et pire. Passez la valeur comme paramètre de la commande.",
        code='''using Microsoft.Data.SqlClient;

public class ProductRepository
{
    public SqlDataReader FindByName(SqlConnection conn, string name)
    {
        var cmd = new SqlCommand("SELECT Id, Name FROM Products WHERE Name = '" + name + "'", conn);
        return cmd.ExecuteReader();
    }
}
''',
        solution='''using Microsoft.Data.SqlClient;

public class ProductRepository
{
    public SqlDataReader FindByName(SqlConnection conn, string name)
    {
        var cmd = new SqlCommand("SELECT Id, Name FROM Products WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        return cmd.ExecuteReader();
    }
}
''',
        rules=("CS-SQLI", "CS-SQLI-FLOW"),
        hints=("SqlCommand accepte des paramètres nommés, par exemple « @name » dans la requête.",
               "Ajoutez la valeur avec cmd.Parameters.AddWithValue (ou Add avec un SqlDbType)."),
        required=(_c("La méthode FindByName existe toujours", r"FindByName\s*\("),
                  _c("La requête contient un paramètre nommé", r"SqlCommand\(\s*\"[^\"]*@\w+"),
                  _c("La valeur est liée au paramètre", r"Parameters\.(AddWithValue|Add)\(\s*\"@\w+\"")),
        forbidden=(_c("Le nom n'est plus concaténé à la requête", r"\+\s*name\b|\bname\s*\+|\$\""),),
    ),
    Exercise(
        id="go-sqli", title="Détail d'une commande (database/sql)", language="go", filename="orders.go",
        cwe="CWE-89", difficulty="facile",
        brief="L'identifiant est concaténé à la requête : il suffit d'y glisser une apostrophe pour réécrire "
              "la requête. Utilisez un paramètre positionnel.",
        code='''package store

import "database/sql"

func FindOrder(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT id, total FROM orders WHERE id = '" + id + "'")
}
''',
        solution='''package store

import "database/sql"

func FindOrder(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT id, total FROM orders WHERE id = $1", id)
}
''',
        rules=("GO-SQLI", "GO-SQLI-FLOW"),
        hints=("db.Query accepte la requête puis les valeurs, séparément.",
               "Le marqueur dépend du pilote : « $1 » (PostgreSQL) ou « ? » (MySQL, SQLite)."),
        required=(_c("La fonction FindOrder existe toujours", r"func\s+FindOrder\s*\("),
                  _c("La valeur est passée en paramètre de Query",
                     r"\.Query(Row)?(Context)?\([^\n]*(\$1|\?)\"\s*,\s*id\s*\)")),
        forbidden=(_c("L'identifiant n'est plus concaténé ni formaté", r"\+\s*id\b|\bid\s*\+|Sprintf"),),
    ),
    Exercise(
        id="go-cmdi", title="Diagnostic réseau (os/exec)", language="go", filename="diagnostics.go",
        cwe="CWE-78", difficulty="moyenne",
        brief="La commande passe par « sh -c » avec le nom d'hôte collé à la chaîne : « example.com && … » "
              "exécuterait une seconde commande. Lancez ping directement, l'hôte étant un argument séparé.",
        code='''package tools

import "os/exec"

func Ping(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).Output()
}
''',
        solution='''package tools

import "os/exec"

func Ping(host string) ([]byte, error) {
	return exec.Command("ping", "-c", "1", "--", host).Output()
}
''',
        rules=("GO-CMDI", "GO-CMDI-FLOW"),
        hints=("exec.Command lance un programme sans shell si on ne lui donne pas « sh -c ».",
               "« -- » empêche qu'un hôte commençant par « - » soit lu comme une option."),
        required=(_c("ping est lancé directement, l'hôte en argument séparé",
                     r"exec\.Command(Context)?\([^\n]*\"ping\"[^\n]*,\s*host\s*\)"),),
        forbidden=(_c("Plus de shell (« sh -c », « bash -c »)", r"\"(ba)?sh\"\s*,\s*\"-c\""),
                   _c("L'hôte n'est plus concaténé à la commande", r"\+\s*host\b")),
    ),
    Exercise(
        id="docker-root", title="Image Docker d'une API", language="dockerfile", filename="Dockerfile",
        cwe="CWE-250", difficulty="facile",
        brief="L'image part d'une version « latest » (contenu imprévisible d'une construction à l'autre) et "
              "l'application tourne en root : une faille dans l'API donnerait tous les droits dans le "
              "conteneur. Figez la version et lancez l'application avec un utilisateur dédié.",
        code='''FROM python:latest
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "app.py"]
''',
        solution='''FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 app
USER app
CMD ["python", "app.py"]
''',
        rules=("DOCKER-LATEST", "DOCKER-ROOT"),
        hints=("Une image comme python:3.12-slim fixe la version (et réduit la surface d'attaque).",
               "Créez un utilisateur (useradd) puis basculez dessus avec l'instruction USER, avant CMD."),
        required=(_c("Instruction USER avec un utilisateur non root", r"^USER\s+(?!root\b|0\b)\S+"),),
        forbidden=(_c("Plus d'image « latest » ni sans version", r"^FROM\s+[^\s:@]+(:latest)?\s*$"),),
    ),
    Exercise(
        id="k8s-hardening", title="Déploiement Kubernetes d'un service", language="kubernetes",
        filename="deployment.yaml", cwe="CWE-250", difficulty="difficile",
        brief="Le conteneur peut tourner en root, élever ses privilèges, et n'a aucune limite de ressources "
              "(un seul pod peut saturer le nœud). Durcissez le déploiement sans changer l'image.",
        code='''apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: orders-api
  template:
    metadata:
      labels:
        app: orders-api
    spec:
      containers:
        - name: api
          image: registry.example.com/orders-api:1.4.2
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: true
''',
        solution='''apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: orders-api
  template:
    metadata:
      labels:
        app: orders-api
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: api
          image: registry.example.com/orders-api:1.4.2
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
''',
        rules=("K8S-PRIV-ESCALATION", "K8S-NO-NONROOT", "K8S-NO-LIMITS", "K8S-RUN-AS-ROOT"),
        hints=("securityContext.runAsNonRoot: true refuse de démarrer un conteneur qui tournerait en root.",
               "allowPrivilegeEscalation: false et capabilities.drop: [\"ALL\"] retirent les droits inutiles.",
               "resources.limits (cpu, memory) borne ce qu'un pod peut consommer."),
        required=(_c("runAsNonRoot: true", r"runAsNonRoot:\s*true"),
                  _c("Élévation de privilèges interdite", r"allowPrivilegeEscalation:\s*false"),
                  _c("Limites de ressources", r"limits:\s*\n\s+(cpu|memory):")),
        forbidden=(_c("L'élévation de privilèges n'est plus autorisée", r"allowPrivilegeEscalation:\s*true"),),
    ),
)

EXERCISES_BY_ID = {e.id: e for e in EXERCISES}
