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
)

EXERCISES_BY_ID = {e.id: e for e in EXERCISES}
