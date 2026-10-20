"""Suivi des données (taint.py) et règles complémentaires (rules_extra.py)."""
import pytest

from secuscan.analyzers import sast
from secuscan.analyzers.taint import find_flows
from secuscan.ingest import SourceFile

EXT = {"python": "py", "javascript": "js", "typescript": "ts", "php": "php", "java": "java"}


def rules(language: str, code: str) -> set[str]:
    return {f.rule_id for f in sast.analyze_file(SourceFile(f"x.{EXT[language]}", language, code))}


VULNERABLE = [
    ("python", "q = request.args['q']\nsql = 'SELECT * FROM t WHERE n = ' + q\ncur.execute(sql)\n", "PY-SQLI"),
    ("python", "url = request.args.get('url')\nr = requests.get(url, timeout=3)\n", "PY-SSRF"),
    ("python", "nxt = request.args['next']\nreturn redirect(nxt)\n", "PY-REDIRECT-FLOW"),
    ("python", "jwt.decode(tok, options={'verify_signature': False})\n", "PY-JWT-NOVERIFY"),
    ("python", "app.secret_key = 'dev'\n", "PY-APP-SECRET"),
    ("python", "resp.set_cookie('sid', sid)\n", "PY-COOKIE"),
    ("python", "tree = etree.fromstring(body)\n", "PY-XXE"),
    ("python", "c = AES.new(key, AES.MODE_ECB)\n", "PY-WEAKCIPHER"),
    ("php", "<?php\n$n = $_GET['n'];\necho \"Hello \" . $n;\n", "PHP-XSS-FLOW"),
    ("php", "<?php\n$id = $_GET['id'];\n$sql = \"SELECT * FROM u WHERE id=$id\";\n$db->query($sql);\n", "PHP-SQLI-FLOW"),
    ("php", "<?php\n$u = $_POST['u'];\n$c = file_get_contents($u);\n", "PHP-SSRF"),
    ("php", "<?php\n$p = $_GET['p'];\ninclude $p . '.php';\n", "PHP-LFI"),
    ("javascript", "const { url } = req.query;\nconst r = await axios.get(url);\n", "JS-SSRF"),
    ("javascript", "const name = req.query.name;\nres.send('<h1>' + name + '</h1>');\n", "JS-XSS-FLOW"),
    ("javascript", "const f = req.params.f;\nres.sendFile('/srv/' + f);\n", "JS-PATH-FLOW"),
    ("javascript", "User.findOne({ email: req.body.email, password: req.body.password });\n", "JS-NOSQL"),
    ("javascript", "const p = _.merge({}, req.body);\n", "JS-PROTO"),
    ("javascript", "jwt.verify(t, k, { algorithms: ['none'] });\n", "JS-JWT-NONE"),
    ("javascript", "app.use(session({ secret: 'keyboard cat' }));\n", "JS-APP-SECRET"),
    ("typescript", "const id = req.query.id as string;\nawait db.query(`SELECT * FROM t WHERE id = ${id}`);\n", "JS-SQLI"),
    ("java", "String u = request.getParameter(\"u\");\nnew URL(u).openStream();\n", "JAVA-SSRF"),
    ("java", "String n = request.getParameter(\"n\");\nresponse.getWriter().println(\"<b>\" + n);\n", "JAVA-XSS-FLOW"),
    ("java", "public String get(@RequestParam String file) {\n  return Files.readString(Paths.get(file));\n}\n",
     "JAVA-PATH-FLOW"),
    ("java", "Cipher c = Cipher.getInstance(\"AES\");\n", "JAVA-WEAKCIPHER"),
    ("java", "http.csrf().disable();\n", "JAVA-CSRF-OFF"),
]


@pytest.mark.parametrize("language, code, expected", VULNERABLE, ids=[v[2] + "-" + str(i) for i, v in enumerate(VULNERABLE)])
def test_detects(language, code, expected):
    found = rules(language, code)
    assert any(r.startswith(expected) for r in found), found


SAFE = [
    # Requête paramétrée : la valeur est passée à part, pas dans le texte SQL
    ("python", "q = request.args['q']\ncur.execute('SELECT * FROM t WHERE n = ?', (q,))\n"),
    ("javascript", "const id = req.query.id;\nawait db.query('SELECT * FROM t WHERE id = ?', [id]);\n"),
    ("php", "<?php\n$id = $_GET['id'];\n$st = $db->prepare('SELECT * FROM u WHERE id = ?');\n$st->execute([$id]);\n"),
    # Nettoyages reconnus
    ("php", "<?php\n$n = $_GET['n'];\necho \"Hello \" . htmlspecialchars($n, ENT_QUOTES, 'UTF-8');\n"),
    ("javascript", "const name = req.query.name;\nres.send('<h1>' + escapeHtml(name) + '</h1>');\n"),
    ("python", "i = request.args['id']\nr = requests.get(f'https://api.example.com/items/{int(i)}', timeout=3)\n"),
    ("java", "String n = request.getParameter(\"n\");\nresponse.getWriter().println(\"<b>\" + Encode.forHtml(n));\n"),
    # Variable réaffectée avec une valeur sûre, ou nom présent seulement dans un texte
    ("python", "url = request.args['u']\nurl = 'https://example.com'\nrequests.get(url, timeout=3)\n"),
    ("javascript", "const name = req.query.name;\nres.send('name');\n"),
    # Fonction suivante : les variables suivies repartent de zéro
    ("python", "def a():\n    url = request.args['u']\n\ndef b(url):\n    return requests.get(url, timeout=3)\n"),
    # Configurations sûres
    ("python", "resp.set_cookie('sid', sid, secure=True, httponly=True, samesite='Lax')\n"),
    ("python", "jwt.decode(tok, PUBLIC_KEY, algorithms=['RS256'])\n"),
    ("python", "tree = etree.fromstring(body, parser=safe_parser)\n"),
    ("javascript", "const KIND = { sast: 'Code', secret: 'Secret' };\n"),
    ("javascript", "User.findOne({ email: String(req.body.email) });\n"),
    ("java", "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"),
]


@pytest.mark.parametrize("language, code", SAFE, ids=[str(i) for i in range(len(SAFE))])
def test_no_false_positive(language, code):
    assert not rules(language, code)


def test_flow_message_names_variable_and_origin():
    code = "<?php\n$n = $_GET['n'];\n$msg = 'Hello ' . $n;\necho $msg;\n"
    finding = [f for f in sast.analyze_file(SourceFile("x.php", "php", code)) if f.rule_id == "PHP-XSS-FLOW"][0]
    assert finding.start_line == 4 and "« msg »" in finding.message and "reçue ligne 2" in finding.message


def test_allowlisted_value_is_not_followed():
    # (la règle PHP-LFI, ligne par ligne, signale encore tout include variable : l'IA tranche ensuite)
    code = "<?php\n$p = in_array($_GET['p'], ['a', 'b'], true) ? $_GET['p'] : 'a';\ninclude __DIR__ . '/' . $p;\n"
    assert find_flows(SourceFile("x.php", "php", code)) == []


def test_no_cascade_on_result_of_flagged_operation():
    code = "<?php\n$h = $_POST['h'];\n$out = shell_exec('nslookup ' . $h);\necho \"<pre>$out</pre>\";\n"
    assert [f.rule_id for f in find_flows(SourceFile("x.php", "php", code))] == ["PHP-CMDI-FLOW"]
