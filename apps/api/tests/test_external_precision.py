"""Précision des règles : cas relevés en analysant les projets publics DVWA, NodeGoat et WebGoat."""
from secuscan.analyzers import sast
from secuscan.ingest import SourceFile


def rules(code: str) -> list[tuple[int, str]]:
    found = sast.analyze_file(SourceFile("page.php", "php", "<?php\n" + code))
    return sorted((f.start_line - 1, f.rule_id) for f in found)


def test_variables_holding_only_fixed_strings_are_not_injections():
    code = """switch ($_COOKIE['security']) {
    case 'low': $file = 'low.php'; break;
    default: $file = 'impossible.php';
}
require_once ROOT . "source/{$file}";
$check = "SHOW TABLES LIKE 'logs'";
mysqli_query($GLOBALS["db"], $check);
$create = "CREATE TABLE logs (
    id INT
)";
mysqli_query($conn, $create);
"""
    assert rules(code) == []


def test_allowlisted_value_is_not_an_inclusion():
    code = """$page = in_array($_GET['page'], $allowed, true) ? $_GET['page'] : 'home';
include __DIR__ . "/pages/" . $page . ".php";
"""
    assert rules(code) == []


def test_variable_from_elsewhere_is_still_reported():
    assert rules("$file = $_GET['page'];\ninclude($file);\n") == [(2, "PHP-LFI")]
    # Paramètre de fonction, ou une seule affectation non fixe : toujours signalé
    assert rules("function load($file) {\n    include($file);\n}\n") == [(2, "PHP-LFI")]
    mixed = "$q = 'SELECT 1';\n$q = $row['sql'];\nmysqli_query($c, 'SELECT ' . $q);\n"
    assert rules(mixed) == [(3, "PHP-SQLI")]
    # extract() peut créer n'importe quelle variable : pas de déduction
    assert rules("extract($_GET);\n$f = 'a.php';\ninclude($f);\n") == [(3, "PHP-LFI")]


def test_html_built_with_user_input_is_xss():
    assert rules("$html .= '<pre>Hello ' . $_GET['name'] . '</pre>';\n") == [(1, "PHP-XSS-FLOW")]
    assert rules("$name = $_GET['name'];\n$html .= \"<pre>Hello {$name}</pre>\";\n") == [(2, "PHP-XSS-FLOW")]
    # Balise passée en argument, ou valeur échappée : pas de XSS
    assert rules("$name = str_replace('<script>', '', $_GET['name']);\n") == []
    assert rules("$html .= '<pre>' . htmlspecialchars($_GET['name']) . '</pre>';\n") == []


def test_request_body_and_local_files_are_not_ssrf():
    assert rules("$input = json_decode(file_get_contents('php://input'), true);\n") == []
    assert rules("$src = file_get_contents(ROOT . \"pages/{$_GET['id']}.php\");\n") == [(1, "PHP-PATH-FLOW")]
    assert rules("$body = file_get_contents($_GET['url']);\n") == [(1, "PHP-SSRF")]


def test_sanitizer_with_space_before_parenthesis():
    assert rules("$id = intval ($_GET['id']);\n$html .= \"<pre>ID: {$id}</pre>\";\n") == []
    assert rules("$name = md5(uniqid() . $_FILES['f']['name']);\nunlink('/tmp/' . $name);\n") == []


def js(code: str, language: str = "javascript") -> list[tuple[int, str]]:
    found = sast.analyze_file(SourceFile("app.js", language, code))
    return sorted((f.start_line, f.rule_id) for f in found)


def test_callback_sees_variables_of_enclosing_function():
    code = """function ResearchHandler(db) {
    this.displayResearch = (req, res) => {
        const url = req.query.url + req.query.symbol;
        return needle.get(url, (error, response, body) => {
            res.end();
        });
    };
    this.other = (req, res) => {
        return needle.get(url, () => {});
    };
}
"""
    # La fonction voisine (this.other) ne voit pas « url » : pas d'alerte en ligne 9
    assert js(code) == [(4, "JS-SSRF")]


def test_template_autoescape_disabled():
    assert js("swig.setDefaults({\n  autoescape: false\n});\n") == [(2, "JS-TEMPLATE-NOESCAPE")]
    found = sast.analyze_file(SourceFile("a.py", "python", "env = Environment(loader=l, autoescape=False)\n"))
    assert "PY-TEMPLATE-NOESCAPE" in {f.rule_id for f in found}
    assert js("swig.setDefaults({ autoescape: true });\n") == []


def test_redos_nested_quantifiers():
    assert js("const routing = /([0-9]+)+\#/;\n") == [(1, "REDOS")]
    assert js("const ok = /([0-9]+)\#/;\nconst total = (count + 1) * price;\n") == []
    found = sast.analyze_file(SourceFile("a.py", "python", 'EMAIL = re.compile(r"^(\w+\.?)*@example\.com$")\n'))
    assert [f.rule_id for f in found] == ["REDOS"]


def flows(code: str, language: str, path: str = "a") -> list[tuple[int, str]]:
    from secuscan.analyzers.taint import find_flows
    return [(f.line, f.rule_id) for f in find_flows(SourceFile(path, language, code))]


def test_quotes_inside_interpolated_strings_keep_the_variable():
    php = "$id = $_REQUEST['id'];\n$query = \"SELECT * FROM users WHERE id = '$id';\";\n$db->query($query);\n"
    assert flows(php, "php") == [(3, "PHP-SQLI-FLOW")]
    py = ("uid = request.args.get('id')\nsql = f\"SELECT * FROM users WHERE id = '{uid}'\"\n"
          "cursor.execute(sql)\n")
    assert flows(py, "python") == [(3, "PY-SQLI-FLOW")]
    js = "const id = req.query.id;\nconst sql = `SELECT * FROM users WHERE id = '${id}'`;\ndb.query(sql);\n"
    assert flows(js, "javascript") == [(3, "JS-SQLI-FLOW")]
    # Un simple texte entre apostrophes ne porte toujours pas la variable
    assert flows("$id = $_GET['id'];\n$db->query('SELECT id FROM users');\n", "php") == []


def test_mysqli_connection_from_globals():
    php = "$id = $_GET['id'];\nmysqli_query($GLOBALS[\"db\"], \"SELECT * FROM t WHERE id = $id\");\n"
    assert (2, "PHP-SQLI-FLOW") in flows(php, "php")


JAVA_HEAD = "public class C {\n"


def test_java_numeric_parameters_are_not_tainted_and_spring_redirects_are_sinks():
    code = JAVA_HEAD + """  public ModelAndView safe(@RequestParam Integer destId) {
    String dest = DESTINATIONS.getOrDefault(destId, "/welcome");
    return new ModelAndView("redirect:" + dest);
  }
  public ModelAndView real(@RequestParam("url") String url) {
    return new ModelAndView("redirect:" + url);
  }
  public String back(@RequestParam String next) {
    return "redirect:" + next;
  }
}
"""
    assert flows(code, "java") == [(7, "JAVA-REDIRECT-FLOW"), (10, "JAVA-REDIRECT-FLOW")]


def test_java_file_name_as_second_argument():
    code = JAVA_HEAD + """  public void upload(@RequestParam String fullName) {
    var uploaded = new File(uploadDirectory, fullName);
  }
}
"""
    assert flows(code, "java") == [(3, "JAVA-PATH-FLOW")]


def test_same_file_method_wins_over_homonyms():
    from secuscan.analyzers.interproc import cross_file_flows
    lesson = JAVA_HEAD + """  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }
  protected AttackResult injectableQuery(String query) {
    ResultSet results = statement.executeQuery(query);
    return null;
  }
}
"""
    other = JAVA_HEAD + "  protected AttackResult injectableQuery(String q) {\n    return null;\n  }\n}\n"
    found = cross_file_flows([SourceFile("Lesson2.java", "java", lesson), SourceFile("Lesson3.java", "java", other)])
    assert [(f.sink.file, f.sink.line, f.caller_line) for f in found] == [("Lesson2.java", 6, 3)]


def test_copied_libraries_are_vendored():
    from secuscan.ingest import is_vendored
    assert is_vendored("static/js/libs/ace.js", "/* BSD license */\nvar x = 1;\n")
    assert is_vendored("web/vendor/editor.js", "var x = 1;\n")
    banner = "var jQuery = require('jquery');\n\n/*! jQuery UI - v1.10.3 - 2013 * Copyright jQuery Foundation; MIT */\n"
    assert is_vendored("static/jquery-ui.js", banner)
    # Code du projet : dossier lib/ (Node.js), en-tête de copyright de l'entreprise sans version
    assert not is_vendored("lib/server.js", "var x = 1;\n")
    assert not is_vendored("src/app.js", "/* Copyright (c) Acme Corp. All rights reserved. */\nvar x = 1;\n")


def test_code_inside_block_comments_is_ignored():
    from secuscan.analyzers.comments import mask_block_comments
    code = """const q = req.query.q;
/*
    // Correction proposée, mise en commentaire
    res.cookie("session", sessionId);
    eval(req.body.x);
*/
eval(req.body.y);
"""
    assert js(code) == [(7, "JS-EVAL")]
    # Lignes et colonnes conservées ; « /* » dans une chaîne ou une expression régulière : rien n'est masqué
    masked = mask_block_comments(code, "javascript")
    assert masked.count("\n") == code.count("\n") and len(masked) == len(code)
    keep = 'const glob = "src/*.js";\nconst re = /\/*$/;\neval(req.body.z);\n'
    assert mask_block_comments(keep, "javascript") == keep
    assert mask_block_comments("x = 1 /* jamais refermé\neval(a)\n", "javascript").endswith("eval(a)\n")


def test_dot_directories_can_be_excluded():
    from secuscan.ingest import is_excluded
    assert is_excluded(".github/workflows/ci.yml", [".github/"])
    assert is_excluded("src/app.py", ["./src/"])
    assert not is_excluded("github/x.py", [".github/"])


def test_identical_lines_get_distinct_fingerprints(settings, tmp_path):
    from secuscan.sandbox import analyze_static
    (tmp_path / "app.py").write_text("import os\n\ndef a(cmd):\n    os.system(cmd)\n\ndef b(cmd):\n    os.system(cmd)\n",
                                     encoding="utf-8")
    prints = [f.fingerprint for f in analyze_static(tmp_path, settings, "s").findings if f.rule_id == "PY-CMDI"]
    assert len(prints) == 2 and len(set(prints)) == 2


def test_a_sanitizer_only_protects_against_its_own_flaw():
    # htmlspecialchars protège la page HTML, pas la requête SQL
    php = "$id = htmlspecialchars($_GET['id']);\necho $id;\n$db->query(\"SELECT * FROM t WHERE id = $id\");\n"
    assert flows(php, "php") == [(3, "PHP-SQLI-FLOW")]
    # escapeshellarg protège la commande, pas la page
    php = "$h = escapeshellarg($_GET['h']);\nexec('ping ' . $h);\necho $h;\n"
    assert flows(php, "php") == [(3, "PHP-XSS-FLOW")]
    # String() n'est pas un nettoyage
    js = "app.get('/', async (req, res) => {\n  const u = String(req.query.u);\n  await fetch(u);\n});\n"
    assert flows(js, "javascript") == [(3, "JS-SSRF")]
    # Conversion en nombre : sûre partout
    py = "n = int(request.args['n'])\ncursor.execute('SELECT * FROM t LIMIT ' + str(n))\n"
    assert flows(py, "python") == []


def test_url_encoded_component_and_server_side_reads_are_safe():
    js = ("app.get('/', async (req, res) => {\n  const { id } = req.query;\n"
          "  await axios.get(`https://cdn.example.com/a/${encodeURIComponent(id)}.png`);\n});\n")
    assert flows(js, "javascript") == []
    go = ("func Download(w http.ResponseWriter, r *http.Request) {\n\tfile := r.URL.Query().Get(\"file\")\n"
          "\tdata, _ := os.ReadFile(filepath.Join(\"/srv\", filepath.Base(file)))\n\tw.Write(data)\n}\n")
    assert flows(go, "go") == []  # le contenu du fichier vient du serveur, pas du client


def test_prefix_check_protects_against_path_traversal():
    js = """app.get('/download', (req, res) => {
  const target = path.resolve(EXPORTS_DIR, String(req.query.name));
  if (!target.startsWith(EXPORTS_DIR + path.sep)) return res.status(400).end();
  res.sendFile(target);
});
"""
    assert flows(js, "javascript") == []
    unchecked = js.replace("  if (!target.startsWith(EXPORTS_DIR + path.sep)) return res.status(400).end();\n", "")
    assert flows(unchecked, "javascript") == [(3, "JS-PATH-FLOW")]
    py = ("target = os.path.realpath(os.path.join(BASE, request.args['f']))\n"
          "if not target.startswith(BASE + os.sep):\n    abort(400)\nreturn send_file(target)\n")
    assert flows(py, "python") == []
    go = ("func D(w http.ResponseWriter, r *http.Request) {\n\tp := filepath.Join(base, r.URL.Query().Get(\"f\"))\n"
          "\tif !strings.HasPrefix(p, base) {\n\t\treturn\n\t}\n\tos.ReadFile(p)\n}\n")
    assert flows(go, "go") == []


def test_statements_formatted_on_several_lines():
    py = """from flask import request

def search():
    term = request.args.get("q")
    cursor.execute(
        "SELECT * FROM products WHERE name = '" + term + "'"
    )
"""
    assert flows(py, "python") == [(5, "PY-SQLI-FLOW")]
    js = """app.get("/", async (req, res) => {
  const rows = await db.query(
    `SELECT * FROM t WHERE id = ${req.query.id}`,
  );
  res.json(rows);
});
"""
    assert flows(js, "javascript") == [(2, "JS-SQLI-FLOW")]
    # Un callback n'est pas aspiré dans l'instruction : ses lignes restent analysées séparément
    cb = """app.get("/", (req, res) => {
  needle.get(req.query.url, (err, resp) => {
    const name = req.query.name;
    exec("ls " + name);
  });
});
"""
    assert flows(cb, "javascript") == [(2, "JS-SSRF"), (4, "JS-CMDI-FLOW")]


def test_multi_line_signatures_are_followed_across_files():
    from secuscan.analyzers.interproc import cross_file_flows
    storage = "def load_file(\n    name,\n    mode=\"rb\",\n):\n    return open(\"/srv/\" + name, mode).read()\n"
    routes = "from flask import request\n\ndef view():\n    return load_file(request.args[\"f\"])\n"
    found = cross_file_flows([SourceFile("storage.py", "python", storage), SourceFile("routes.py", "python", routes)])
    assert [(f.sink.file, f.sink.line) for f in found] == [("storage.py", 5)]


def test_secrets_in_configuration_files_are_found(settings, tmp_path):
    from secuscan.sandbox import analyze_static
    (tmp_path / "src" / "main" / "resources").mkdir(parents=True)
    (tmp_path / "src" / "main" / "resources" / "application.properties").write_text(
        "spring.datasource.url=jdbc:postgresql://db/shop\nspring.datasource.password=Pl4ceholder-Db-Passw0rd\n",
        encoding="utf-8")
    (tmp_path / ".npmrc").write_text("//registry.example.com/:_authToken=npm_Pl4ceholderTokenValue000000000000000\n",
                                     encoding="utf-8")
    (tmp_path / "settings.yml").write_text("smtp:\n  password: \"Pl4ceholder-Smtp-Secret\"\n", encoding="utf-8")
    result = analyze_static(tmp_path, settings, "s")
    found = {f.file for f in result.findings if f.kind == "secret"}
    assert found == {"src/main/resources/application.properties", ".npmrc", "settings.yml"}
    # La valeur reste masquée dans ce qui sort de l'analyse (affichage, IA)
    props = result.redacted["src/main/resources/application.properties"].content
    assert "Pl4ceholder-Db-Passw0rd" not in props
    # Aucune règle de code ne s'applique à ces fichiers
    assert all(f.kind == "secret" for f in result.findings)


def test_translated_labels_are_not_secrets(settings, tmp_path):
    from secuscan.sandbox import analyze_static
    (tmp_path / "i18n").mkdir()
    (tmp_path / "i18n" / "messages_de.properties").write_text("password=Passwort\n", encoding="utf-8")
    (tmp_path / "app.properties").write_text("ui.label.password=Contraseña\nfeature.token=enabled\n",
                                             encoding="utf-8")
    assert [f for f in analyze_static(tmp_path, settings, "s").findings if f.kind == "secret"] == []


def test_interface_texts_are_not_sql():
    def ids(code, language):
        return [f.rule_id for f in sast.analyze_file(SourceFile("a", language, code))]
    assert ids('msg = "Message from %s" % user\n', "python") == []
    assert ids('if (confirm("Delete " + name + "?")) remove(name);\n', "javascript") == []
    assert ids('label = "Select a file from the list: " + name\n', "python") == []
    # Vraies requêtes, en majuscules ou en minuscules
    assert ids('q = "SELECT * FROM users WHERE id = " + uid\n', "python") == ["PY-SQLI-BUILD"]
    assert ids('const q = "select name from users where id = " + id;\n', "javascript") == ["JS-SQLI-BUILD"]
    assert ids('q = ("SELECT id "\n     "FROM users WHERE name = \'%s\'" % name)\n', "python") == ["PY-SQLI-BUILD"]


def test_sibling_callbacks_keep_the_route_variables():
    js = """app.get("/", (req, res) => {
  const id = req.query.id;
  a.then(() => {
    log("ok");
  });
  b.then(() => {
    db.query("SELECT * FROM t WHERE id = " + id);
  });
});
app.get("/other", (req, res) => {
  db.query("SELECT * FROM t WHERE id = " + id);
});
"""
    # La 2e route ne voit pas « id » de la première
    assert flows(js, "javascript") == [(7, "JS-SQLI-FLOW")]


def test_summarized_body_keeps_parameters_inside_callbacks():
    from secuscan.analyzers.interproc import cross_file_flows
    store = """function fetchProfile(profileName) {
  return new Promise((resolve) => {
    db.query("SELECT * FROM p WHERE name = '" + profileName + "'", resolve);
  });
}
"""
    route = 'app.get("/p", (req, res) => {\n  fetchProfile(req.query.name);\n});\n'
    found = cross_file_flows([SourceFile("store.js", "javascript", store), SourceFile("route.js", "javascript", route)])
    assert [(f.sink.file, f.sink.line) for f in found] == [("store.js", 3)]


def test_bandit_runs_in_batches(tmp_path, monkeypatch):
    from secuscan.analyzers import external
    if not external.bandit_available():
        return
    monkeypatch.setattr(external, "BANDIT_BATCH", 1)
    for i in range(3):
        (tmp_path / f"m{i}.py").write_text("import subprocess\nsubprocess.call(cmd, shell=True)\n", encoding="utf-8")
    found = external.run_bandit(tmp_path, [f"m{i}.py" for i in range(3)])
    assert {f.file for f in found} == {"m0.py", "m1.py", "m2.py"}


def test_sarif_with_absolute_paths_is_kept(tmp_path):
    from secuscan.analyzers.external import parse_sarif
    absolute = (tmp_path / "src" / "app.py").resolve().as_posix()
    sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "r1"}]}}, "results": [
        {"ruleId": "r1", "message": {"text": "m"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "file:///" + absolute.lstrip("/")}, "region": {"startLine": 3}}}]}]}]}
    found = parse_sarif(sarif, {"src/app.py": "python"}, root=tmp_path)
    assert [(f.file, f.start_line) for f in found] == [("src/app.py", 3)]


def test_ternary_and_escaped_quotes():
    from secuscan.analyzers.taint import split_arguments
    js = "app.get('/', (req, res) => {\n  const u = req.query.u;\n  fetch(ok ? u : DEFAULT_URL);\n});\n"
    assert flows(js, "javascript") == [(3, "JS-SSRF")]
    # Clé d'objet : pas une utilisation de la variable
    js_key = "app.get('/', (req, res) => {\n  const u = req.query.u;\n  fetch(API, { u: 1 });\n});\n"
    assert flows(js_key, "javascript") == []
    assert split_arguments('"a\\\\", b)') == ['"a\\\\"', " b"]
    assert split_arguments('"x\\"y", z)') == ['"x\\"y"', " z"]


def test_kubernetes_documents_are_checked_one_by_one():
    hardened = """apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    spec:
      securityContext: {runAsNonRoot: true}
      containers:
        - name: api
          image: registry.example.com/api:1.2.0
          resources: {limits: {cpu: 500m}}
"""
    bare = hardened.replace("      securityContext: {runAsNonRoot: true}\n", "").replace("metadata: {name: api}",
                                                                                         "metadata: {name: worker}")
    found = sast.analyze_file(SourceFile("k8s.yaml", "kubernetes", hardened + "---\n" + bare))
    assert [(f.rule_id, f.start_line) for f in found if f.rule_id == "K8S-NO-NONROOT"] == [("K8S-NO-NONROOT", 19)]
    assert not [f for f in sast.analyze_file(SourceFile("c.yml", "compose", "services:\n  api:\n    image: ${API_IMAGE}\n"))
                if f.rule_id == "IAC-IMAGE-LATEST"]


def test_terraform_open_ingress_on_several_lines():
    tf = """resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }
}
"""
    assert [f.rule_id for f in sast.analyze_file(SourceFile("main.tf", "terraform", tf))
            if f.rule_id == "TF-OPEN-INGRESS"] == ["TF-OPEN-INGRESS"]


def test_csharp_content_is_xss_only_as_html():
    code = """public class C : Controller {
    public IActionResult A(string q) {
        return Content(q);
    }
    public IActionResult B(string q) {
        return Content(q, "text/html");
    }
}
"""
    assert flows(code, "csharp") == [(6, "CS-XSS-FLOW")]


def test_sql_escaping_protects_only_quoted_values():
    base = "$id = mysqli_real_escape_string($conn, $_POST['id']);\n"
    unquoted = base + "$q = \"SELECT * FROM users WHERE id = $id;\";\nmysqli_query($conn, $q);\n"
    quoted = base + "$q = \"SELECT * FROM users WHERE id = '$id';\";\nmysqli_query($conn, $q);\n"
    assert flows(unquoted, "php") == [(3, "PHP-SQLI-FLOW")]
    assert flows(quoted, "php") == []
    # Toujours non fiable pour la page HTML
    assert flows(base + "echo $id;\n", "php") == [(2, "PHP-XSS-FLOW")]


def java_rules(code: str) -> list[str]:
    return sorted({f.rule_id for f in sast.analyze_file(SourceFile("A.java", "java", code))})


def test_java_jwt_xstream_and_zip_slip():
    assert java_rules("Jwt jwt = Jwts.parser().setSigningKey(KEY).parse(token);\n") == ["JAVA-JWT-PARSE"]
    assert java_rules("Jws<Claims> c = Jwts.parser().setSigningKey(KEY).parseClaimsJws(token);\n") == []
    assert java_rules("contact = (Contact) xstream.fromXML(payload);\n") == ["JAVA-DESER"]
    zip_code = ("import java.util.zip.ZipEntry;\nclass A {\n  void x(ZipEntry e) {\n"
                "    File f = new File(dir, e.getName());\n  }\n}\n")
    assert "JAVA-ZIPSLIP" in java_rules(zip_code)
    guard = "    if (!f.toPath().normalize().startsWith(dir.toPath())) throw new IOException();\n"
    checked = zip_code.replace("    File f", guard + "    File f")
    assert "JAVA-ZIPSLIP" not in java_rules(checked)


def test_spring_params_without_annotation_and_split_concatenation():
    code = """public class Lesson {
  @PostMapping("/attack")
  @ResponseBody
  public AttackResult completed(String name, Integer page) {
    String query =
        "SELECT * FROM employees WHERE last_name = '"
            + name
            + "'";
    ResultSet results = statement.executeQuery(query);
    return null;
  }
}
"""
    assert flows(code, "java") == [(9, "JAVA-SQLI-FLOW")]
    # Sans annotation de routage, un paramètre texte n'est pas une entrée utilisateur
    assert flows(code.replace('  @PostMapping("/attack")\n', ""), "java") == []
