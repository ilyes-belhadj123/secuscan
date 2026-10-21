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
