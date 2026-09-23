"""SS-11 — vérification syntaxique des correctifs dans les 4 langages."""
import pytest

from secuscan.analyzers.syntax import count_errors, patch_is_valid, splice


@pytest.mark.parametrize("language,valid,invalid", [
    ("python", "def f(x):\n    return x + 1\n", "def f(x)\n    return x +\n"),
    ("javascript", "function f(x) { return x + 1; }", "function f(x { return x + ; }"),
    ("typescript", "export function f(x: number): number { return x + 1; }", "export function f(x: number: { return }"),
    ("php", "<?php\nfunction f($x) { return $x + 1; }\n", "<?php\nfunction f($x { return $x + ; }\n"),
    ("java", "class A { int f(int x) { return x + 1; } }", "class A { int f(int x) { return x + ; }"),
])
def test_count_errors(language, valid, invalid):
    assert count_errors(language, valid) == 0
    assert count_errors(language, invalid) > 0


JAVA_FILE = """package com.example;

public class Service {
    public String find(String id) throws Exception {
        return stmt.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");
    }
}
"""


def test_java_method_patch_checked_in_file_context():
    original = JAVA_FILE.split("\n")[3:6]  # la méthode seule : invalide hors de sa classe
    good = [
        "    public String find(String id) throws Exception {",
        "        PreparedStatement ps = connection.prepareStatement(\"SELECT * FROM t WHERE id = ?\");",
        "        ps.setString(1, id);",
        "        return ps.executeQuery();",
        "    }",
    ]
    bad = ["    public String find(String id) throws Exception {", "        return ps.executeQuery(;", "    }"]
    common = {"original": "\n".join(original), "file_content": JAVA_FILE, "start_line": 4}
    assert patch_is_valid("java", "\n".join(good), **common) is True
    assert patch_is_valid("java", "\n".join(bad), **common) is False


def test_php_fragment_without_open_tag():
    assert count_errors("php", "$stmt = $pdo->prepare('SELECT 1');") == 0
    assert count_errors("php", "$stmt = $pdo->prepare('SELECT 1';") > 0


def test_patch_does_not_add_errors_to_already_broken_file():
    broken = "function a( {\n}\nfunction b() { return 1; }\n"
    # Le fichier contient déjà une erreur ailleurs : le correctif de b() est jugé sur ce qu'il ajoute
    assert patch_is_valid("javascript", "function b() { return 2; }", original="function b() { return 1; }",
                          file_content=broken, start_line=3) is True


def test_splice_replaces_exact_lines():
    assert splice("a\nb\nc\nd", 2, 3, "X") == "a\nX\nd"


def test_unknown_language():
    assert count_errors("cobol", "IDENTIFICATION DIVISION.") is None
