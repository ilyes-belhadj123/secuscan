"""SS-11 — vérification syntaxique des correctifs proposés (sans jamais exécuter le code).

Le correctif (un extrait) est replacé dans le fichier complet avant l'analyse : un extrait isolé
(méthode Java hors de sa classe, fragment PHP sans balise) serait jugé invalide à tort. Un correctif
est valide s'il n'introduit aucune erreur de syntaxe par rapport au fichier d'origine.
"""
import ast
import textwrap
from functools import lru_cache

import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_php
import tree_sitter_typescript
from tree_sitter import Language, Parser

_GRAMMARS = {
    "javascript": tree_sitter_javascript.language,
    "typescript": tree_sitter_typescript.language_typescript,
    "tsx": tree_sitter_typescript.language_tsx,
    "java": tree_sitter_java.language,
    "php": tree_sitter_php.language_php,  # fichier complet : HTML + <?php ... ?>
    "php_only": tree_sitter_php.language_php_only,  # extrait sans balise d'ouverture
}


@lru_cache
def _parser(grammar: str) -> Parser:
    return Parser(Language(_GRAMMARS[grammar]()))


def _grammar_for(language: str, code: str, filename: str = "") -> str | None:
    if language == "typescript":
        return "tsx" if filename.endswith(".tsx") else "typescript"
    if language == "php":
        return "php" if "<?php" in code or "<?=" in code else "php_only"
    return language if language in _GRAMMARS else None


def count_errors(language: str, code: str, filename: str = "") -> int | None:
    """Nombre d'erreurs de syntaxe (None si le langage n'est pas pris en charge)."""
    if language == "python":
        try:
            ast.parse(textwrap.dedent(code))
            return 0
        except SyntaxError:
            return 1
    grammar = _grammar_for(language, code, filename)
    if grammar is None:
        return None
    tree = _parser(grammar).parse(code.encode("utf-8"))
    if not tree.root_node.has_error:
        return 0
    errors = 0
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            errors += 1
            continue  # une erreur englobe ses enfants : on ne les recompte pas
        if node.has_error:
            stack.extend(node.children)
    return errors


def splice(file_content: str, start_line: int, end_line: int, patched: str) -> str:
    """Remplace les lignes start..end (1-indexées, incluses) du fichier par le correctif."""
    lines = file_content.split("\n")
    return "\n".join(lines[: start_line - 1] + patched.split("\n") + lines[end_line:])


def patch_is_valid(
    language: str, patched: str, *, original: str, file_content: str | None = None,
    start_line: int = 1, filename: str = "",
) -> bool | None:
    """True si le correctif n'introduit pas d'erreur de syntaxe, None si non vérifiable."""
    if file_content is not None:
        end_line = start_line + original.count("\n")
        before = count_errors(language, file_content, filename)
        after = count_errors(language, splice(file_content, start_line, end_line, patched), filename)
    else:
        before = count_errors(language, original, filename)
        after = count_errors(language, patched, filename)
    if before is None or after is None:
        return None
    return after == 0 or after <= before
