from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tree_sitter import Language, Parser


@dataclass
class LanguageBundle:
    php: Language | None
    javascript: Language | None
    html: Language | None
    load_errors: list[str]


def load_languages() -> LanguageBundle:
    errors: list[str] = []
    php_l = js_l = html_l = None
    try:
        import tree_sitter_php as tsp

        lang_fn = getattr(tsp, "language_php", None) or getattr(tsp, "language", None)
        if lang_fn is None:
            raise AttributeError("no language function on tree_sitter_php")
        php_l = Language(lang_fn())
    except Exception as e:  # noqa: BLE001 — surface as diagnostic
        errors.append(f"tree_sitter_php: {e}")
    try:
        import tree_sitter_javascript as tsj

        js_l = Language(tsj.language())
    except Exception as e:
        errors.append(f"tree_sitter_javascript: {e}")
    try:
        import tree_sitter_html as tsh

        html_l = Language(tsh.language())
    except Exception as e:
        errors.append(f"tree_sitter_html: {e}")
    return LanguageBundle(php=php_l, javascript=js_l, html=html_l, load_errors=errors)


def make_parser(lang: Language) -> Parser:
    p = Parser()
    p.language = lang
    return p


def language_for_file(bundle: LanguageBundle, language: str) -> tuple[Language | None, Callable[[], Parser] | None]:
    if language == "php" and bundle.php:
        return bundle.php, lambda: make_parser(bundle.php)  # type: ignore[arg-type]
    if language == "javascript" and bundle.javascript:
        return bundle.javascript, lambda: make_parser(bundle.javascript)  # type: ignore[arg-type]
    if language == "html" and bundle.html:
        return bundle.html, lambda: make_parser(bundle.html)  # type: ignore[arg-type]
    return None, None
