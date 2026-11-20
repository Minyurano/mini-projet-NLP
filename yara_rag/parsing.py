"""
Lecture des règles YARA : découpage d'un fichier en règles, extraction des sections,
compilation avec yara-python.

Le découpage suit la grammaire YARA (chaînes "…", expressions régulières /…/,
chaînes hexadécimales {…}, commentaires // et /* */) au lieu d'expressions régulières
naïves, qui se trompent dès qu'une accolade apparaît dans une chaîne.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

RULE_HEAD = re.compile(
    r"^[ \t]*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([A-Za-z0-9_ \t]+?))?\s*\{",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r'^\s*import\s+"([a-z0-9_]+)"', re.MULTILINE)
# Variables externes de certaines règles (signature-base, THOR) : déclarées pour compiler
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
KNOWN_MODULES = ("pe", "elf", "math", "hash", "dotnet", "magic", "time", "console", "string", "cuckoo")
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
# Mots réservés de YARA : interdits comme nom de règle
RESERVED = {
    "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition", "contains", "endswith",
    "entrypoint", "false", "filesize", "for", "fullword", "global", "import", "icontains", "iendswith",
    "iequals", "in", "include", "int16", "int16be", "int32", "int32be", "int8", "int8be", "istartswith",
    "matches", "meta", "nocase", "none", "not", "of", "or", "private", "rule", "startswith", "strings",
    "them", "true", "uint16", "uint16be", "uint32", "uint32be", "uint8", "uint8be", "wide", "xor",
    "defined",
}


def strip_comments(text: str) -> str:
    """Supprime les commentaires // et /* */ sans toucher aux chaînes ni aux regex."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def find_rule_end(text: str, open_brace: int) -> int:
    """Position de l'accolade qui ferme la règle ouverte en ``open_brace`` (-1 si absente).

    Ignore les accolades contenues dans les chaînes "…", les commentaires et les
    chaînes hexadécimales { … } de la section strings.
    """
    depth, i, n = 0, open_brace, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"' and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


@dataclass
class Rule:
    name: str
    tags: list[str]
    text: str                       # règle complète, de « rule » à « } »
    imports: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    strings: list[tuple[str, str]] = field(default_factory=list)   # ($nom, définition)
    condition: str = ""

    def source(self) -> str:
        """Texte compilable : imports nécessaires + règle."""
        head = "".join(f'import "{m}"\n' for m in self.imports)
        return head + self.text


def mask_literals(text: str) -> str:
    """Copie du texte où le contenu des chaînes "…", regex /…/ et hex {…} est masqué
    (même longueur) : les recherches de mots-clés ne tombent plus dans les chaînes."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = "x"
            i = j + 1
        elif c == "/" and re.search(r"=\s*$", text[max(0, i - 20):i]):        # $r = /regex/
            j = i + 1
            while j < n and text[j] != "/" and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = "x"
            i = j + 1
        else:
            i += 1
    return "".join(out)


def sections(rule_text: str) -> tuple[str, str, str]:
    """Contenu brut des sections meta, strings et condition d'une règle (une ou plusieurs lignes)."""
    body = strip_comments(rule_text)
    o = body.find("{")
    end = find_rule_end(body, o) if o >= 0 else -1
    inner = body[o + 1:end] if o >= 0 and end > o else body[o + 1:] if o >= 0 else body
    masked = mask_literals(inner)
    marks = {}
    for k in ("meta", "strings", "condition"):
        m = re.search(rf"(?<![A-Za-z0-9_$]){k}\s*:", masked)
        if m:
            marks[k] = (m.start(), m.end())
    order = sorted(marks.items(), key=lambda kv: kv[1][0])
    out = {}
    for idx, (k, (start, after)) in enumerate(order):
        stop = order[idx + 1][1][0] if idx + 1 < len(order) else len(inner)
        out[k] = inner[after:stop]
    return out.get("meta", "").strip(), out.get("strings", "").strip(), out.get("condition", "").strip()


def parse_meta(meta_text: str) -> dict[str, str]:
    meta = {}
    for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:\\.|[^"\\])*"|-?\d+|true|false)', meta_text):
        v = m.group(2)
        meta.setdefault(m.group(1), v[1:-1] if v.startswith('"') else v)
    return meta


def parse_strings(strings_text: str) -> list[tuple[str, str]]:
    """Définitions de chaînes « $nom = … » (hex multi-lignes et règles sur une ligne compris)."""
    masked = mask_literals(strings_text)
    starts = list(re.finditer(r"(?<![A-Za-z0-9_])(\$[A-Za-z0-9_]*)\s*=", masked))
    out = []
    for k, m in enumerate(starts):
        stop = starts[k + 1].start() if k + 1 < len(starts) else len(strings_text)
        out.append((m.group(1), strings_text[m.end():stop].strip()))
    return out


def split_rules(text: str) -> list[Rule]:
    """Découpe le contenu d'un fichier .yar en règles individuelles."""
    imports = sorted(set(IMPORT_RE.findall(text)))
    rules, pos = [], 0
    clean = text
    for m in RULE_HEAD.finditer(clean):
        if m.start() < pos:
            continue
        o = clean.find("{", m.start())
        end = find_rule_end(clean, o)
        if end < 0:
            break
        rule_text = clean[m.start():end + 1].strip()
        pos = end + 1
        meta_t, str_t, cond_t = sections(rule_text)
        tags = (m.group(2) or "").split()
        rules.append(Rule(name=m.group(1), tags=tags, text=rule_text,
                          imports=[i for i in imports if re.search(rf"\b{i}\.", rule_text)],
                          meta=parse_meta(meta_t), strings=parse_strings(str_t), condition=cond_t))
    return rules


def needed_imports(rule_text: str) -> list[str]:
    """Modules utilisés par la règle (pe.xxx, math.xxx…)."""
    body = strip_comments(rule_text)
    return [m for m in KNOWN_MODULES if re.search(rf"\b{m}\.[a-z_]", body)]


def compile_error(source: str, externals: dict | None = None) -> str | None:
    """None si la règle compile, sinon le message d'erreur de yara-python."""
    import yara
    try:
        yara.compile(source=source, externals=externals or {})
        return None
    except yara.SyntaxError as exc:
        return str(exc)
    except yara.Error as exc:            # erreurs internes, modules absents…
        return str(exc)


def is_valid_yara(rule_text: str) -> bool:
    """Vrai si la règle compile (avec les imports de modules qu'elle utilise)."""
    if not rule_text or "rule" not in rule_text:
        return False
    src = rule_text
    if not IMPORT_RE.search(src):
        src = "".join(f'import "{m}"\n' for m in needed_imports(src)) + src
    return compile_error(src, EXTERNALS) is None
