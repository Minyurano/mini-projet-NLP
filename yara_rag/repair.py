"""
Remise en forme et réparation des règles produites par le LLM.

Principe : on ne « devine » pas la règle à coups de remplacements globaux (l'ancien
post-traitement cassait des règles correctes). On :
  1. recolle le début de règle imposé dans le prompt (préremplissage) et la suite générée ;
  2. isole la première règle complète (accolades équilibrées, chaînes respectées) ;
  3. corrige seulement des défauts précis et fréquents des petits LLM ;
  4. compile avec yara-python ; si une ligne de « strings » est fautive, elle est retirée
     et la condition mise à jour, puis on recompile (quelques tours au plus).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parsing import (EXTERNALS, IMPORT_RE, NAME_RE, RESERVED, compile_error, find_rule_end, needed_imports,
                      parse_strings, sections)

FENCE_RE = re.compile(r"```[a-zA-Z]*")


def sanitize_name(name: str, default: str = "Generated_Rule") -> str:
    """Nom de règle YARA valide : lettres, chiffres, _, ne commence pas par un chiffre, ≤ 128."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", name or "").strip("_")
    name = re.sub(r"_+", "_", name)
    if not name:
        name = default
    if name[0].isdigit():
        name = "Rule_" + name
    if name.lower() in RESERVED:
        name = "Rule_" + name
    return name[:128]


def meta_escape(value: str) -> str:
    """Valeur utilisable entre guillemets dans la section meta."""
    value = re.sub(r"\s+", " ", str(value)).strip()
    return value.replace("\\", "\\\\").replace('"', '\\"')


@dataclass
class RepairResult:
    rule: str
    valid: bool
    error: str | None
    fixes: list[str] = field(default_factory=list)


def extract_rule(text: str) -> str | None:
    """Première règle complète trouvée dans un texte libre (prose, markdown…)."""
    text = FENCE_RE.sub("", text or "")
    m = re.search(r"(?:(?:private|global)\s+)*rule\s+[^\s{]+[^{\n]*\s*\{", text)
    if not m:
        return None
    end = find_rule_end(text, text.index("{", m.start()))
    return text[m.start():end + 1] if end > 0 else text[m.start():]


def _close_braces(rule: str) -> str:
    """Ferme les chaînes hexadécimales et la règle si la génération a été coupée."""
    o = rule.find("{")
    if o >= 0 and find_rule_end(rule, o) < 0:
        meta, strs, cond = sections(rule)
        rule = rule.rstrip()
        if not cond:
            rule += "\n    condition:\n        any of them"
        rule += "\n}"
    return rule


def _rebuild(name: str, tags: str, meta: str, strings: list[tuple[str, str]], cond: str) -> str:
    lines = [f"rule {name}{(' : ' + tags) if tags else ''} {{"]
    if meta.strip():
        lines += ["    meta:"] + [f"        {l.strip()}" for l in meta.strip().splitlines() if l.strip()]
    if strings:
        lines += ["    strings:"] + [f"        {n} = {d}" for n, d in strings]
    lines += ["    condition:", f"        {cond.strip() or ('any of them' if strings else 'false')}"]
    return "\n".join(lines) + "\n}"


def _fix_meta(meta: str) -> tuple[str, bool]:
    """Garde les lignes « clé = valeur » valides, met les valeurs libres entre guillemets."""
    out, changed = [], False
    for line in meta.splitlines():
        line = line.strip().rstrip(",;")
        if not line:
            continue
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.*)$', line)
        if not m:
            changed = True
            continue
        key, val = m.groups()
        if re.fullmatch(r'"(?:\\.|[^"\\])*"|-?\d+|true|false', val):
            out.append(f"{key} = {val}")
            continue
        changed = True
        out.append(f'{key} = "{meta_escape(val.strip(chr(34) + chr(39)))}"')
    return "\n".join(dict.fromkeys(out)), changed


def _fix_strings(strings: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[str]]:
    """Corrige les définitions de chaînes les plus souvent mal écrites."""
    out, fixes, seen_names, seen_vals = [], [], set(), set()
    for name, d in strings:
        d = d.strip().rstrip(",;")
        if d.startswith("{") and "}" not in d:                       # hex non fermée
            d += " }"
            fixes.append(f"{name}: chaîne hexadécimale fermée")
        if d.startswith("{"):                                        # commentaires dans l'hex
            d = re.sub(r"//[^\n}]*", "", d)
            d = re.sub(r"\s+", " ", d)
        if d.startswith("'") and d.count("'") >= 2:                   # 'texte' -> "texte"
            d = '"' + d[1:d.rindex("'")].replace('"', '\\"') + '"' + d[d.rindex("'") + 1:]
            fixes.append(f"{name}: guillemets simples remplacés")
        if not d or d[0] not in '"{/':                                # texte nu -> chaîne
            d = f'"{meta_escape(d)}"'
            fixes.append(f"{name}: valeur mise entre guillemets")
        if name == "$" or name in seen_names:                        # noms vides ou en double
            base = name if name != "$" else "$s"
            k = 2
            while f"{base}_{k}" in seen_names:                        # même préfixe : $a* reste valable
                k += 1
            fixes.append(f"{name}: renommée en {base}_{k}")
            name = f"{base}_{k}"
        core = d.split('"')[1] if d.startswith('"') and d.count('"') >= 2 else d
        if core in seen_vals:                                        # valeurs en double
            fixes.append(f"{name}: doublon supprimé")
            continue
        seen_names.add(name)
        seen_vals.add(core)
        out.append((name, d))
    return out, fixes


def _fix_condition(cond: str, names: list[str]) -> tuple[str, list[str]]:
    """Retire de la condition les variables qui n'existent pas ; condition vide -> any of them."""
    fixes = []
    if re.search(r"&&|\|\||(?<![<>=!])!(?=\s*[$(])", cond):
        cond = cond.replace("&&", " and ").replace("||", " or ")
        cond = re.sub(r"(?<![<>=!])!(?=\s*[$(])", " not ", cond)      # !$a -> not $a (!a = longueur)
        fixes.append("condition : opérateurs &&, ||, ! traduits en and, or, not")
    lowered = [n.lower() for n in names]

    def exists(ref: str) -> bool:
        ref = ref.lower()
        if ref.endswith("*"):
            return any(n.startswith(ref[:-1]) for n in lowered)
        return ref in lowered

    # « N of ($a, $b*) » : on garde les éléments existants, sinon on retire l'expression
    def fix_set(m):
        items = [x.strip() for x in m.group(2).split(",")]
        keep = [x for x in items if exists(x)]
        if len(keep) != len(items):
            fixes.append("condition : ensemble de chaînes corrigé")
        return f"{m.group(1)} of ({', '.join(keep)})" if keep else ""
    cond = re.sub(r"(\b\d+|\bany|\ball|\bnone)\s+of\s+\(\s*(\$[^)]*)\)", fix_set, cond)

    undefined = sorted({v for v in re.findall(r"[$#@!]([A-Za-z0-9_]+\*?)", cond) if not exists("$" + v)})
    for var in undefined:
        v = re.escape(var.rstrip("*")) + (r"\*" if var.endswith("*") else r"(?![A-Za-z0-9_*])")
        cond = re.sub(rf"[#@!]{v}(\[[^\]]*\])?\s*(==|!=|>=|<=|>|<)\s*[\w.()]+", "", cond)  # #a > 2
        cond = re.sub(rf"\${v}\s+at\s+[\w.()+\-*]+", "", cond)                              # $a at 0
        cond = re.sub(rf"\${v}\s+in\s*\([^)]*\)", "", cond)                                  # $a in (0..10)
        cond = re.sub(rf"[$#@!]{v}(\[[^\]]*\])?", "", cond)
        fixes.append(f"condition : ${var} inexistante retirée")
    # nettoyage des opérateurs orphelins laissés par les suppressions
    for _ in range(3):
        cond = re.sub(r"\(\s*(and|or)\s*", "(", cond)
        cond = re.sub(r"\s*(and|or)\s*\)", ")", cond)
        cond = re.sub(r"\b(and|or)\s+(and|or)\b", r"\1", cond)
        cond = re.sub(r"^\s*(and|or)\b|\b(and|or)\s*$", "", cond.strip())
        cond = re.sub(r"(?<![A-Za-z0-9_])\(\s*\)", "", cond)        # () vide, pas pe.is_dll()
    cond = re.sub(r"\s+", " ", cond).strip()
    if not cond or not re.search(r"[A-Za-z0-9$#@!]", cond):
        cond = "any of them" if names else "false"
        fixes.append("condition vide remplacée")
    return cond, fixes


def repair_rule(text: str, default_name: str = "Generated_Rule", max_rounds: int = 4) -> RepairResult:
    """Extrait, corrige et valide une règle YARA générée."""
    fixes: list[str] = []
    rule = extract_rule(text)
    if rule is None:
        return RepairResult(text or "", False, "aucune règle trouvée dans la sortie du modèle", fixes)
    rule = _close_braces(rule)

    head = re.match(r"\s*(?:(?:private|global)\s+)*rule\s+([^\s:{]+)\s*(?::\s*([^{]*))?\{", rule)
    raw_name = head.group(1) if head else default_name
    name = sanitize_name(raw_name, default_name)
    if name != raw_name:
        fixes.append(f"nom « {raw_name} » corrigé en « {name} »")
    tags = " ".join(sanitize_name(t) for t in (head.group(2) or "").split()) if head else ""

    # Commentaire « // » dans une chaîne hexadécimale : il masquerait l'accolade fermante
    rule = re.sub(r"(?m)^(\s*\$[A-Za-z0-9_]*\s*=\s*\{[^}\n]*?)//[^}\n]*", r"\1", rule)
    rule = _close_braces(rule)
    # Sections : « meta {…} » / « strings = » sont ramenés à la forme « meta: »
    rule = re.sub(r"(?m)^(\s*)(meta|strings|condition)\s*(?:\{|=)\s*$", r"\1\2:", rule)
    meta, strs, cond = sections(rule)
    meta, meta_changed = _fix_meta(meta)
    if meta_changed:
        fixes.append("section meta remise en forme")
    strings, f2 = _fix_strings(parse_strings(strs))
    fixes += f2
    if cond.count("}") > cond.count("{"):                            # accolade de fin capturée
        cond = cond[:cond.rindex("}")]
    cond, f3 = _fix_condition(cond, [n for n, _ in strings])
    fixes += f3
    rule = _rebuild(name, tags, meta, strings, cond)

    imports = needed_imports(rule)
    prefix = "".join(f'import "{m}"\n' for m in imports)
    for _ in range(max_rounds):
        err = compile_error(prefix + rule, EXTERNALS)
        if err is None:
            return RepairResult(prefix + rule, True, None, fixes)
        # Erreur sur une ligne de « strings » : on retire cette chaîne et on recommence
        m = re.search(r"line (\d+)", err)
        bad = None
        if m:
            lineno = int(m.group(1)) - len(imports)
            lines = rule.splitlines()
            if 0 < lineno <= len(lines):
                bad = re.match(r"\s*(\$[A-Za-z0-9_]*)\s*=", lines[lineno - 1])
        if not bad:
            sm = re.search(r'string "(\$[A-Za-z0-9_]*)"', err)
            bad = sm
        if not bad or not strings:
            return RepairResult(prefix + rule, False, err, fixes)
        victim = bad.group(1)
        strings = [(n, d) for n, d in strings if n != victim]
        fixes.append(f"{victim} retirée (erreur de compilation : {err.split(':')[-1].strip()[:60]})")
        cond, f3 = _fix_condition(cond, [n for n, _ in strings])
        rule = _rebuild(name, tags, meta, strings, cond)
    err = compile_error(prefix + rule, EXTERNALS)
    return RepairResult(prefix + rule, err is None, err, fixes)
