"""
Règle « extractive », sans LLM : assemblée à partir des chaînes des règles retrouvées.

Sert de référence (baseline) et de moteur à la démo web (GitHub Pages), où aucun LLM
ne peut tourner. Les chaînes viennent de règles qui compilent ; la condition n'utilise
que « N of them » : la règle obtenue compile donc toujours (vérifié par les tests).
La même logique est réécrite en JavaScript dans docs/index.html.
"""
from __future__ import annotations

import datetime as dt
import re

from .parsing import parse_strings, sections, split_rules
from .pipeline import rule_name_from_query
from .repair import meta_escape
from .retrieval import tokenize

MAX_STRINGS = 8
MAX_CANDIDATES = 10            # chaînes gardées par règle (mêmes limites que la démo web)
MZ_CHECK = re.compile(r"uint16\(0\)\s*==\s*0x5a4d", re.IGNORECASE)


def candidate_strings(doc: dict) -> list[tuple[str, str]]:
    """Chaînes réutilisables d'une règle : on écarte celles qui dépendent d'autres règles."""
    rules = split_rules(str(doc.get("rule_body", "")))
    if not rules:
        return []
    _, strs, _ = sections(rules[0].text)
    out = []
    for name, d in parse_strings(strs):
        d = re.sub(r"\s+", " ", d).strip()
        if len(d) > 160 or "private" in d:
            continue
        out.append((name, d))
    return out[:MAX_CANDIDATES]


def string_score(definition: str, query_terms: set[str]) -> int:
    toks = set(tokenize(definition))
    return len(toks & query_terms)


WEB_FIELDS = ["name", "type", "description", "author", "url", "tags", "literals", "strings", "mz"]


def web_payload(df) -> dict:
    """Base de règles au format de la démo web (docs/data/rules.json)."""
    from .dataset import string_literals
    rows = [[d["rule_name"], d["type"], d["description"], str(d.get("author", ""))[:60], d["source_url"],
             d["tags"], string_literals(d["rule_body"]), [s for _, s in candidate_strings(d)],
             int(bool(MZ_CHECK.search(d["rule_body"])))] for d in df.to_dict("records")]
    return {"fields": WEB_FIELDS, "count": len(rows), "rules": rows}


def assemble_rule(query: str, docs: list[dict], max_strings: int = MAX_STRINGS, today: str | None = None) -> dict:
    """Assemble une règle : chaînes les plus liées à la requête, prises dans les règles retrouvées."""
    terms = set(tokenize(query))
    pool, seen = [], set()
    for rank, d in enumerate(docs):
        for _, definition in candidate_strings(d):
            lit = re.match(r'"(?:\\.|[^"\\])*"', definition)
            key = lit.group(0) if lit else definition.split(" ")[0] if definition.startswith("/") else definition
            if key in seen:
                continue
            seen.add(key)
            pool.append((string_score(definition, terms), -rank, definition, d.get("rule_name", "")))
    pool.sort(key=lambda t: (-t[0], -t[1]))
    chosen = pool[:max_strings]
    name = rule_name_from_query(query)
    mz = sum(bool(MZ_CHECK.search(str(d.get("rule_body", "")))) for d in docs) > len(docs) / 2
    n = len(chosen)
    need = 1 if n <= 2 else 2 if n <= 5 else 3
    cond = (f"{need} of them" if n else "false")
    if mz and n:
        cond = f"uint16(0) == 0x5A4D and {cond}"
    ref = docs[0].get("source_url", "") if docs else ""
    lines = [f"rule {name} {{", "    meta:",
             f'        description = "{meta_escape(query[:200])}"',
             '        author = "yara-rag (assemblage extractif)"',
             f'        date = "{today or dt.date.today().isoformat()}"']
    if ref:
        lines.append(f'        reference = "{meta_escape(ref)}"')
    if chosen:
        lines.append("    strings:")
        lines += [f"        $s{i} = {c[2]}" for i, c in enumerate(chosen, 1)]
    lines += ["    condition:", f"        {cond}", "}"]
    return {"rule": "\n".join(lines), "sources": [c[3] for c in chosen]}
