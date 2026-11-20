"""
Les trois architectures RAG du projet.

- RAG hybride  : BM25 + dense (fusion RRF) → prompt avec exemples → LLM → réparation.
- RAG rerank   : comme l'hybride, avec re-classement des candidats par un cross-encoder.
- RAG agentique: rerank + boucle d'auto-correction. Après chaque génération, la règle est
                 compilée par yara-python ; en cas d'échec, le message d'erreur exact et la
                 règle fautive sont renvoyés au LLM pour correction (3 essais au plus).
                 L'ancienne version renvoyait le même prompt sans l'erreur : le modèle
                 refaisait la même faute.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .parsing import parse_strings, sections, split_rules
from .repair import RepairResult, meta_escape, repair_rule, sanitize_name
from .retrieval import STOPWORDS, Retriever

SYSTEM = (
    "You are a malware analyst who writes YARA rules. "
    "You answer with exactly one valid YARA rule and nothing else: no explanation, no markdown."
)

RULES_OF_SYNTAX = """Syntax reminders:
- Sections in this order: meta:, strings:, condition:
- Text strings use double quotes, e.g. $s1 = "cmd.exe /c" ascii wide
- Hex strings use braces, e.g. $h1 = { 4D 5A 90 00 }
- The condition only uses strings defined in the strings section (e.g. 2 of ($s*), any of them).
- Do not copy hashes, dates or rule names from the examples; write strings for the described behaviour."""


def rule_name_from_query(query: str) -> str:
    """Nom lisible tiré des premiers mots significatifs de la requête, dans l'ordre."""
    words = [w[0].upper() + w[1:] for w in re.findall(r"[A-Za-z][A-Za-z0-9]+", query)
             if len(w) > 2 and w.lower() not in STOPWORDS][:4]
    return sanitize_name("Gen_" + "_".join(words) if words else "Generated_Rule")


def example_block(doc: dict, max_strings: int = 8) -> str:
    """Exemple court et compilable : description + quelques chaînes + condition."""
    rules = split_rules(str(doc.get("rule_body", "")))
    if not rules:
        return ""
    r = rules[0]
    _, strs, cond = sections(r.text)
    strings = parse_strings(strs)[:max_strings]
    kept = {n for n, _ in strings}
    if any(v not in kept for v in re.findall(r"\$[A-Za-z0-9_]+(?!\*)", cond)) or len(cond) > 220:
        cond = "any of them"
    desc = meta_escape(r.meta.get("description", doc.get("description", "")))[:160]
    lines = [f"rule {r.name} {{", "    meta:", f'        description = "{desc}"', "    strings:"]
    lines += [f"        {n} = {d[:140]}" for n, d in strings]
    lines += ["    condition:", f"        {cond}", "}"]
    return "\n".join(lines)


def build_messages(query: str, docs: list[dict], n_examples: int = 3) -> list[dict]:
    examples = "\n\n".join(e for e in (example_block(d) for d in docs[:n_examples]) if e)
    user = (f"Write a YARA rule that detects: {query}\n\n"
            f"Related rules from the knowledge base (use them for syntax and typical indicators):\n\n"
            f"{examples}\n\n{RULES_OF_SYNTAX}")
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]


def prefill_for(name: str) -> str:
    """Début de règle imposé au modèle : il ne peut pas partir dans une autre direction."""
    return f"rule {name} {{\n    meta:\n        description = \""


@dataclass
class Generation:
    architecture: str
    query: str
    rule: str
    valid: bool
    error: str | None
    docs: list[dict]
    latency: float
    attempts: int = 1
    fixes: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)


class YaraRAG:
    ARCHITECTURES = ("RAG Hybride", "RAG Rerank", "Agentic RAG")

    def __init__(self, retriever: Retriever, generator, k: int = 5):
        self.retriever = retriever
        self.generator = generator
        self.k = k

    def retrieve(self, query: str, architecture: str) -> list[dict]:
        if architecture == "RAG Hybride":
            hits = self.retriever.search_hybrid(query, k=self.k)
        else:
            hits = self.retriever.search_rerank(query, k=self.k)
        return self.retriever.docs(hits)

    def _generate_once(self, messages: list[dict], name: str) -> tuple[str, RepairResult]:
        raw = self.generator.complete(messages, prefill=prefill_for(name))
        return raw, repair_rule(raw, default_name=name)

    def run(self, query: str, architecture: str = "RAG Hybride", max_attempts: int = 3) -> Generation:
        t0 = time.time()
        docs = self.retrieve(query, architecture)
        name = rule_name_from_query(query)
        messages = build_messages(query, docs)
        raw, res = self._generate_once(messages, name)
        trace = [f"essai 1 : {'compile' if res.valid else 'erreur : ' + str(res.error)}"]
        attempts = 1
        if architecture == "Agentic RAG":
            while not res.valid and attempts < max_attempts:
                attempts += 1
                fix_messages = messages + [
                    {"role": "assistant", "content": res.rule or raw},
                    {"role": "user", "content": (
                        f"yara-python refuses this rule with the error:\n{res.error}\n"
                        "Fix the error and return the complete corrected rule only.")},
                ]
                raw, res = self._generate_once(fix_messages, name)
                trace.append(f"essai {attempts} : {'compile' if res.valid else 'erreur : ' + str(res.error)}")
        return Generation(architecture, query, res.rule, res.valid, res.error, docs,
                          round(time.time() - t0, 2), attempts, res.fixes, trace)
