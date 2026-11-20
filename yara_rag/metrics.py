"""
Mesures d'évaluation.

Les anciennes métriques mesuraient mal ce qu'elles annonçaient :
- « Pertinence retrieval » ne regardait pas la requête (seulement la longueur des descriptions) ;
- « Hallucination » vérifiait seulement la présence des sections meta/strings/condition ;
- « Similarité » comparait le code d'une règle à des descriptions en langage naturel.

Mesures retenues ici :
- syntax_valid      : la règle compile avec yara-python (critère indispensable) ;
- type_precision@k  : part des règles retrouvées du bon type de malware (requêtes étiquetées) ;
- query_coverage    : part des mots-clés techniques de la requête présents dans les chaînes ;
- grounding         : part des chaînes générées présentes dans les règles retrouvées
                      (ancrage dans la base ; 100 % peut aussi signifier « simple copie ») ;
- copy              : toutes les chaînes générées viennent d'une seule règle retrouvée (copie) ;
- n_strings, latency.
"""
from __future__ import annotations

import re
from statistics import mean

import pandas as pd

from .parsing import parse_strings, sections
from .retrieval import tokenize

# Requêtes de test étiquetées (type attendu), en anglais comme la base de règles
TEST_QUERIES = [
    ("Detect ransomware encrypting files with AES and requesting a Bitcoin ransom", "ransomware"),
    ("Ransomware that deletes shadow copies with vssadmin and drops a ransom note", "ransomware"),
    ("Identify a keylogger capturing keystrokes with GetAsyncKeyState", "keylogger"),
    ("Find a rootkit hiding processes by hooking the SSDT", "rootkit"),
    ("Detect a backdoor opening a reverse shell on port 4444 with cmd.exe", "backdoor"),
    ("Identify a cryptominer using CPU resources to mine Monero with xmrig", "cryptominer"),
    ("PHP webshell executing commands sent through eval and base64_decode", "webshell"),
    ("ASPX webshell running cmd.exe from an HTTP request", "webshell"),
    ("Remote access trojan with keylogging, screen capture and C2 over TCP", "rat"),
    ("Credential stealer collecting browser passwords and cookies", "infostealer"),
    ("Mimikatz dumping credentials from lsass memory", "hacktool"),
    ("Cobalt Strike beacon payload", "hacktool"),
    ("Downloader that fetches a second stage payload with URLDownloadToFile", "loader"),
    ("Exploit for CVE-2017-11882 in Microsoft Office equation editor", "exploit"),
    ("Banking trojan injecting into browsers to steal online banking credentials", "banker"),
]


def string_values(rule: str) -> list[str]:
    _, strs, _ = sections(rule)
    vals = []
    for _, d in parse_strings(strs):
        m = re.match(r'"((?:\\.|[^"\\])*)"', d)
        vals.append(m.group(1) if m else re.sub(r"\s+", " ", d.split("}")[0] + "}") if d.startswith("{") else d)
    return vals


def query_coverage(rule: str, query: str) -> float:
    """Part des termes techniques de la requête (API, outils, extensions…) retrouvés dans la règle."""
    terms = {t for t in tokenize(query) if len(t) > 3 and not t.isdigit()}
    technical = {t for t in terms if re.search(r"[a-z]\d|\d[a-z]|\.|exe|dll|api|key|shell|xmr|lsass|base64|eval|cmd", t)
                 or t in {"bitcoin", "monero", "vssadmin", "mimikatz", "cobalt", "strike", "getasynckeystate",
                          "urldownloadtofile", "ssdt", "aes", "eval", "cookies", "passwords"}}
    terms = technical or terms
    if not terms:
        return 0.0
    body = rule.lower()
    return sum(1 for t in terms if t in body) / len(terms)


def grounding(rule: str, docs: list[dict]) -> tuple[float, bool]:
    vals = [v for v in string_values(rule) if len(v) >= 3]
    if not vals:
        return 0.0, False
    corpus = [set(string_values(str(d.get("rule_body", "")))) for d in docs]
    joined = " ".join(str(d.get("rule_body", "")) for d in docs)
    grounded = sum(1 for v in vals if v in joined) / len(vals)
    copy = any(c and set(vals) <= c for c in corpus)
    return grounded, copy


def type_precision(docs: list[dict], expected: str | None) -> float | None:
    if not expected or not docs:
        return None
    return sum(1 for d in docs if str(d.get("type", "")) == expected) / len(docs)


def evaluate(rag, queries=TEST_QUERIES, architectures=None, log=print) -> pd.DataFrame:
    rows = []
    for arch in architectures or rag.ARCHITECTURES:
        for query, expected in queries:
            g = rag.run(query, arch)
            grounded, copy = grounding(g.rule, g.docs)
            rows.append({
                "architecture": arch, "query": query, "expected_type": expected,
                "syntax_valid": g.valid, "attempts": g.attempts,
                "type_precision@k": type_precision(g.docs, expected),
                "query_coverage": round(query_coverage(g.rule, query), 3),
                "grounding": round(grounded, 3), "copy": copy,
                "n_strings": len(string_values(g.rule)), "latency_s": g.latency, "rule": g.rule,
            })
            log(f"[{arch}] {'OK ' if g.valid else 'ERR'} {g.latency:5.1f}s  {query[:60]}")
    return pd.DataFrame(rows)


def summary(results: pd.DataFrame) -> pd.DataFrame:
    cols = ["syntax_valid", "type_precision@k", "query_coverage", "grounding", "copy", "n_strings",
            "attempts", "latency_s"]
    s = results.groupby("architecture")[cols].mean(numeric_only=False).astype(float).round(3)
    return s


def retrieval_benchmark(retriever, df: pd.DataFrame, queries=TEST_QUERIES, k: int = 5, n_loo: int = 500,
                        seed: int = 0, methods=None) -> pd.DataFrame:
    """Qualité de la recherche seule (sans LLM).

    1. Requêtes étiquetées : part des k règles retrouvées du type attendu.
    2. « Leave-one-out » : la description d'une règle sert de requête ; on mesure si les
       k autres règles retrouvées ont le même type (la règle elle-même est exclue).
    """
    import numpy as np
    methods = methods or {"BM25": retriever.search_bm25, "Hybride (RRF)": retriever.search_hybrid}
    rng = np.random.default_rng(seed)
    cand = df.index[(df["description"].str.len() > 30) & (df["type"] != "malware")].to_numpy()
    sample = rng.choice(cand, size=min(n_loo, len(cand)), replace=False)
    rows = []
    for mname, fn in methods.items():
        p_q = mean(sum(df.at[h.index, "type"] == t for h in fn(q, k=k)) / k for q, t in queries)
        loo = []
        for i in sample:
            hits = [h for h in fn(df.at[i, "description"], k=k + 1) if h.index != i][:k]
            loo.append(sum(df.at[h.index, "type"] == df.at[i, "type"] for h in hits) / k if hits else 0)
        rows.append({"méthode": mname, f"précision type@{k} (requêtes)": round(p_q, 3),
                     f"précision type@{k} (leave-one-out)": round(float(np.mean(loo)), 3)})
    return pd.DataFrame(rows)
