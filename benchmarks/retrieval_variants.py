"""
Choix du texte indexé par BM25 (mesuré sans GPU).

    python benchmarks/retrieval_variants.py [--data data/yara_rules.csv]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rank_bm25 import BM25Okapi  # noqa: E402

from yara_rag.dataset import load_dataset, string_literals  # noqa: E402
from yara_rag.metrics import retrieval_benchmark  # noqa: E402
from yara_rag.retrieval import STOPWORDS, Hit, tokenize  # noqa: E402


def bm25_search(texts, tok):
    index = BM25Okapi([tok(t) for t in texts])

    def search(q, k=5):
        s = index.get_scores(tok(q))
        return [Hit(int(i), float(s[i])) for i in np.argsort(-s)[:k]]
    return search


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data" / "yara_rules.csv"))
    args = ap.parse_args()
    df = load_dataset(args.data)
    simple = lambda t: [w for w in re.findall(r"[a-z0-9]+", t.lower()) if w not in STOPWORDS and len(w) > 1]  # noqa: E731
    lits = df["rule_body"].map(string_literals)
    variants = {
        "notebook d'origine : description, split()": bm25_search(df.embed_text, lambda t: t.lower().split()),
        "description, mots simples": bm25_search(df.embed_text, simple),
        "description + tags + chaînes, CamelCase": bm25_search(df.embed_text + " " + df.tags + " " + lits, tokenize),
        "retenu : description x2 + tags + chaînes": bm25_search(df.search_text, tokenize),
    }
    print(retrieval_benchmark(None, df, methods=variants).to_string(index=False))


if __name__ == "__main__":
    main()
