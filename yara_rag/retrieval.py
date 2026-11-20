"""
Recherche des règles les plus proches d'une description (partie « R » du RAG).

- BM25 (mots-clés) sur le texte de recherche : nom, type, description, tags et
  chaînes de la règle (noms d'API, commandes, chemins). Tokenisation adaptée :
  « GetAsyncKeyState » donne aussi « get », « async », « key », « state ».
- Recherche dense (sens général) avec un modèle d'embeddings et FAISS, si disponible.
- Fusion des deux classements par Reciprocal Rank Fusion (RRF), insensible aux
  échelles de scores (l'ancienne fusion divisait des scores de natures différentes).
- Re-classement facultatif par un cross-encoder.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Sequence

import numpy as np
import pandas as pd

STOPWORDS = set("""a an the and or of to in on for with by from that this these those is are be been
using use uses used which who what when where how detect detects detection identify find rule rules
yara file files le la les un une des du de et ou pour avec par qui que dans sur est""".split())

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def tokenize(text: str) -> list[str]:
    """Mots en minuscules + morceaux des identifiants (CamelCase, snake_case, chemins)."""
    out = []
    for tok in re.findall(r"[A-Za-z0-9_.\\/-]+", str(text)):
        parts = [p for p in re.split(r"[_.\\/-]+", tok) if p]
        pieces = {tok.lower()}
        for p in parts:
            pieces.add(p.lower())
            pieces.update(x.lower() for x in _CAMEL.split(p) if x)
        out += sorted(p for p in pieces if len(p) > 1 and p not in STOPWORDS)   # ordre stable
    return out


@dataclass
class Hit:
    index: int
    score: float
    dense: float | None = None
    sparse: float | None = None
    rerank: float | None = None


class Retriever:
    """Index BM25 + dense (facultatif) sur un DataFrame produit par ``load_dataset``."""

    def __init__(self, df: pd.DataFrame, encoder: Callable[[Sequence[str]], np.ndarray] | None = None,
                 doc_embeddings: np.ndarray | None = None, reranker=None):
        from rank_bm25 import BM25Okapi
        self.df = df.reset_index(drop=True)
        self.bm25 = BM25Okapi([tokenize(t) for t in self.df["search_text"]])
        self.encoder = encoder
        self.reranker = reranker
        self.index = None
        if encoder is not None:
            emb = doc_embeddings if doc_embeddings is not None else encoder(list(self.df["embed_text"]))
            emb = np.asarray(emb, dtype="float32")
            emb /= np.linalg.norm(emb, axis=1, keepdims=True) + 1e-10
            self.emb = emb
            try:
                import faiss
                self.index = faiss.IndexFlatIP(emb.shape[1])
                self.index.add(emb)
            except ImportError:                # sans FAISS : produit scalaire numpy
                self.index = None

    # -------------------------------------------------------------- classements
    def sparse_ranking(self, query: str, n: int) -> list[tuple[int, float]]:
        scores = self.bm25.get_scores(tokenize(query))
        top = np.argsort(-scores, kind="stable")[:n]          # à égalité : ordre de la base
        return [(int(i), float(scores[i])) for i in top if scores[i] > 0]

    def dense_ranking(self, query: str, n: int) -> list[tuple[int, float]]:
        if self.encoder is None:
            return []
        q = np.asarray(self.encoder([query]), dtype="float32")
        q /= np.linalg.norm(q, axis=1, keepdims=True) + 1e-10
        if self.index is not None:
            scores, idx = self.index.search(q, n)
            return [(int(i), float(s)) for i, s in zip(idx[0], scores[0]) if i >= 0]
        sims = self.emb @ q[0]
        top = np.argsort(-sims)[:n]
        return [(int(i), float(sims[i])) for i in top]

    # -------------------------------------------------------------- recherches
    def search_bm25(self, query: str, k: int = 5) -> list[Hit]:
        return [Hit(i, s, sparse=s) for i, s in self.sparse_ranking(query, k)]

    def search_hybrid(self, query: str, k: int = 5, pool: int = 50, rrf_k: int = 60) -> list[Hit]:
        """Fusion RRF : score = Σ 1 / (rrf_k + rang) sur les deux classements."""
        sparse = self.sparse_ranking(query, pool)
        dense = self.dense_ranking(query, pool)
        fused: dict[int, Hit] = {}
        for ranking, attr in ((sparse, "sparse"), (dense, "dense")):
            for rank, (i, s) in enumerate(ranking):
                h = fused.setdefault(i, Hit(i, 0.0))
                h.score += 1.0 / (rrf_k + rank + 1)
                setattr(h, attr, s)
        return sorted(fused.values(), key=lambda h: -h.score)[:k]

    def search_rerank(self, query: str, k: int = 5, candidates: int = 20) -> list[Hit]:
        hits = self.search_hybrid(query, k=candidates)
        if self.reranker is None or not hits:
            return hits[:k]
        pairs = [[query, self.df.at[h.index, "embed_text"]] for h in hits]
        for h, s in zip(hits, self.reranker.predict(pairs)):
            h.rerank = float(s)
        return sorted(hits, key=lambda h: -h.rerank)[:k]

    def docs(self, hits: list[Hit]) -> list[dict]:
        out = []
        for h in hits:
            d = self.df.iloc[h.index].to_dict()
            d.update(retrieval_score=round(h.score, 4), dense_score=h.dense, sparse_score=h.sparse,
                     rerank_score=h.rerank)
            out.append(d)
        return out
