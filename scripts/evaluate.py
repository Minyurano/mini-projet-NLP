"""
Évaluation complète sur GPU (Colab) : recherche seule, puis les 3 architectures RAG
pour un ou plusieurs LLM.

    python scripts/evaluate.py --models "TinyLlama (1.1B)" "Mistral-7B Instruct"

Écrit results/retrieval.csv, results/eval_<modele>.csv et results/summary.md.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from yara_rag.dataset import load_dataset  # noqa: E402
from yara_rag.generation import MODELS, HFGenerator  # noqa: E402
from yara_rag.metrics import evaluate, retrieval_benchmark, summary  # noqa: E402
from yara_rag.pipeline import YaraRAG  # noqa: E402
from yara_rag.retrieval import Retriever  # noqa: E402

EMBED_MODEL = "BAAI/bge-base-en-v1.5"
RERANK_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"


def make_retriever(df, dense: bool = True):
    if not dense:
        return Retriever(df)
    from sentence_transformers import CrossEncoder, SentenceTransformer
    st = SentenceTransformer(EMBED_MODEL)
    encoder = lambda texts: st.encode(list(texts), batch_size=64, convert_to_numpy=True,  # noqa: E731
                                      normalize_embeddings=True, show_progress_bar=len(texts) > 100)
    return Retriever(df, encoder=encoder, reranker=CrossEncoder(RERANK_MODEL))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data" / "yara_rules.csv"))
    ap.add_argument("--models", nargs="+", default=["TinyLlama (1.1B)"], choices=list(MODELS))
    ap.add_argument("--no-dense", action="store_true", help="BM25 seul (sans GPU ni téléchargement)")
    ap.add_argument("--out", default=str(ROOT / "results"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    df = load_dataset(args.data)
    retriever = make_retriever(df, dense=not args.no_dense)
    methods = {"BM25": retriever.search_bm25, "Hybride (RRF)": retriever.search_hybrid}
    if retriever.reranker is not None:
        methods["Rerank"] = retriever.search_rerank
    rb = retrieval_benchmark(retriever, df, methods=methods)
    rb.to_csv(out / "retrieval.csv", index=False)
    report = ["# Résultats", "", "## Recherche", "", rb.to_markdown(index=False), ""]

    for label in args.models:
        gen = HFGenerator(label)
        res = evaluate(YaraRAG(retriever, gen))
        slug = label.split()[0].lower()
        res.to_csv(out / f"eval_{slug}.csv", index=False)
        report += [f"## Génération : {label}", "", summary(res).to_markdown(), ""]
        gen.unload()
    (out / "summary.md").write_text("\n".join(report), encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
