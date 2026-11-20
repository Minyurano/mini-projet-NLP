"""
Fiabilité du post-traitement : ancien notebook contre nouveau module de réparation.

On prend de vraies règles de la base, on leur applique les défauts typiques des
sorties de petits LLM (benchmarks/corruptions.py), puis on mesure la part de règles
qui compilent après chaque post-traitement. On mesure aussi le cas « sortie parfaite » :
le LLM renvoie exactement la suite attendue du début de règle imposé dans le prompt.

    python benchmarks/repair_benchmark.py [--data data/yara_rules.csv] [--n 500]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "benchmarks"))
import pandas as pd  # noqa: E402
from corruptions import CORRUPTIONS  # noqa: E402
from legacy_postprocess import clean_rule_output, legacy_postprocess  # noqa: E402

from yara_rag.parsing import is_valid_yara, sections, split_rules  # noqa: E402
from yara_rag.pipeline import prefill_for  # noqa: E402
from yara_rag.repair import repair_rule  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data" / "yara_rules.csv"))
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--out", default=str(ROOT / "docs" / "results" / "repair_benchmark.json"))
    args = ap.parse_args()
    df = pd.read_csv(args.data, dtype=str).fillna("")
    rng = random.Random(0)
    idx = [i for i in rng.sample(range(len(df)), min(len(df), 3 * args.n)) if not df.imports[i]][: args.n]

    # 1. Sortie parfaite du LLM (suite exacte du préremplissage)
    old_ok = new_ok = 0
    for i in idx:
        r = split_rules(df.rule_body[i])[0]
        _, strs, cond = sections(r.text)
        desc = (r.meta.get("description") or "x").replace('"', "")
        pre = prefill_for(r.name)
        suite = f'{desc}"\n    strings:\n        {strs}\n    condition:\n        {cond}\n}}'
        old_ok += is_valid_yara(clean_rule_output(legacy_postprocess(suite)))   # l'ancien code ne recollait pas
        new_ok += repair_rule(pre + suite).valid
    rows = {"sortie parfaite du LLM": [len(idx), None, old_ok, new_ok]}

    # 2. Défauts typiques
    for cname, fn in CORRUPTIONS.items():
        n = raw = old = new = 0
        for i in idx:
            bad = fn(df.rule_body[i], rng)
            if bad == df.rule_body[i]:
                continue
            n += 1
            raw += is_valid_yara(bad)
            old += is_valid_yara(clean_rule_output(legacy_postprocess(bad)))
            new += repair_rule(bad).valid
        rows[cname] = [n, raw, old, new]
    print(f"{'cas':45s} {'n':>4s} {'brut':>7s} {'ancien':>7s} {'nouveau':>8s}")
    for k, (n, raw, old, new) in rows.items():
        raw_s = "-" if raw is None else f"{100 * raw / n:.1f}%"
        print(f"{k:45s} {n:4d} {raw_s:>7s} {100 * old / n:6.1f}% {100 * new / n:7.1f}%")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
