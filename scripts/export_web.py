"""
Exporte la base de règles pour la démo web (docs/data/rules.json, GitHub Pages).

    python scripts/export_web.py [--data data/yara_rules.csv]

Pour chaque règle : nom, type, description, auteur, lien source, tags, chaînes lisibles
(index de recherche) et chaînes réutilisables (assemblage). Les licences des dépôts
sources sont copiées dans docs/data/licenses/.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from yara_rag.assemble import web_payload  # noqa: E402
from yara_rag.dataset import load_dataset  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data" / "yara_rules.csv"))
    ap.add_argument("--sources-dir", default=str(ROOT / "data" / "sources"))
    ap.add_argument("--out", default=str(ROOT / "docs" / "data"))
    args = ap.parse_args()
    df = load_dataset(args.data)
    payload = web_payload(df)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rules.json").write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    lic = out / "licenses"
    lic.mkdir(exist_ok=True)
    for src in Path(args.sources_dir).glob("*"):
        f = next((p for p in src.glob("LICENSE*")), None)
        if f:
            shutil.copy(f, lic / f"{src.name}.txt")
    print(f"{payload['count']:,} règles -> {out / 'rules.json'} ({(out / 'rules.json').stat().st_size / 1e6:.1f} Mo)")


if __name__ == "__main__":
    main()
