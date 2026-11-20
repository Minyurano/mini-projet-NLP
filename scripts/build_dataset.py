"""
Reconstruit la base de règles YARA à partir de dépôts publics.

    python scripts/build_dataset.py                 # -> data/yara_rules.csv
    python scripts/build_dataset.py --out data/x.csv --sources-dir /tmp/yara_sources

Les dépôts sont clonés (dernière version uniquement), chaque fichier est découpé en
règles, seules les règles qui compilent avec yara-python sont gardées, les doublons
sont retirés et un type de malware est attribué à chaque règle.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from yara_rag.dataset import SOURCES, build_dataset  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "data" / "yara_rules.csv"))
    ap.add_argument("--sources-dir", default=str(ROOT / "data" / "sources"))
    args = ap.parse_args()
    src_dir = Path(args.sources_dir)
    src_dir.mkdir(parents=True, exist_ok=True)
    repos = {}
    for name, url in SOURCES.items():
        dest = src_dir / name.replace("/", "_")
        if not dest.exists():
            print(f"Clonage de {url} …")
            subprocess.run(["git", "clone", "--quiet", "--depth", "1", url, str(dest)], check=True)
        repos[name] = dest
    df = build_dataset(repos, Path(args.out))
    print(f"{len(df):,} règles valides et uniques -> {args.out}")
    print(df["malware_type"].value_counts().to_string())


if __name__ == "__main__":
    main()
