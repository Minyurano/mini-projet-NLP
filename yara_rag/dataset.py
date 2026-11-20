"""
Construction et chargement du jeu de règles YARA.

- ``build_dataset`` lit des dépôts publics de règles (clonés localement), découpe
  chaque fichier en règles, garde celles qui compilent, supprime les doublons et
  attribue un type de malware à partir du nom, des tags, du chemin et de la description.
- ``load_dataset`` charge le CSV obtenu, ou le CSV d'origine du projet
  (``yara_step2.csv``) : les deux formats sont acceptés.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pandas as pd

from .parsing import EXTERNALS, compile_error, split_rules

# Dépôts publics utilisés (licences propres à chaque dépôt : le jeu de données
# n'est pas redistribué, il est reconstruit localement).
SOURCES = {
    "Yara-Rules/rules": "https://github.com/Yara-Rules/rules",
    "Neo23x0/signature-base": "https://github.com/Neo23x0/signature-base",
    "reversinglabs/reversinglabs-yara-rules": "https://github.com/reversinglabs/reversinglabs-yara-rules",
}

# Fichiers écartés : ~9 000 signatures de packers PEiD (une suite d'octets d'entrée,
# sans description) qui noieraient les vraies règles de détection.
SKIP_FILES = ("peid.yar", "packer_compiler_signatures")


# Type de malware : premier motif trouvé (ordre = priorité, du plus précis au plus général)
TYPE_PATTERNS = [
    ("ransomware", r"ransom|crypt(?:o)?locker|wannacry|lockbit|ryuk|conti\b|revil|sodinokibi"),
    ("webshell", r"web_?shell|\bwshell|china_?chopper|\bjsp_|\bphp_|\baspx?_"),
    ("keylogger", r"keylog|key_?logger|getasynckeystate"),
    ("rootkit", r"rootkit|bootkit"),
    ("cryptominer", r"miner|monero|xmrig|coin_?hive|cryptonight"),
    ("infostealer", r"stealer|infostealer|password_?steal|azorult|redline|vidar|raccoon"),
    ("banker", r"banker|banking|zeus|dridex|trickbot|emotet|qakbot|qbot"),
    ("rat", r"\brat\b|_rat_|_rat\b|\brat_|remote_?access|njrat|darkcomet|nanocore|quasar|asyncrat|remcos"),
    ("backdoor", r"backdoor|reverse_?shell|bind_?shell"),
    ("loader", r"loader|dropper|downloader|stager"),
    ("exploit", r"exploit|cve[-_]\d{4}|\bcve\b"),
    ("hacktool", r"hacktool|hack_?tool|mimikatz|cobalt_?strike|metasploit|meterpreter|powersploit|impacket"),
    ("maldoc", r"maldoc|macro|\bole\b|office|\.docm|rtf_"),
    ("apt", r"\bapt\d*|apt_|lazarus|turla|sofacy|fancy_?bear|equation"),
    ("worm", r"\bworm"),
    ("packer", r"packer|packed|upx|themida|vmprotect"),
]


def guess_type(*texts: str) -> str:
    blob = " ".join(t for t in texts if t).lower()
    for name, pat in TYPE_PATTERNS:
        if re.search(pat, blob):
            return name
    return "malware"


def build_dataset(repo_dirs: dict[str, Path], out_csv: Path | None = None) -> pd.DataFrame:
    """Lit les dépôts clonés ({nom: dossier}) et produit un DataFrame de règles valides."""
    rows, seen = [], set()
    for source_name, root in repo_dirs.items():
        root = Path(root)
        base_url = SOURCES.get(source_name, "")
        for path in sorted(list(root.rglob("*.yar")) + list(root.rglob("*.yara"))):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            if any(x in rel.lower() for x in SKIP_FILES):
                continue
            for r in split_rules(text):
                if not r.strings:                    # règles purement logiques : peu utiles au RAG
                    continue
                if compile_error(r.source(), EXTERNALS) is not None:
                    continue
                body_norm = re.sub(r"\s+", " ", r.text)
                h = hashlib.sha1(body_norm.encode()).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                desc = r.meta.get("description", "")
                rows.append({
                    "id": len(rows),
                    "rule_name": r.name,
                    "malware_type": guess_type(r.name, " ".join(r.tags), rel, desc),
                    "description": desc,
                    "rule_body": r.text,
                    "imports": " ".join(r.imports),
                    "author": r.meta.get("author", ""),
                    "date": r.meta.get("date", ""),
                    "tags": " ".join(r.tags),
                    "source_url": f"{base_url}/blob/HEAD/{rel}" if base_url else rel,
                    "source_name": source_name,
                    "filename": rel,
                    "content_hash": h,
                    "is_valid": True,
                })
    df = pd.DataFrame(rows)
    if out_csv:
        Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(out_csv, index=False)
    return df


def string_literals(rule_body: str, limit: int = 12) -> str:
    """Chaînes texte lisibles d'une règle (noms d'API, chemins, commandes…), pour la recherche."""
    lits = re.findall(r'=\s*"((?:\\.|[^"\\]){3,80})"', rule_body)
    return " ".join(dict.fromkeys(lits))[: 60 * limit]


def load_dataset(csv_path: Path | str) -> pd.DataFrame:
    """Charge le CSV de règles (format de build_dataset ou yara_step2.csv d'origine)."""
    df = pd.read_csv(csv_path, dtype=str).fillna("")
    if "is_valid" in df.columns:
        df = df[df["is_valid"].str.lower().isin(["true", "1", "yes"])].copy()
    for alt in ("rule_text", "rule"):
        if "rule_body" not in df.columns and alt in df.columns:
            df = df.rename(columns={alt: "rule_body"})
    if "predicted_type" in df.columns and df["predicted_type"].str.len().gt(0).any():
        df["type"] = df["predicted_type"].where(df["predicted_type"] != "", df.get("malware_type", "malware"))
    elif "malware_type" in df.columns:
        df["type"] = df["malware_type"]
    else:
        df["type"] = "malware"
    for col in ("description", "rule_name", "source_url", "tags"):
        if col not in df.columns:
            df[col] = ""
    df = df.reset_index(drop=True)
    # Texte décrivant la règle (recherche sémantique) …
    df["embed_text"] = (df["rule_name"].str.replace("_", " ") + " " + df["type"] + " "
                        + df["description"]).str.strip()
    # … et texte de recherche par mots-clés : la description compte double, on y ajoute
    # les tags et les chaînes de la règle (API Windows, commandes, chemins), absentes de
    # la description (choix mesuré : voir benchmarks/retrieval_variants.py).
    df["search_text"] = (df["embed_text"] + " " + df["embed_text"] + " " + df["tags"] + " "
                         + df["rule_body"].map(string_literals))
    return df
