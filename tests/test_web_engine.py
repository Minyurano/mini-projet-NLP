"""La démo web (docs/engine.js) doit donner les mêmes résultats que le code Python."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from yara_rag.assemble import assemble_rule, web_payload
from yara_rag.parsing import is_valid_yara
from yara_rag.retrieval import Retriever

ENGINE = Path(__file__).resolve().parents[1] / "docs" / "engine.js"
QUERIES = ["keylogger capturing keystrokes with GetAsyncKeyState", "ransomware asking for a bitcoin ransom",
           "PHP webshell eval base64_decode", "monero miner xmrig stratum", "nothing matches zzzz"]


def python_results(df):
    r = Retriever(df)
    out = []
    for q in QUERIES:
        docs = r.docs(r.search_bm25(q, k=3))
        out.append({"names": [d["rule_name"] for d in docs],
                    "rule": assemble_rule(q, docs, today="2026-01-01")["rule"]})
    return out


def test_regles_assemblees_compilent(dataset):
    for res in python_results(dataset):
        assert is_valid_yara(res["rule"]), res["rule"]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js absent")
def test_meme_resultat_en_javascript(dataset, tmp_path):
    (tmp_path / "rules.json").write_text(json.dumps(web_payload(dataset)), encoding="utf-8")
    script = f"""
const E = require({json.dumps(str(ENGINE))});
const eng = new E.Engine(require({json.dumps(str(tmp_path / "rules.json"))}));
const out = {json.dumps(QUERIES)}.map(q => {{ const g = eng.generate(q, 3, "", "2026-01-01");
  return {{names: g.docs.map(d => d.name), rule: g.rule}}; }});
console.log(JSON.stringify(out));"""
    js = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout)
    assert js == python_results(dataset)
