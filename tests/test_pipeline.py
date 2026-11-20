import numpy as np

from yara_rag.generation import ScriptedGenerator, render_prompt
from yara_rag.metrics import evaluate, grounding, query_coverage, summary, type_precision
from yara_rag.pipeline import YaraRAG, build_messages, rule_name_from_query
from yara_rag.retrieval import Retriever, tokenize

SUITE = ('Keylogger using GetAsyncKeyState"\n    strings:\n        $a1 = "GetAsyncKeyState" ascii\n'
         '        $a2 = "keylog.txt" ascii\n    condition:\n        all of them\n}')


def fake_encoder(texts):
    """Encodeur de test : sac de mots haché (remplace le modèle d'embeddings)."""
    out = np.zeros((len(texts), 64), dtype="float32")
    for i, t in enumerate(texts):
        for w in tokenize(t):
            out[i, hash(w) % 64] += 1
    return out


def test_tokenisation():
    toks = tokenize("GetAsyncKeyState keylog_file.txt")
    assert {"getasynckeystate", "get", "async", "key", "state", "keylog", "txt"} <= set(toks)


def test_recherche_bm25_et_hybride(dataset):
    r = Retriever(dataset, encoder=fake_encoder)
    top = r.docs(r.search_bm25("capture keystrokes with GetAsyncKeyState", k=1))[0]
    assert top["rule_name"] == "Keylogger_GetAsyncKeyState"
    hits = r.search_hybrid("monero miner xmrig", k=2)
    assert dataset.at[hits[0].index, "rule_name"] == "Miner_XMRig"
    assert hits[0].dense is not None and hits[0].sparse is not None


def test_prompt_contient_exemples_et_consignes(dataset):
    r = Retriever(dataset)
    docs = r.docs(r.search_bm25("keylogger", k=2))
    msgs = build_messages("keylogger", docs)
    assert msgs[0]["role"] == "system" and "GetAsyncKeyState" in msgs[1]["content"]
    assert rule_name_from_query("Detect a keylogger capturing keys with GetAsyncKeyState") == "Gen_Keylogger_Capturing_Keys_GetAsyncKeyState"


def test_rag_genere_une_regle_valide(dataset):
    rag = YaraRAG(Retriever(dataset), ScriptedGenerator([SUITE]))
    g = rag.run("keylogger capturing keystrokes with GetAsyncKeyState", "RAG Hybride")
    assert g.valid and g.rule.startswith("rule Gen_Keylogger")
    assert g.attempts == 1 and len(g.docs) > 0


def test_agent_renvoie_l_erreur_au_modele(dataset):
    gen = ScriptedGenerator(['x"\n    strings:\n    condition:\n        uint16(0) == \n}', SUITE])
    rag = YaraRAG(Retriever(dataset), gen)
    g = rag.run("keylogger GetAsyncKeyState", "Agentic RAG")
    assert g.valid and g.attempts == 2
    assert "yara-python refuses this rule" in gen.calls[1][-1]["content"]   # erreur transmise
    assert "essai 1 : erreur" in g.trace[0] and g.trace[1].endswith("compile")


def test_hybride_ne_reessaie_pas(dataset):
    gen = ScriptedGenerator(['x"\n    condition:\n        uint16(0) == \n}'])
    g = YaraRAG(Retriever(dataset), gen).run("keylogger", "RAG Hybride")
    assert not g.valid and g.attempts == 1 and len(gen.calls) == 1


def test_metriques(dataset):
    rule = 'rule X { strings: $a = "GetAsyncKeyState" $b = "keylog.txt" condition: all of them }'
    docs = dataset[dataset.rule_name == "Keylogger_GetAsyncKeyState"].to_dict("records")
    g, copy = grounding(rule, docs)
    assert g == 1.0 and copy is True                       # toutes les chaînes viennent d'une seule règle
    g2, copy2 = grounding(rule.replace('"keylog.txt"', '"stolen_keys.dat"'), docs)
    assert g2 == 0.5 and copy2 is False
    assert query_coverage(rule, "keylogger using GetAsyncKeyState") > 0.4
    assert type_precision(docs, "keylogger") == 1.0


def test_evaluation_complete(dataset):
    rag = YaraRAG(Retriever(dataset), ScriptedGenerator([SUITE] * 6))
    res = evaluate(rag, queries=[("keylogger GetAsyncKeyState", "keylogger"), ("monero miner", "cryptominer")],
                   log=lambda *_: None)
    s = summary(res)
    assert set(s.index) == set(YaraRAG.ARCHITECTURES) and (s["syntax_valid"] == 1.0).all()


def test_format_prompt_sans_chat_template():
    class Tok:
        chat_template = None
    p = render_prompt(Tok(), [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}], "rule X {")
    assert p.endswith("Output:\nrule X {") and "Instruct: U" in p
