import pandas as pd

from yara_rag.dataset import guess_type, load_dataset
from yara_rag.parsing import compile_error, is_valid_yara, split_rules


def test_decoupage_respecte_chaines_hex_commentaires(rules_text):
    rules = split_rules(rules_text)
    assert [r.name for r in rules] == ["Ransom_AES_Bitcoin", "Keylogger_GetAsyncKeyState",
                                      "Webshell_PHP_Eval", "Miner_XMRig"]
    assert rules[0].tags == ["ransomware"]
    assert [n for n, _ in rules[0].strings] == ["$s1", "$s2", "$s3", "$h1"]
    assert rules[1].imports == ["pe"]                     # import détecté pour la règle qui l'utilise
    assert all(compile_error(r.source()) is None for r in rules)


def test_validation_ajoute_les_imports_utilises():
    assert is_valid_yara('rule a { condition: pe.number_of_sections > 1 }')
    assert not is_valid_yara('rule a { condition: $x }')
    assert not is_valid_yara('pas une règle')


def test_construction_du_jeu_de_donnees(dataset):
    assert len(dataset) == 4                               # la règle cassée est écartée
    types = dict(zip(dataset.rule_name, dataset.type))
    assert types["Ransom_AES_Bitcoin"] == "ransomware"
    assert types["Keylogger_GetAsyncKeyState"] == "keylogger"
    assert types["Webshell_PHP_Eval"] == "webshell"
    assert types["Miner_XMRig"] == "cryptominer"
    assert "GetAsyncKeyState" in dataset.set_index("rule_name").at["Keylogger_GetAsyncKeyState", "search_text"]
    assert dataset.source_url.str.startswith("https://github.com/Yara-Rules/rules/blob/").all()


def test_chargement_du_csv_d_origine(tmp_path):
    """Le format yara_step2.csv du notebook d'origine reste accepté."""
    pd.DataFrame({"rule_name": ["A"], "rule_text": ['rule A { strings: $a = "x" condition: $a }'],
                  "description": ["d"], "predicted_type": ["rat"], "is_valid": ["True"]}
                 ).to_csv(tmp_path / "old.csv", index=False)
    df = load_dataset(tmp_path / "old.csv")
    assert df.at[0, "type"] == "rat" and "rule_body" in df.columns and df.at[0, "embed_text"] == "A rat d"


def test_type_par_mots_cles():
    assert guess_type("APT_Lazarus_Loader") == "loader"
    assert guess_type("Generic", "", "", "Detects webshell") == "webshell"
    assert guess_type("Something") == "malware"
