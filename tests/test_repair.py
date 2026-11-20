import pytest

from yara_rag.parsing import is_valid_yara
from yara_rag.pipeline import prefill_for
from yara_rag.repair import repair_rule, sanitize_name

GOOD = '''rule Good {
    meta:
        description = "test"
    strings:
        $a = "cmd.exe" ascii
        $b = { 4D 5A }
    condition:
        $a and $b
}'''

BROKEN = {
    "markdown et prose": "Here is the rule:\n```yara\n" + GOOD + "\n```\nHope it helps!",
    "sections avec accolades": GOOD.replace("meta:", "meta {").replace("strings:", "strings {"),
    "meta sans guillemets": GOOD.replace('description = "test"', "description = Detects bad things"),
    "variable inexistante": GOOD.replace("$a and $b", "$a and $b and $c and #d > 2"),
    "règle coupée": GOOD[:-2],
    "guillemets simples": GOOD.replace('"cmd.exe"', "'cmd.exe'"),
    "nom invalide": GOOD.replace("rule Good", "rule 2024-Good.v2"),
    "noms en double": GOOD.replace("$b = { 4D 5A }", "$a = { 4D 5A }"),
    "commentaire dans l'hex": GOOD.replace("{ 4D 5A }", "{ 4D 5A // MZ header }"),
    "opérateurs C": GOOD.replace("$a and $b", "$a && $b || !$a"),
    "hex invalide": GOOD.replace("{ 4D 5A }", "{ 4D ZZ }"),
    "hex non fermée": GOOD.replace("{ 4D 5A }", "{ 4D 5A"),
}


def test_regle_correcte_inchangee_et_valide():
    r = repair_rule(GOOD)
    assert r.valid and r.fixes == []


@pytest.mark.parametrize("label", list(BROKEN))
def test_reparation(label):
    r = repair_rule(BROKEN[label])
    assert r.valid, (label, r.error, r.rule)
    assert is_valid_yara(r.rule)


def test_reparation_garde_le_sens_de_la_condition():
    r = repair_rule(BROKEN["variable inexistante"])
    assert "$a and $b" in r.rule and "$c" not in r.rule and "#d" not in r.rule


def test_ensembles_avec_joker():
    rule = GOOD.replace("$a and $b", "all of ($a*) or 2 of ($x*)")
    r = repair_rule(rule)
    assert r.valid and "all of ($a*)" in r.rule and "$x" not in r.rule


def test_noms_de_regle():
    assert sanitize_name("2024-bad.name") == "Rule_2024_bad_name"
    assert sanitize_name("condition") == "Rule_condition"
    assert sanitize_name("") == "Generated_Rule"


def test_prefill_recolle_comme_le_pipeline():
    """Le modèle ne renvoie que la suite du début imposé : prefill + suite doit compiler."""
    suite = 'Detects cmd"\n    strings:\n        $a = "cmd.exe"\n    condition:\n        $a\n}'
    assert repair_rule(prefill_for("Gen_Test") + suite).valid
    assert not repair_rule(suite).valid                    # sans le recollage : pas de règle


def test_imports_ajoutes():
    r = repair_rule('rule P { strings: $a = "x" condition: $a and pe.is_dll() }')
    assert r.valid and r.rule.startswith('import "pe"')
