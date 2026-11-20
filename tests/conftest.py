import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

RULES = r'''
import "pe"

rule Ransom_AES_Bitcoin : ransomware {
    meta:
        description = "Ransomware encrypting files with AES and asking for a Bitcoin ransom"
        author = "test"
    strings:
        $s1 = "Your files have been encrypted" ascii wide
        $s2 = "bitcoin" nocase
        $s3 = "vssadmin delete shadows /all /quiet" ascii
        $h1 = { 4D 5A 90 00 }   // en-tête MZ
    condition:
        uint16(0) == 0x5A4D and 2 of ($s*) and $h1
}

rule Keylogger_GetAsyncKeyState {
    meta:
        description = "Keylogger polling keyboard state"
    strings:
        $a1 = "GetAsyncKeyState" ascii
        $a2 = "keylog.txt" ascii
        $b = "{ not an hex string }" ascii   /* accolades dans une chaîne */
    condition:
        all of ($a*) and $b and pe.number_of_sections > 2
}

private rule Webshell_PHP_Eval {
    meta:
        description = "PHP webshell using eval and base64_decode"
    strings:
        $p1 = "eval(base64_decode($_POST" ascii
        $p2 = /\$_(GET|POST)\[['"]cmd['"]\]/
    condition:
        any of them
}

rule Miner_XMRig {
    meta:
        description = "Cryptominer XMRig mining Monero"
    strings:
        $m1 = "stratum+tcp://" ascii
        $m2 = "xmrig" nocase
    condition:
        all of them
}
'''


@pytest.fixture()
def rules_text():
    return RULES


@pytest.fixture()
def repo(tmp_path):
    d = tmp_path / "repo" / "malware"
    d.mkdir(parents=True)
    (d / "sample.yar").write_text(RULES, encoding="utf-8")
    (d / "broken.yar").write_text("rule Broken { strings: $a = \"x\" condition: $b }", encoding="utf-8")
    return tmp_path / "repo"


@pytest.fixture()
def dataset(repo, tmp_path):
    from yara_rag.dataset import build_dataset, load_dataset
    build_dataset({"Yara-Rules/rules": repo}, tmp_path / "rules.csv")
    return load_dataset(tmp_path / "rules.csv")
