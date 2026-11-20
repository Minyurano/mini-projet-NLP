"""Défauts typiques des sorties de petits LLM, appliqués à de vraies règles."""
import random, re

def c_fence(r, rng):      return "Here is the YARA rule:\n```yara\n" + r + "\n```\nThis rule detects the malware."
def c_brace_sections(r, rng): return re.sub(r"(?m)^(\s*)(meta|strings|condition):", r"\1\2 {", r)
def c_unquoted_meta(r, rng):  return re.sub(r'(description|author)\s*=\s*"([^"]*)"', r"\1 = \2", r, count=2)
def c_undefined_var(r, rng):  return re.sub(r"(?m)(condition:\s*\n\s*)(.+)", r"\1\2 and $zz9 and #qq > 2", r, count=1)
def c_truncated(r, rng):      return r.rstrip().rstrip("}").rstrip()
def c_single_quotes(r, rng):  return re.sub(r'(\$\w+\s*=\s*)"([^"\\\']{3,60})"', r"\1'\2'", r, count=2)
def c_bad_name(r, rng):       return re.sub(r"rule\s+(\w+)", r"rule 2024-\1.v2", r, count=1)
def c_dup_names(r, rng):      return re.sub(r"(?m)^(\s*)\$\w+(\s*=)", r"\1$a\2", r)
def c_hex_comment(r, rng):    return re.sub(r"\{\s*([0-9A-Fa-f]{2} [0-9A-Fa-f]{2})", r"{ \1 // header", r, count=1)
def c_cpp_ops(r, rng):        return re.sub(r"(?m)(condition:\s*\n\s*)(.+)", lambda m: m.group(1) + m.group(2).replace(" and ", " && ").replace(" or ", " || "), r, count=1)
def c_bad_hex(r, rng):        return re.sub(r"\{\s*([0-9A-Fa-f]{2}) ", r"{ \1 GZ ", r, count=1)

CORRUPTIONS = {
    "texte et balises markdown autour": c_fence,
    "sections écrites « meta { »": c_brace_sections,
    "valeurs meta sans guillemets": c_unquoted_meta,
    "variable inexistante dans la condition": c_undefined_var,
    "règle coupée (accolade finale manquante)": c_truncated,
    "chaînes entre guillemets simples": c_single_quotes,
    "nom de règle invalide": c_bad_name,
    "noms de chaînes en double": c_dup_names,
    "commentaire dans une chaîne hexadécimale": c_hex_comment,
    "opérateurs && et ||": c_cpp_ops,
    "chaîne hexadécimale invalide": c_bad_hex,
}
