"""Post-traitement du notebook d'origine (cellules 10 et 12), copié tel quel pour comparaison."""
import re
def legacy_postprocess(prompt: str, max_tokens: int = 400) -> str:
    try:
        text = prompt.strip()

        # 1. Supprimer les préfixes numériques
        text = re.sub(r'^\d+\s*\{', 'rule Detect_Malware {', text)

        # 2. Ajouter "rule " si absent
        if not re.search(r'^rule\s+\w+', text, re.IGNORECASE):
            match = re.search(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\{', text, re.MULTILINE)
            if match:
                rule_name = match.group(1)
                text = re.sub(rf'^{re.escape(rule_name)}\s*{{', f'rule {rule_name} {{', text, flags=re.MULTILINE)
            else:
                text = 'rule Detect_Malware {\n' + text

        # 3. Supprimer le faux "rule Detect_Malware {" suivi d'un autre rule
        text = re.sub(r'rule\s+Detect_Malware\s*\{\s*\n\s*(?=\w+\s*\{)', '', text, flags=re.IGNORECASE)

        # 4. Corriger les noms commençant par un chiffre
        match = re.search(r'rule\s+([0-9][A-Za-z0-9_]*)\s*\{', text)
        if match:
            text = text.replace(f'rule {match.group(1)}', f'rule Rule_{match.group(1)}')

        # 5. Supprimer les appels à string.find() et autres fonctions Python
        lines = text.split('\n')
        text = '\n'.join([l for l in lines if 'string.find(' not in l and '.find(' not in l and 'import ' not in l and 'def ' not in l])

        # 6. Nettoyer les strings hex : enlever les commentaires // et tout ce qui suit sur la ligne
        def clean_hex_line(m):
            content = m.group(1)
            # Supprimer les commentaires // et tout texte après
            content = re.sub(r'\s*//.*', '', content)
            return f'{{ {content.strip()} }}'
        text = re.sub(r'\{\s*([^}]*?)\s*\}', clean_hex_line, text, flags=re.DOTALL)

        # 7. Déduplication des strings (par valeur)
        lines = text.split('\n')
        new_lines = []
        seen_values = set()
        in_strings = False
        for line in lines:
            if re.search(r'^\s*strings\s*[:{]', line, re.IGNORECASE):
                in_strings = True
                new_lines.append(line)
                continue
            if in_strings and re.search(r'^\s*condition\s*[:{]', line, re.IGNORECASE):
                in_strings = False
            if in_strings:
                m = re.match(r'\s*(\$\w+)\s*=\s*({[^}]+}|"[^"]+")(?:\s+(?:ascii|wide|fullword))*', line)
                if m:
                    name, val = m.groups()
                    if val in seen_values:
                        continue
                    seen_values.add(val)
            new_lines.append(line)
        text = '\n'.join(new_lines)

        # 8. Correction de la section meta : si "meta:" manque mais que des champs sont présents
        if re.search(r'rule\s+\w+\s*\{\s*(?!meta:)', text, re.IGNORECASE):
            # Insérer "meta:" après l'accolade ouvrante
            text = re.sub(r'(rule\s+\w+\s*\{\s*)', r'\1meta:\n    author = "RAG-System"\n', text, flags=re.IGNORECASE)

        # 9. Doubles accolades
        text = text.replace('{ {', '{').replace('}}', '}')

        # 10. Correction des sections mal formatées
        text = re.sub(r'meta\s*\{', 'meta:', text, flags=re.IGNORECASE)
        text = re.sub(r'strings\s*\{', 'strings:', text, flags=re.IGNORECASE)
        text = re.sub(r'condition\s*\{', 'condition:', text, flags=re.IGNORECASE)

        # 11. Nettoyer la condition : supprimer les références à des strings inexistantes
        defined_strings = set(re.findall(r'\$(\w+)\s*=', text))
        def clean_condition(m):
            cond = m.group(1)
            for s in re.findall(r'\$(\w+)', cond):
                if s not in defined_strings:
                    cond = re.sub(rf'\${re.escape(s)}\b', '', cond)
            cond = re.sub(r'\s+and\s+and\s+', ' and ', cond)
            cond = re.sub(r'\s+or\s+or\s+', ' or ', cond)
            cond = re.sub(r'\s+and\s*$', '', cond)
            cond = re.sub(r'^\s*and\s+', '', cond)
            if not cond.strip():
                cond = 'true'
            return f'condition: {cond}'
        text = re.sub(r'condition\s*:\s*(.*?)(?=\n\S|\Z)', clean_condition, text, flags=re.DOTALL)

        # 12. Fermer les accolades manquantes
        open_b = text.count('{')
        close_b = text.count('}')
        if open_b > close_b:
            text += '}' * (open_b - close_b)

        return text.strip()
    except Exception as e:
        return f'Erreur génération: {e}'

def clean_rule_output(raw: str) -> str:
    """Extrait et corrige la règle YARA depuis la sortie brute."""
    # Supprimer tout ce qui précède la première occurrence de 'rule '
    if 'rule ' in raw.lower():
        raw = raw[raw.lower().index('rule '):]
    # Couper à la première occurrence de '```' ou d'un double saut de ligne après la règle
    for stop in ['```', '\n\n\n']:
        if stop in raw:
            raw = raw.split(stop)[0]
    # Nettoyer les artefacts
    raw = re.sub(r'^\d+\s*', '', raw)          # enlève '1 ' en début
    raw = re.sub(r'rule\s+\d+\s*\{', 'rule Detect_Malware {', raw)
    return raw.strip()


