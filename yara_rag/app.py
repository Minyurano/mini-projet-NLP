"""
Interface Gradio : description du comportement malveillant → règle YARA compilée.

Corrections par rapport à l'ancienne interface :
- le choix du LLM charge vraiment le modèle choisi (avant, la liste ne changeait rien) ;
- l'état n'est plus une variable globale partagée entre tous les visiteurs ;
- la validité affichée est celle de la règle affichée (compilation yara-python).
"""
from __future__ import annotations

import re

from .generation import MODELS, HFGenerator
from .pipeline import YaraRAG


class ModelCache:
    """Garde un seul LLM en mémoire GPU à la fois."""

    def __init__(self, initial=None):
        self.current = initial

    def get(self, label: str):
        if self.current is not None and self.current.name == label:
            return self.current
        if self.current is not None and hasattr(self.current, "unload"):
            self.current.unload()
        self.current = HFGenerator(label)
        return self.current


def format_sources(docs: list[dict]) -> str:
    lines = []
    for i, d in enumerate(docs, 1):
        score = d.get("rerank_score") if d.get("rerank_score") is not None else d.get("retrieval_score")
        lines.append(f"{i}. [{d.get('type', '?')}] {d.get('rule_name', '?')}  (score {score:.3f})\n"
                     f"   {str(d.get('description', ''))[:110]}\n   {d.get('source_url', '')}")
    return "\n".join(lines) or "Aucune règle trouvée."


def explain(generator, rule: str) -> str:
    if not rule.strip():
        return "Générez d'abord une règle."
    messages = [{"role": "user", "content": (
        "Explain this YARA rule for a security analyst, in 5 short bullet points: what it detects, "
        "the most important strings and why, and when the condition matches.\n\n" + rule[:1500])}]
    text = generator.complete(messages, prefill="- ", max_new_tokens=260)
    return re.split(r"\n\s*rule\s", text)[0].strip()


def build_app(retriever, models: ModelCache, default_model: str = "TinyLlama (1.1B)"):
    import gradio as gr

    def generate(query, architecture, model_label):
        if not query or not query.strip():
            return "Décrivez d'abord le comportement à détecter.", "", "", {}
        rag = YaraRAG(retriever, models.get(model_label))
        g = rag.run(query.strip(), architecture)
        status = (f"{'✅ La règle compile (yara-python)' if g.valid else '❌ La règle ne compile pas : ' + str(g.error)}"
                  f"  ·  {architecture}  ·  {model_label}  ·  {g.latency:.1f} s  ·  {g.attempts} essai(s)")
        if g.fixes:
            status += "\n🔧 Corrections automatiques : " + " ; ".join(g.fixes[:6])
        if architecture == "Agentic RAG":
            status += "\n🤖 " + " → ".join(g.trace)
        return g.rule, status, format_sources(g.docs), {"rule": g.rule, "model": model_label}

    def do_explain(state):
        if not state or not state.get("rule"):
            return "Générez d'abord une règle."
        return explain(models.get(state["model"]), state["rule"])

    with gr.Blocks(title="Génération de règles YARA par RAG") as demo:
        gr.Markdown("# Génération de règles YARA par RAG\n"
                    "Décrivez un comportement malveillant : le système retrouve des règles proches dans la base, "
                    "puis un LLM écrit une règle **vérifiée par le compilateur YARA**.")
        state = gr.State({})
        with gr.Row():
            query = gr.Textbox(label="Comportement à détecter", lines=3, scale=3,
                               placeholder="Ex. : ransomware qui chiffre les fichiers en AES et demande une rançon en Bitcoin")
            with gr.Column(scale=1):
                arch = gr.Dropdown(list(YaraRAG.ARCHITECTURES), value="Agentic RAG", label="Architecture RAG")
                model = gr.Dropdown(list(MODELS), value=default_model, label="LLM")
                go = gr.Button("Générer la règle", variant="primary")
        rule = gr.Code(label="Règle YARA", language=None, lines=18)
        status = gr.Textbox(label="Vérification", lines=3, interactive=False)
        with gr.Row():
            sources = gr.Textbox(label="Règles de la base utilisées (sources)", lines=10, interactive=False)
            explanation = gr.Textbox(label="Explication", lines=10, interactive=False)
        expl_btn = gr.Button("Expliquer la règle")
        gr.Examples([[q] for q in (
            "Ransomware encrypting files with AES and asking for a Bitcoin ransom",
            "Keylogger capturing keystrokes with GetAsyncKeyState",
            "PHP webshell executing commands sent through eval and base64_decode",
            "Cryptominer using xmrig to mine Monero",
        )], inputs=[query])
        go.click(generate, [query, arch, model], [rule, status, sources, state])
        expl_btn.click(do_explain, [state], [explanation])
    return demo
