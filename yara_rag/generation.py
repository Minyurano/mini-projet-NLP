"""
Génération de texte (partie « G » du RAG).

``HFGenerator`` charge un modèle Hugging Face (Phi-2, TinyLlama, Mistral-7B…) et
utilise le format de conversation propre à chaque modèle (chat template), avec un
décodage déterministe (glouton) : une règle doit être reproductible.

Point clé corrigé : le prompt se termine par le début de la règle (« préremplissage »).
Le modèle ne renvoie que la suite ; on la recolle au préremplissage avant de valider.
L'ancienne version oubliait ce recollage : même une sortie parfaite ne compilait pas.
"""
from __future__ import annotations

import gc
from typing import Protocol

MODELS = {
    "TinyLlama (1.1B)": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
    "Phi-2 (2.7B)": "microsoft/phi-2",
    "Mistral-7B Instruct": "mistralai/Mistral-7B-Instruct-v0.2",
}


class Generator(Protocol):
    name: str

    def complete(self, messages: list[dict], prefill: str = "", max_new_tokens: int = 450) -> str:
        """Renvoie prefill + texte généré."""


def render_prompt(tokenizer, messages: list[dict], prefill: str) -> str:
    """Prompt au format du modèle ; repli générique si le modèle n'a pas de chat template."""
    if getattr(tokenizer, "chat_template", None):
        msgs = messages
        if msgs and msgs[0]["role"] == "system":           # Mistral refuse le rôle « system »
            try:
                tokenizer.apply_chat_template(msgs, tokenize=False)
            except Exception:
                msgs = [{"role": "user", "content": msgs[0]["content"] + "\n\n" + msgs[1]["content"]}] + msgs[2:]
        text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    else:                                                   # Phi-2 : format Instruct/Output
        sys_txt = "\n".join(m["content"] for m in messages if m["role"] == "system")
        user = "\n".join(m["content"] for m in messages if m["role"] == "user")
        text = f"{sys_txt}\n\nInstruct: {user}\nOutput:\n"
    return text + prefill


class HFGenerator:
    """Modèle de langage local (transformers), quantifié en 4 bits si un GPU est présent."""

    def __init__(self, label: str, model_id: str | None = None, load_in_4bit: bool | None = None,
                 cache_dir: str | None = None):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.name = label
        model_id = model_id or MODELS.get(label, label)
        gpu = torch.cuda.is_available()
        if load_in_4bit is None:
            load_in_4bit = gpu
        kwargs = {"cache_dir": cache_dir}
        if load_in_4bit:
            from transformers import BitsAndBytesConfig
            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True)
            kwargs["device_map"] = "auto"
        else:
            kwargs["torch_dtype"] = torch.float16 if gpu else torch.float32
            kwargs["device_map"] = "auto" if gpu else None
        self.tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=cache_dir)
        self.model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

    def complete(self, messages: list[dict], prefill: str = "", max_new_tokens: int = 450) -> str:
        import torch
        prompt = render_prompt(self.tokenizer, messages, prefill)
        inputs = self.tokenizer(prompt, return_tensors="pt", add_special_tokens=False).to(self.model.device)
        with torch.no_grad():
            out = self.model.generate(
                **inputs, max_new_tokens=max_new_tokens, do_sample=False,
                repetition_penalty=1.08, pad_token_id=self.tokenizer.pad_token_id)
        new_tokens = out[0, inputs["input_ids"].shape[1]:]
        return prefill + self.tokenizer.decode(new_tokens, skip_special_tokens=True)

    def unload(self) -> None:
        import torch
        del self.model
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()


class ScriptedGenerator:
    """Générateur de test : renvoie des réponses écrites à l'avance (tests sans GPU)."""

    def __init__(self, answers: list[str], name: str = "scripted"):
        self.answers = list(answers)
        self.name = name
        self.calls: list[list[dict]] = []

    def complete(self, messages: list[dict], prefill: str = "", max_new_tokens: int = 450) -> str:
        self.calls.append(messages)
        answer = self.answers.pop(0) if self.answers else ""
        return prefill + answer
