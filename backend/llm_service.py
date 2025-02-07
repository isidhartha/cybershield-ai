"""Unified LLM service — supports OpenAI and Ollama (free, local)."""
from __future__ import annotations
import os
import requests

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

def _ollama_chat(messages: list[dict], **kwargs) -> str:
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={"model": OLLAMA_MODEL, "messages": messages, "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Ollama is not running. Start it with: ollama serve\n"
            "Install from https://ollama.com — then run: ollama pull llama3.2"
        )

def _openai_chat(messages: list[dict], **kwargs) -> str:
    import openai
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    resp = client.chat.completions.create(
        model=OPENAI_MODEL, messages=messages, **kwargs
    )
    return resp.choices[0].message.content

def chat(messages: list[dict], **kwargs) -> str:
    if LLM_PROVIDER == "ollama":
        return _ollama_chat(messages, **kwargs)
    return _openai_chat(messages, **kwargs)

def complete(prompt: str, system: str | None = None, **kwargs) -> str:
    msgs = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    return chat(msgs, **kwargs)
