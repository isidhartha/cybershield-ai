"""Universal LLM provider router — supports all major AI providers + Ollama."""
from __future__ import annotations

import os
from typing import Any

_PROVIDER = (
    os.getenv("AI_PROVIDER") or os.getenv("LLM_PROVIDER") or "ollama"
).lower()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")


def _ollama(messages: list[dict], **kw) -> str:
    import requests
    try:
        r = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={"model": OLLAMA_MODEL, "messages": messages, "stream": False},
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Ollama is not running. Start with: ollama serve\n"
            "Install from https://ollama.com — then: ollama pull llama3.2"
        )


def _openai(messages: list[dict], **kw) -> str:
    import openai
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    r = client.chat.completions.create(model=model, messages=messages, **kw)
    return r.choices[0].message.content


def _anthropic(messages: list[dict], **kw) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    system = next((m["content"] for m in messages if m["role"] == "system"), None)
    user_msgs = [m for m in messages if m["role"] != "system"]
    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    kwargs: dict[str, Any] = {"model": model, "max_tokens": 4096, "messages": user_msgs}
    if system:
        kwargs["system"] = system
    r = client.messages.create(**kwargs)
    return r.content[0].text


def _gemini(messages: list[dict], **kw) -> str:
    import google.generativeai as genai
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-1.5-flash"))
    prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
    r = model.generate_content(prompt)
    return r.text


def _openai_compat(messages: list[dict], base_url: str, api_key: str, model: str, **kw) -> str:
    import openai
    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    r = client.chat.completions.create(model=model, messages=messages, **kw)
    return r.choices[0].message.content


def chat(messages: list[dict], **kw) -> str:
    p = _PROVIDER
    if p == "ollama":
        return _ollama(messages, **kw)
    elif p == "openai":
        return _openai(messages, **kw)
    elif p == "anthropic":
        return _anthropic(messages, **kw)
    elif p in ("gemini", "google"):
        return _gemini(messages, **kw)
    elif p == "nvidia":
        return _openai_compat(
            messages,
            base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            api_key=os.getenv("NVIDIA_API_KEY", ""),
            model=os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
            **kw,
        )
    elif p == "deepseek":
        return _openai_compat(
            messages,
            base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            api_key=os.getenv("DEEPSEEK_API_KEY", ""),
            model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            **kw,
        )
    elif p == "groq":
        return _openai_compat(
            messages,
            base_url="https://api.groq.com/openai/v1",
            api_key=os.getenv("GROQ_API_KEY", ""),
            model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
            **kw,
        )
    elif p == "mistral":
        return _openai_compat(
            messages,
            base_url="https://api.mistral.ai/v1",
            api_key=os.getenv("MISTRAL_API_KEY", ""),
            model=os.getenv("MISTRAL_MODEL", "mistral-small-latest"),
            **kw,
        )
    else:
        return _ollama(messages, **kw)


def complete(prompt: str, system: str | None = None, **kw) -> str:
    msgs: list[dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    return chat(msgs, **kw)
