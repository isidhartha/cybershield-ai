"""LLM service — delegates to llm_router for multi-provider support."""
from __future__ import annotations

from .llm_router import _PROVIDER as LLM_PROVIDER, chat, complete

__all__ = ["LLM_PROVIDER", "chat", "complete"]
