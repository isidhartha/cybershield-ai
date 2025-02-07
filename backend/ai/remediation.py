"""AI-powered remediation suggestion generator."""

from __future__ import annotations

from typing import Optional

from ..shared.config import get_settings
from ..shared.logging import get_logger
from ..shared.models import RemediationRequest, Vulnerability
from backend.llm_service import LLM_PROVIDER, complete as llm_complete

logger = get_logger("remediation")

REMEDIATION_SYSTEM = """You are a senior application security engineer and secure code expert.
Given a vulnerability finding, provide:
1. A clear explanation of the root cause.
2. A concrete, working code fix in the specified language.
3. Additional defensive measures (defence in depth).
4. Testing guidance to verify the fix works.

Format your response with these exact sections:
## Root Cause
## Fixed Code
## Defence in Depth
## Testing Guidance

Be specific, practical, and avoid generic advice."""


def _build_prompt(request: RemediationRequest) -> str:
    v = request.vulnerability
    parts = [
        f"**Vulnerability:** {v.title}",
        f"**Category:** {v.category}",
        f"**Severity:** {v.severity.value.upper()}",
        f"**Description:** {v.description}",
    ]
    if v.cwe_id:
        parts.append(f"**CWE:** {v.cwe_id}")
    if v.owasp_category:
        parts.append(f"**OWASP:** {v.owasp_category}")
    if v.code_snippet:
        parts.append(f"\n**Vulnerable code ({request.language}):**\n```{request.language}\n{v.code_snippet}\n```")
    if request.code_context:
        parts.append(f"\n**Surrounding context:**\n```{request.language}\n{request.code_context}\n```")
    if v.remediation:
        parts.append(f"\n**Existing hint:** {v.remediation}")

    return "\n".join(parts)


class RemediationEngine:
    """Generate AI fix suggestions for detected vulnerabilities."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def suggest_fix(self, request: RemediationRequest) -> str:
        """Return an AI-generated remediation for the given vulnerability."""
        prompt = _build_prompt(request)

        if LLM_PROVIDER == "ollama":
            return self._fix_ollama(prompt)
        provider = self.settings.ai_provider.lower()
        if provider == "anthropic":
            return await self._fix_anthropic(prompt)
        return await self._fix_openai(prompt)

    def _fix_ollama(self, prompt: str) -> str:
        try:
            return llm_complete(prompt, system=REMEDIATION_SYSTEM)
        except Exception as exc:
            logger.error("Ollama remediation failed: %s", exc)
            return f"AI service error: {exc}"

    async def _fix_openai(self, prompt: str) -> str:
        if not self.settings.openai_api_key:
            return _static_remediation(prompt)

        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=self.settings.openai_api_key)
        try:
            response = await client.chat.completions.create(
                model=self.settings.ai_model,
                messages=[
                    {"role": "system", "content": REMEDIATION_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1500,
                temperature=0.2,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            logger.error("OpenAI remediation failed: %s", exc)
            return f"AI service error: {exc}"

    async def _fix_anthropic(self, prompt: str) -> str:
        if not self.settings.anthropic_api_key:
            return _static_remediation(prompt)

        import anthropic
        client = anthropic.AsyncAnthropic(api_key=self.settings.anthropic_api_key)
        try:
            response = await client.messages.create(
                model="claude-opus-4-5",
                max_tokens=1500,
                system=REMEDIATION_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text if response.content else ""
        except Exception as exc:
            logger.error("Anthropic remediation failed: %s", exc)
            return f"AI service error: {exc}"


def _static_remediation(prompt: str) -> str:
    return (
        "AI provider not configured. General remediation guidance:\n\n"
        "## Root Cause\nReview the flagged code pattern for unsafe data handling.\n\n"
        "## Fixed Code\nApply input validation, parameterised queries, and least-privilege principles.\n\n"
        "## Defence in Depth\n- Enable WAF rules\n- Apply CSP headers\n- Enforce code review gates\n\n"
        "## Testing Guidance\nWrite unit tests that inject malicious payloads and verify they are rejected.\n\n"
        "Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env for AI-powered suggestions."
    )
