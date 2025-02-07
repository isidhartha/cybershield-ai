"""AI security assistant — chat interface with a security-focused system prompt."""

from __future__ import annotations

from typing import AsyncIterator, List, Optional

from ..shared.config import get_settings
from ..shared.logging import get_logger
from ..shared.models import ChatMessage

logger = get_logger("security_assistant")

SYSTEM_PROMPT = """You are CyberShield AI, an elite cybersecurity assistant and penetration testing advisor.

Your expertise covers:
- OWASP Top 10 vulnerabilities and mitigations
- CVE analysis and exploit techniques (for educational and authorized testing purposes)
- Secure code review (Python, JavaScript/TypeScript, Go, Java, C/C++, PHP)
- Network security, authentication, cryptography, and cloud security
- Threat modeling (STRIDE, PASTA, DREAD)
- Incident response and forensic analysis
- DevSecOps practices and security tool chains
- Regulatory compliance (SOC2, PCI-DSS, HIPAA, GDPR)

Guidelines:
1. Provide precise, actionable security guidance.
2. Always include remediation steps alongside vulnerability explanations.
3. Cite CWE IDs and OWASP categories where relevant.
4. For exploit discussions, emphasize authorized testing and legal boundaries.
5. Never provide working exploit code for unpatched production vulnerabilities.
6. Recommend defence-in-depth strategies, not single-point controls.
7. Format code examples with the appropriate language tag.
8. Be concise but thorough — security professionals value accuracy over verbosity.

You are operating within an authorized security assessment platform."""


class SecurityAssistant:
    """Wraps OpenAI or Anthropic to provide security-focused AI chat."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def _build_messages(
        self, messages: List[ChatMessage], context: Optional[str]
    ) -> list[dict]:
        system = SYSTEM_PROMPT
        if context:
            system += f"\n\n## Scan Context\n{context}"

        openai_messages: list[dict] = [{"role": "system", "content": system}]
        for msg in messages:
            openai_messages.append({"role": msg.role, "content": msg.content})
        return openai_messages

    async def chat(
        self,
        messages: List[ChatMessage],
        context: Optional[str] = None,
    ) -> str:
        """Return a complete chat response as a string."""
        provider = self.settings.ai_provider.lower()
        if provider == "anthropic":
            return await self._chat_anthropic(messages, context)
        return await self._chat_openai(messages, context)

    async def _chat_openai(
        self, messages: List[ChatMessage], context: Optional[str]
    ) -> str:
        if not self.settings.openai_api_key:
            return self._fallback_response(messages)

        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=self.settings.openai_api_key)
        openai_messages = self._build_messages(messages, context)

        try:
            response = await client.chat.completions.create(
                model=self.settings.ai_model,
                messages=openai_messages,
                max_tokens=2048,
                temperature=0.3,
            )
            content = response.choices[0].message.content or ""
            logger.debug("OpenAI response tokens=%d", response.usage.total_tokens if response.usage else 0)
            return content
        except Exception as exc:
            logger.error("OpenAI chat failed: %s", exc)
            return f"AI service error: {exc}"

    async def _chat_anthropic(
        self, messages: List[ChatMessage], context: Optional[str]
    ) -> str:
        if not self.settings.anthropic_api_key:
            return self._fallback_response(messages)

        import anthropic
        client = anthropic.AsyncAnthropic(api_key=self.settings.anthropic_api_key)

        system = SYSTEM_PROMPT
        if context:
            system += f"\n\n## Scan Context\n{context}"

        anthropic_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role != "system"
        ]

        try:
            response = await client.messages.create(
                model="claude-opus-4-5",
                max_tokens=2048,
                system=system,
                messages=anthropic_messages,
            )
            return response.content[0].text if response.content else ""
        except Exception as exc:
            logger.error("Anthropic chat failed: %s", exc)
            return f"AI service error: {exc}"

    def _fallback_response(self, messages: List[ChatMessage]) -> str:
        """Return a helpful static response when no AI key is configured."""
        last = messages[-1].content if messages else ""
        return (
            "AI provider not configured. Please set OPENAI_API_KEY or ANTHROPIC_API_KEY in your .env file.\n\n"
            f"Your question was: {last}\n\n"
            "For security questions, refer to: https://owasp.org/www-project-top-ten/"
        )
