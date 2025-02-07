"""CVE explainer — fetches CVE data and explains it in plain English."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

import httpx

from ..shared.config import get_settings
from ..shared.logging import get_logger
from backend.llm_service import LLM_PROVIDER, complete as llm_complete

logger = get_logger("cve_explainer")

CVE_SYSTEM = """You are a cybersecurity educator explaining vulnerabilities to developers.
Given a CVE ID and its technical details, explain:
1. What the vulnerability is (plain English, no jargon)
2. How an attacker could exploit it (attack scenario)
3. What systems/versions are affected
4. Concrete remediation steps
5. CVSS score interpretation

Keep it practical — developers should understand why this matters to their application."""


class CVEExplainer:
    """Fetch CVE details from OSV/NVD and explain them using AI."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def explain(self, cve_id: str, include_technical: bool = True) -> Dict[str, Any]:
        """Return structured CVE explanation."""
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id, re.IGNORECASE):
            return {"error": f"Invalid CVE ID format: {cve_id}"}

        raw_data = await self._fetch_osv(cve_id)
        if "error" in raw_data:
            raw_data = await self._fetch_nvd(cve_id)

        ai_explanation = await self._ai_explain(cve_id, raw_data, include_technical)

        return {
            "cve_id": cve_id.upper(),
            "summary": raw_data.get("summary", "No summary available"),
            "published": raw_data.get("published"),
            "modified": raw_data.get("modified"),
            "severity": _extract_severity(raw_data),
            "cvss_score": _extract_cvss(raw_data),
            "references": _extract_references(raw_data),
            "affected": _extract_affected(raw_data),
            "explanation": ai_explanation,
        }

    async def _fetch_osv(self, cve_id: str) -> Dict[str, Any]:
        url = f"{self.settings.osv_api_url}/vulns/{cve_id}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.json()
                return {"error": f"OSV returned {resp.status_code}"}
        except httpx.HTTPError as exc:
            logger.warning("OSV fetch failed cve=%s error=%s", cve_id, exc)
            return {"error": str(exc)}

    async def _fetch_nvd(self, cve_id: str) -> Dict[str, Any]:
        """Fallback: query NVD API v2."""
        url = f"{self.settings.nvd_api_url}?cveId={cve_id}"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers={"Accept": "application/json"})
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return {"error": "CVE not found in NVD"}
                cve_data = vulns[0].get("cve", {})
                descriptions = cve_data.get("descriptions", [])
                summary = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"), ""
                )
                return {
                    "id": cve_id,
                    "summary": summary,
                    "published": cve_data.get("published"),
                    "modified": cve_data.get("lastModified"),
                    "_nvd_raw": cve_data,
                }
        except httpx.HTTPError as exc:
            logger.warning("NVD fetch failed cve=%s error=%s", cve_id, exc)
            return {"error": str(exc)}

    async def _ai_explain(
        self, cve_id: str, data: Dict[str, Any], include_technical: bool
    ) -> str:
        summary = data.get("summary", "No details available")
        severity = _extract_severity(data)
        cvss = _extract_cvss(data)
        affected = _extract_affected(data)

        prompt = (
            f"CVE ID: {cve_id}\n"
            f"Summary: {summary}\n"
            f"Severity: {severity} (CVSS: {cvss})\n"
            f"Affected packages: {', '.join(affected[:5]) if affected else 'unknown'}\n\n"
            "Please explain this vulnerability as described in the system prompt."
        )
        if not include_technical:
            prompt += "\nFocus on business impact rather than technical details."

        if LLM_PROVIDER == "ollama":
            return self._explain_ollama(prompt)
        provider = self.settings.ai_provider.lower()
        if provider == "anthropic":
            return await self._explain_anthropic(prompt)
        return await self._explain_openai(prompt)

    def _explain_ollama(self, prompt: str) -> str:
        try:
            return llm_complete(prompt, system=CVE_SYSTEM)
        except Exception as exc:
            logger.error("Ollama CVE explain failed: %s", exc)
            return f"AI explanation unavailable: {exc}"

    async def _explain_openai(self, prompt: str) -> str:
        if not self.settings.openai_api_key:
            return "Configure OPENAI_API_KEY or ANTHROPIC_API_KEY for AI-powered CVE explanations."

        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=self.settings.openai_api_key)
        try:
            response = await client.chat.completions.create(
                model=self.settings.ai_model,
                messages=[
                    {"role": "system", "content": CVE_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1200,
                temperature=0.2,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            logger.error("OpenAI CVE explain failed: %s", exc)
            return f"AI explanation unavailable: {exc}"

    async def _explain_anthropic(self, prompt: str) -> str:
        if not self.settings.anthropic_api_key:
            return "Configure OPENAI_API_KEY or ANTHROPIC_API_KEY for AI-powered CVE explanations."

        import anthropic
        client = anthropic.AsyncAnthropic(api_key=self.settings.anthropic_api_key)
        try:
            response = await client.messages.create(
                model="claude-opus-4-5",
                max_tokens=1200,
                system=CVE_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text if response.content else ""
        except Exception as exc:
            logger.error("Anthropic CVE explain failed: %s", exc)
            return f"AI explanation unavailable: {exc}"


def _extract_severity(data: Dict[str, Any]) -> str:
    for entry in data.get("severity", []):
        score = entry.get("score", "")
        if score:
            try:
                val = float(score.split("/")[0] if "/" in score else score)
                if val >= 9:
                    return "CRITICAL"
                if val >= 7:
                    return "HIGH"
                if val >= 4:
                    return "MEDIUM"
                return "LOW"
            except ValueError:
                pass
    db = data.get("database_specific", {})
    return db.get("severity", "UNKNOWN").upper()


def _extract_cvss(data: Dict[str, Any]) -> Optional[float]:
    for entry in data.get("severity", []):
        score = entry.get("score", "")
        try:
            return float(score.split("/")[0] if "/" in score else score)
        except (ValueError, AttributeError):
            pass
    return None


def _extract_references(data: Dict[str, Any]) -> list[str]:
    return [r.get("url", "") for r in data.get("references", []) if r.get("url")][:8]


def _extract_affected(data: Dict[str, Any]) -> list[str]:
    affected = []
    for entry in data.get("affected", []):
        pkg = entry.get("package", {})
        name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        if name:
            affected.append(f"{ecosystem}/{name}" if ecosystem else name)
    return affected
