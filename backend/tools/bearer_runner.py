"""Bearer binary wrapper for SAST and sensitive data flow analysis."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from ..scanners.code_scanner import CodeScanner
from ..shared.config import get_settings
from ..shared.logging import get_logger
from ..shared.models import Severity, Vulnerability

logger = get_logger("bearer_runner")

_SEVERITY_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "warning": Severity.LOW,
}


def _is_available(binary_path: str) -> bool:
    if Path(binary_path).is_file():
        return True
    return shutil.which("bearer") is not None


def _get_binary(path: str) -> str:
    if Path(path).is_file():
        return path
    found = shutil.which("bearer")
    if found:
        return found
    raise FileNotFoundError("bearer binary not found")


def _parse_bearer_output(data: Any) -> List[Vulnerability]:
    """Parse Bearer JSON report into Vulnerability models."""
    vulns: List[Vulnerability] = []
    if not isinstance(data, dict):
        return vulns

    for severity_key, findings in data.items():
        if not isinstance(findings, list):
            continue
        sev = _SEVERITY_MAP.get(severity_key.lower(), Severity.MEDIUM)
        for finding in findings:
            vuln_id = f"bearer-{finding.get('id', finding.get('rule_id', 'unknown'))}"
            line_num = finding.get("line_number") or finding.get("source", {}).get("start")
            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    title=finding.get("title", finding.get("rule_id", "Bearer finding")),
                    description=finding.get("description", ""),
                    severity=sev,
                    category=finding.get("category", "SAST"),
                    file_path=finding.get("filename"),
                    line_number=int(line_num) if line_num else None,
                    code_snippet=finding.get("code_extract", ""),
                    remediation=finding.get("documentation_url", ""),
                    cwe_id=finding.get("cwe_ids", [None])[0] if finding.get("cwe_ids") else None,
                    owasp_category=finding.get("owasp", {}).get("name") if isinstance(finding.get("owasp"), dict) else None,
                )
            )
    return vulns


class BearerRunner:
    """Run Bearer SAST scanner with fallback to built-in code scanner."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._binary_path = self.settings.bearer_path
        self._available = _is_available(self._binary_path)
        if not self._available:
            logger.info(
                "bearer binary not found at %s — using built-in code scanner",
                self._binary_path,
            )
        self._fallback = CodeScanner()

    @property
    def is_available(self) -> bool:
        return self._available

    def scan_code(self, code: str, file_path: str = "stdin", language: str = "python") -> List[Vulnerability]:
        """Scan code for security vulnerabilities."""
        if not self._available:
            return self._fallback.scan(code, file_path=file_path, language=language)
        return self._scan_with_bearer(code, file_path, language)

    def _scan_with_bearer(self, code: str, file_path: str, language: str) -> List[Vulnerability]:
        try:
            binary = _get_binary(self._binary_path)
        except FileNotFoundError:
            return self._fallback.scan(code, file_path=file_path, language=language)

        ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts",
                   "ruby": ".rb", "go": ".go", "java": ".java", "php": ".php"}
        suffix = ext_map.get(language, ".txt")

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / f"scan{suffix}"
            src_file.write_text(code, encoding="utf-8")
            report_path = Path(tmpdir) / "bearer-report.json"

            try:
                subprocess.run(
                    [binary, "scan", str(tmpdir), "--format", "json",
                     "--output", str(report_path), "--quiet"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if report_path.exists():
                    report_data = json.loads(report_path.read_text(encoding="utf-8"))
                    vulns = _parse_bearer_output(report_data)
                    for v in vulns:
                        if v.file_path:
                            v.file_path = file_path
                    return vulns
            except subprocess.TimeoutExpired:
                logger.error("bearer scan timed out for %s", file_path)
            except Exception as exc:
                logger.error("bearer scan failed: %s", exc)

        return self._fallback.scan(code, file_path=file_path, language=language)
