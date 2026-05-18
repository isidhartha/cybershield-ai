"""TruffleHog binary wrapper with graceful fallback to built-in secret scanner."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List

from ..scanners.secret_scanner import SecretScanner
from ..shared.config import get_settings
from ..shared.logging import get_logger
from ..shared.models import Secret, Severity

logger = get_logger("trufflehog_runner")


def _is_available(binary_path: str) -> bool:
    if Path(binary_path).is_file():
        return True
    return shutil.which("trufflehog") is not None


def _get_binary(path: str) -> str:
    if Path(path).is_file():
        return path
    found = shutil.which("trufflehog")
    if found:
        return found
    raise FileNotFoundError("trufflehog binary not found")


def _mask(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


def _parse_trufflehog_output(output: str) -> List[Secret]:
    """Parse trufflehog JSON-lines output."""
    secrets: List[Secret] = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue

        raw = finding.get("Raw", finding.get("RawV2", ""))
        detector = finding.get("DetectorName", "Unknown")
        source_meta = finding.get("SourceMetadata", {})
        data = source_meta.get("Data", {})
        file_path = (
            data.get("Filesystem", {}).get("file")
            or data.get("Git", {}).get("file")
            or None
        )
        line_num = data.get("Filesystem", {}).get("line") or data.get("Git", {}).get("lineNumber")

        secrets.append(
            Secret(
                id=f"th-{finding.get('StructuredData', {}).get('id', raw[:16] if raw else 'unknown')}",
                type=detector,
                description=f"TruffleHog detected: {detector}",
                masked_value=_mask(raw) if raw else "****",
                file_path=str(file_path) if file_path else None,
                line_number=int(line_num) if line_num else None,
                severity=Severity.CRITICAL,
                confidence=float(finding.get("Verified", False)),
            )
        )
    return secrets


class TruffleHogRunner:
    """Run TruffleHog for enhanced entropy-based secret detection."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._binary_path = self.settings.trufflehog_path
        self._available = _is_available(self._binary_path)
        if not self._available:
            logger.info(
                "trufflehog binary not found at %s — using built-in scanner",
                self._binary_path,
            )
        self._fallback = SecretScanner()

    @property
    def is_available(self) -> bool:
        return self._available

    def scan_text(self, code: str, file_path: str = "stdin") -> List[Secret]:
        """Scan text for high-entropy secrets."""
        if not self._available:
            return self._fallback.scan_text(code, file_path=file_path)
        return self._scan_filesystem_text(code, file_path)

    def scan_git_repo(self, repo_url: str) -> List[Secret]:
        """Scan a git repository URL for secrets."""
        if not self._available:
            logger.warning("TruffleHog unavailable; cannot scan git repo %s", repo_url)
            return []
        return self._run_trufflehog_git(repo_url)

    def _scan_filesystem_text(self, code: str, file_path: str) -> List[Secret]:
        try:
            binary = _get_binary(self._binary_path)
        except FileNotFoundError:
            return self._fallback.scan_text(code, file_path=file_path)

        suffix = Path(file_path).suffix or ".txt"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [binary, "filesystem", tmp_path, "--json", "--no-update"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            secrets = _parse_trufflehog_output(result.stdout)
            for s in secrets:
                s.file_path = file_path
            return secrets
        except subprocess.TimeoutExpired:
            logger.error("trufflehog timed out")
            return self._fallback.scan_text(code, file_path=file_path)
        except Exception as exc:
            logger.error("trufflehog failed: %s", exc)
            return self._fallback.scan_text(code, file_path=file_path)
        finally:
            os.unlink(tmp_path)

    def _run_trufflehog_git(self, repo_url: str) -> List[Secret]:
        try:
            binary = _get_binary(self._binary_path)
        except FileNotFoundError:
            return []

        try:
            result = subprocess.run(
                [binary, "git", repo_url, "--json", "--no-update"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return _parse_trufflehog_output(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error("trufflehog git scan timed out for %s", repo_url)
            return []
        except Exception as exc:
            logger.error("trufflehog git scan failed: %s", exc)
            return []
