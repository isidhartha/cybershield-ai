"""Gitleaks binary wrapper with graceful fallback to built-in secret scanner."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..scanners.secret_scanner import SecretScanner
from ..shared.config import get_settings
from ..shared.logging import get_logger
from ..shared.models import Secret, Severity

logger = get_logger("gitleaks_runner")


def _is_available(binary_path: str) -> bool:
    """Return True if the gitleaks binary exists and is executable."""
    if Path(binary_path).is_file():
        return True
    return shutil.which("gitleaks") is not None


def _get_binary(path: str) -> str:
    """Resolve the actual binary path to use."""
    if Path(path).is_file():
        return path
    found = shutil.which("gitleaks")
    if found:
        return found
    raise FileNotFoundError("gitleaks binary not found")


def _parse_gitleaks_output(output: str) -> List[Secret]:
    """Parse gitleaks JSON report into Secret models."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("Failed to parse gitleaks output as JSON")
        return []

    if not isinstance(data, list):
        data = [data]

    secrets: List[Secret] = []
    for finding in data:
        raw_secret = finding.get("Secret", "")
        secrets.append(
            Secret(
                id=f"gl-{finding.get('Fingerprint', finding.get('Match', '')[:16])}",
                type=finding.get("RuleID", "unknown"),
                description=finding.get("Description", finding.get("RuleID", "Secret detected by gitleaks")),
                masked_value=_mask(raw_secret),
                file_path=finding.get("File"),
                line_number=finding.get("StartLine"),
                severity=Severity.CRITICAL,
                confidence=0.95,
            )
        )
    return secrets


def _mask(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


class GitleaksRunner:
    """Run gitleaks on code content or directories."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._binary_path = self.settings.gitleaks_path
        self._available = _is_available(self._binary_path)
        if not self._available:
            logger.info(
                "gitleaks binary not found at %s — falling back to built-in scanner",
                self._binary_path,
            )
        self._fallback = SecretScanner()

    @property
    def is_available(self) -> bool:
        return self._available

    def scan_text(self, code: str, file_path: str = "stdin") -> List[Secret]:
        """Scan text content for secrets."""
        if not self._available:
            return self._fallback.scan_text(code, file_path=file_path)
        return self._scan_with_tempfile(code, file_path)

    def scan_directory(self, directory: str) -> List[Secret]:
        """Scan a directory for secrets using gitleaks."""
        if not self._available:
            logger.warning("gitleaks unavailable; scanning directory with built-in scanner may be limited")
            return self._scan_directory_fallback(directory)
        return self._run_gitleaks_dir(directory)

    def _scan_with_tempfile(self, code: str, file_path: str) -> List[Secret]:
        """Write code to a temp file and run gitleaks on it."""
        try:
            binary = _get_binary(self._binary_path)
        except FileNotFoundError:
            return self._fallback.scan_text(code, file_path=file_path)

        suffix = Path(file_path).suffix or ".txt"
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [binary, "detect", "--source", tmp_path, "--report-format", "json", "--no-git", "--exit-code", "0"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            secrets = _parse_gitleaks_output(result.stdout)
            # Patch file path back to original
            for s in secrets:
                s.file_path = file_path
            return secrets
        except subprocess.TimeoutExpired:
            logger.error("gitleaks timed out scanning %s", file_path)
            return self._fallback.scan_text(code, file_path=file_path)
        except Exception as exc:
            logger.error("gitleaks failed: %s", exc)
            return self._fallback.scan_text(code, file_path=file_path)
        finally:
            os.unlink(tmp_path)

    def _run_gitleaks_dir(self, directory: str) -> List[Secret]:
        """Run gitleaks against a directory."""
        try:
            binary = _get_binary(self._binary_path)
        except FileNotFoundError:
            return self._scan_directory_fallback(directory)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        try:
            subprocess.run(
                [binary, "detect", "--source", directory, "--report-path", report_path,
                 "--report-format", "json", "--exit-code", "0"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            report_content = Path(report_path).read_text(encoding="utf-8")
            return _parse_gitleaks_output(report_content)
        except subprocess.TimeoutExpired:
            logger.error("gitleaks timed out scanning directory %s", directory)
            return []
        except Exception as exc:
            logger.error("gitleaks directory scan failed: %s", exc)
            return []
        finally:
            os.unlink(report_path)

    def _scan_directory_fallback(self, directory: str) -> List[Secret]:
        """Scan all text files in a directory with the built-in scanner."""
        files: Dict[str, str] = {}
        for root, _, filenames in os.walk(directory):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        files[fpath] = f.read()
                except OSError:
                    continue
        return self._fallback.scan_files(files)
