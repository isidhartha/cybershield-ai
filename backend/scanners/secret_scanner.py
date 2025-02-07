"""Secret and credential detection scanner with comprehensive regex patterns."""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

from ..shared.logging import get_logger
from ..shared.models import Secret, Severity

logger = get_logger("secret_scanner")


@dataclass
class SecretPattern:
    name: str
    pattern: str
    severity: Severity = Severity.CRITICAL
    description: str = ""
    confidence: float = 0.9
    _compiled: Optional[Pattern[str]] = field(default=None, repr=False, compare=False)

    def compile(self) -> Pattern[str]:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        return self._compiled


SECRET_PATTERNS: List[SecretPattern] = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    SecretPattern(
        name="AWS Access Key ID",
        pattern=r"(?<![A-Z0-9])(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        severity=Severity.CRITICAL,
        description="Amazon Web Services Access Key ID",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=r"(?i)aws[_\-\s.]*(secret|access)[_\-\s.]*key[_\-\s.]*[=:\"'\s]+([A-Za-z0-9/+=]{40})",
        severity=Severity.CRITICAL,
        description="Amazon Web Services Secret Access Key",
    ),
    SecretPattern(
        name="AWS Session Token",
        pattern=r"(?i)aws[_\-\s.]*session[_\-\s.]*token[_\-\s.]*[=:\"'\s]+([A-Za-z0-9/+=]{100,})",
        severity=Severity.CRITICAL,
        description="Amazon Web Services Session Token",
    ),
    # ── GCP ──────────────────────────────────────────────────────────────────
    SecretPattern(
        name="GCP Service Account Key",
        pattern=r'"type"\s*:\s*"service_account"',
        severity=Severity.CRITICAL,
        description="Google Cloud Platform Service Account JSON key",
    ),
    SecretPattern(
        name="GCP API Key",
        pattern=r"AIza[0-9A-Za-z_\-]{35}",
        severity=Severity.HIGH,
        description="Google Cloud Platform / Firebase API key",
    ),
    SecretPattern(
        name="GCP OAuth Token",
        pattern=r"ya29\.[0-9A-Za-z_\-]+",
        severity=Severity.CRITICAL,
        description="Google OAuth access token",
    ),
    # ── Azure ─────────────────────────────────────────────────────────────────
    SecretPattern(
        name="Azure Storage Account Key",
        pattern=r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});",
        severity=Severity.CRITICAL,
        description="Azure Storage Account connection string with key",
    ),
    SecretPattern(
        name="Azure Client Secret",
        pattern=r"(?i)azure[_\-\s.]*client[_\-\s.]*secret[_\-\s.]*[=:\"'\s]+([A-Za-z0-9~._\-]{34,40})",
        severity=Severity.CRITICAL,
        description="Azure Active Directory client secret",
    ),
    SecretPattern(
        name="Azure SAS Token",
        pattern=r"(?i)sig=[A-Za-z0-9%+/=]{43,64}&se=",
        severity=Severity.HIGH,
        description="Azure Shared Access Signature token",
    ),
    # ── GitHub ────────────────────────────────────────────────────────────────
    SecretPattern(
        name="GitHub Personal Access Token (Classic)",
        pattern=r"ghp_[A-Za-z0-9]{36}",
        severity=Severity.CRITICAL,
        description="GitHub personal access token (classic)",
    ),
    SecretPattern(
        name="GitHub OAuth App Token",
        pattern=r"gho_[A-Za-z0-9]{36}",
        severity=Severity.CRITICAL,
        description="GitHub OAuth access token",
    ),
    SecretPattern(
        name="GitHub App Token",
        pattern=r"(ghu|ghs|ghr)_[A-Za-z0-9]{36}",
        severity=Severity.CRITICAL,
        description="GitHub App/server/refresh token",
    ),
    SecretPattern(
        name="GitHub Fine-Grained PAT",
        pattern=r"github_pat_[A-Za-z0-9_]{82}",
        severity=Severity.CRITICAL,
        description="GitHub fine-grained personal access token",
    ),
    # ── Slack ─────────────────────────────────────────────────────────────────
    SecretPattern(
        name="Slack Bot Token",
        pattern=r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}",
        severity=Severity.HIGH,
        description="Slack bot OAuth token",
    ),
    SecretPattern(
        name="Slack App Token",
        pattern=r"xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+",
        severity=Severity.HIGH,
        description="Slack app-level token",
    ),
    SecretPattern(
        name="Slack Webhook URL",
        pattern=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        severity=Severity.HIGH,
        description="Slack incoming webhook URL",
    ),
    # ── Discord ───────────────────────────────────────────────────────────────
    SecretPattern(
        name="Discord Bot Token",
        pattern=r"[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}",
        severity=Severity.HIGH,
        description="Discord bot token",
    ),
    SecretPattern(
        name="Discord Webhook URL",
        pattern=r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        severity=Severity.MEDIUM,
        description="Discord webhook URL",
    ),
    # ── Generic API Keys ──────────────────────────────────────────────────────
    SecretPattern(
        name="Generic API Key Assignment",
        pattern=r"""(?i)(?:api[_\-\s.]?key|apikey|api[_\-\s.]?secret|client[_\-\s.]?secret)\s*[=:]\s*["']([A-Za-z0-9_\-\.]{20,64})["']""",
        severity=Severity.HIGH,
        description="Generic API key or secret assignment",
        confidence=0.7,
    ),
    SecretPattern(
        name="Bearer Token in Header",
        pattern=r"""(?i)Authorization\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_\-\.]+)["']?""",
        severity=Severity.HIGH,
        description="Hardcoded Bearer authorization token",
        confidence=0.8,
    ),
    # ── Passwords ─────────────────────────────────────────────────────────────
    SecretPattern(
        name="Hardcoded Password",
        pattern=r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{8,64})["']""",
        severity=Severity.HIGH,
        description="Hardcoded password value",
        confidence=0.75,
    ),
    SecretPattern(
        name="Password in URL",
        pattern=r"[a-zA-Z]{3,10}://[^/\s:@]+:([^/\s:@]{3,64})@[^/\s]{3,}",
        severity=Severity.CRITICAL,
        description="Password embedded in URL credentials",
    ),
    # ── Private Keys ──────────────────────────────────────────────────────────
    SecretPattern(
        name="RSA Private Key",
        pattern=r"-----BEGIN RSA PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="RSA private key block",
    ),
    SecretPattern(
        name="EC Private Key",
        pattern=r"-----BEGIN EC PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="Elliptic Curve private key block",
    ),
    SecretPattern(
        name="OpenSSH Private Key",
        pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="OpenSSH private key block",
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity=Severity.CRITICAL,
        description="PGP private key block",
    ),
    SecretPattern(
        name="Generic Private Key",
        pattern=r"-----BEGIN (?:DSA|ENCRYPTED) PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="DSA or encrypted private key block",
    ),
    # ── Database Connection Strings ───────────────────────────────────────────
    SecretPattern(
        name="PostgreSQL Connection String",
        pattern=r"postgresql(?:\+\w+)?://[^:]+:([^@]{4,64})@[^/\s]+",
        severity=Severity.CRITICAL,
        description="PostgreSQL connection string with credentials",
    ),
    SecretPattern(
        name="MySQL Connection String",
        pattern=r"mysql(?:\+\w+)?://[^:]+:([^@]{4,64})@[^/\s]+",
        severity=Severity.CRITICAL,
        description="MySQL connection string with credentials",
    ),
    SecretPattern(
        name="MongoDB Connection String",
        pattern=r"mongodb(?:\+srv)?://[^:]+:([^@]{4,64})@[^/\s]+",
        severity=Severity.CRITICAL,
        description="MongoDB connection string with credentials",
    ),
    SecretPattern(
        name="Redis Connection String with Password",
        pattern=r"redis://:[^@]{4,64}@[^/\s]+",
        severity=Severity.HIGH,
        description="Redis connection string with password",
    ),
    # ── Stripe / Payment ──────────────────────────────────────────────────────
    SecretPattern(
        name="Stripe Secret Key",
        pattern=r"sk_live_[0-9A-Za-z]{24,}",
        severity=Severity.CRITICAL,
        description="Stripe live secret key",
    ),
    SecretPattern(
        name="Stripe Restricted Key",
        pattern=r"rk_live_[0-9A-Za-z]{24,}",
        severity=Severity.CRITICAL,
        description="Stripe live restricted key",
    ),
    # ── Twilio / SendGrid ────────────────────────────────────────────────────
    SecretPattern(
        name="Twilio Account SID",
        pattern=r"AC[a-zA-Z0-9]{32}",
        severity=Severity.HIGH,
        description="Twilio account SID",
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        severity=Severity.HIGH,
        description="SendGrid API key",
    ),
    # ── JWT ───────────────────────────────────────────────────────────────────
    SecretPattern(
        name="JSON Web Token",
        pattern=r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        severity=Severity.MEDIUM,
        description="JSON Web Token (may contain sensitive claims)",
        confidence=0.6,
    ),
    # ── npm / PyPI tokens ─────────────────────────────────────────────────────
    SecretPattern(
        name="npm Access Token",
        pattern=r"npm_[A-Za-z0-9]{36}",
        severity=Severity.HIGH,
        description="npm publish/access token",
    ),
    SecretPattern(
        name="PyPI Upload Token",
        pattern=r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
        severity=Severity.HIGH,
        description="PyPI API upload token",
    ),
]


def _mask_value(value: str, keep: int = 4) -> str:
    """Return the value with all but the last `keep` characters replaced."""
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


def _short_id(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:8]


class SecretScanner:
    """Scan source code for secrets and credentials using regex patterns."""

    def __init__(self) -> None:
        self._compiled: Dict[str, Pattern[str]] = {
            p.name: p.compile() for p in SECRET_PATTERNS
        }

    def scan_text(self, text: str, file_path: str = "<stdin>") -> List[Secret]:
        """Scan a block of text and return detected secrets."""
        findings: List[Secret] = []
        lines = text.splitlines()

        for pattern_def in SECRET_PATTERNS:
            compiled = self._compiled[pattern_def.name]
            for match in compiled.finditer(text):
                line_num = text[: match.start()].count("\n") + 1
                raw_value = match.group(0)
                findings.append(
                    Secret(
                        id=f"secret-{_short_id(file_path + str(line_num) + raw_value)}",
                        type=pattern_def.name,
                        description=pattern_def.description or pattern_def.name,
                        masked_value=_mask_value(raw_value),
                        file_path=file_path,
                        line_number=line_num,
                        severity=pattern_def.severity,
                        confidence=pattern_def.confidence,
                    )
                )
                logger.debug(
                    "Secret found type=%s file=%s line=%d",
                    pattern_def.name,
                    file_path,
                    line_num,
                )

        return _deduplicate(findings)

    def scan_files(self, files: Dict[str, str]) -> List[Secret]:
        """Scan multiple files given as {path: content} dict."""
        all_findings: List[Secret] = []
        for path, content in files.items():
            all_findings.extend(self.scan_text(content, file_path=path))
        return all_findings


def _deduplicate(secrets: List[Secret]) -> List[Secret]:
    seen: set[str] = set()
    result: List[Secret] = []
    for s in secrets:
        if s.id not in seen:
            seen.add(s.id)
            result.append(s)
    return result
