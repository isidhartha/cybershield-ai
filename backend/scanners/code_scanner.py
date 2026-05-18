"""Static code analysis scanner for common security vulnerabilities."""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern

from ..shared.logging import get_logger
from ..shared.models import Severity, Vulnerability

logger = get_logger("code_scanner")


@dataclass
class CodePattern:
    id: str
    title: str
    pattern: str
    severity: Severity
    category: str
    description: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    languages: List[str] = field(default_factory=lambda: ["any"])
    _compiled: Optional[Pattern[str]] = field(default=None, repr=False, compare=False)

    def compile(self) -> Pattern[str]:
        if self._compiled is None:
            flags = re.IGNORECASE | re.MULTILINE
            self._compiled = re.compile(self.pattern, flags)
        return self._compiled


VULN_PATTERNS: List[CodePattern] = [
    # ── SQL Injection ─────────────────────────────────────────────────────────
    CodePattern(
        id="sqli-001",
        title="SQL Injection via String Concatenation",
        pattern=r"""(?:execute|query|raw|cursor\.execute)\s*\(\s*(?:f['""]|['""].*?\+|.*?%\s*\(|.*?\.format)""",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        description="Detected SQL query built with string concatenation or formatting which can allow SQL injection.",
        remediation="Use parameterised queries / prepared statements. Pass user input as bind parameters, not inline strings.",
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        languages=["python", "javascript", "php", "java"],
    ),
    CodePattern(
        id="sqli-002",
        title="Raw SQL with User Input",
        pattern=r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*?(?:\+\s*\w+|\{\w+\}|%s|\$\{)""",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        description="Raw SQL statement appears to include dynamic user-controlled content.",
        remediation="Replace dynamic SQL with ORM queries or parameterised statements.",
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
    ),
    # ── XSS ──────────────────────────────────────────────────────────────────
    CodePattern(
        id="xss-001",
        title="Cross-Site Scripting (innerHTML)",
        pattern=r"""\.innerHTML\s*=\s*(?!["']<)""",
        severity=Severity.HIGH,
        category="XSS",
        description="Setting innerHTML with potentially unsanitized content can lead to XSS.",
        remediation="Use textContent instead of innerHTML, or sanitize with DOMPurify before assigning.",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        languages=["javascript", "typescript"],
    ),
    CodePattern(
        id="xss-002",
        title="Cross-Site Scripting (document.write)",
        pattern=r"""document\.write\s*\(""",
        severity=Severity.HIGH,
        category="XSS",
        description="document.write() with dynamic content is a classic XSS vector.",
        remediation="Avoid document.write(); use DOM manipulation methods instead.",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        languages=["javascript"],
    ),
    CodePattern(
        id="xss-003",
        title="Unsafe Template Rendering (Jinja2 mark_safe / autoescape off)",
        pattern=r"""(?:mark_safe|Markup|autoescape\s*=\s*False|\.html_safe)""",
        severity=Severity.HIGH,
        category="XSS",
        description="Disabling auto-escaping or marking content as safe without sanitisation risks XSS.",
        remediation="Enable Jinja2 autoescape or explicitly sanitise HTML before marking safe.",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        languages=["python"],
    ),
    # ── Command Injection ─────────────────────────────────────────────────────
    CodePattern(
        id="cmdi-001",
        title="Command Injection via shell=True",
        pattern=r"""subprocess\.[a-z_]+\s*\(.*?shell\s*=\s*True""",
        severity=Severity.CRITICAL,
        category="Command Injection",
        description="Using shell=True with subprocess and dynamic input allows OS command injection.",
        remediation="Pass a list of arguments to subprocess and avoid shell=True. Validate and sanitize all inputs.",
        cwe_id="CWE-78",
        owasp_category="A03:2021 - Injection",
        languages=["python"],
    ),
    CodePattern(
        id="cmdi-002",
        title="OS Command Execution (os.system)",
        pattern=r"""os\.(?:system|popen|execv?[ep]?)\s*\(""",
        severity=Severity.HIGH,
        category="Command Injection",
        description="os.system/popen/exec with dynamic input can lead to command injection.",
        remediation="Replace with subprocess.run() using a list of arguments, never shell=True with user input.",
        cwe_id="CWE-78",
        owasp_category="A03:2021 - Injection",
        languages=["python"],
    ),
    CodePattern(
        id="cmdi-003",
        title="eval() Usage",
        pattern=r"""\beval\s*\(""",
        severity=Severity.CRITICAL,
        category="Command Injection",
        description="eval() executes arbitrary code and is extremely dangerous with user input.",
        remediation="Never use eval() on user-supplied data. Use literal_eval() for data parsing or structured parsers.",
        cwe_id="CWE-78",
        owasp_category="A03:2021 - Injection",
    ),
    CodePattern(
        id="cmdi-004",
        title="exec() Usage",
        pattern=r"""\bexec\s*\(""",
        severity=Severity.HIGH,
        category="Command Injection",
        description="exec() can execute arbitrary Python code, dangerous with untrusted input.",
        remediation="Remove exec() calls. Use explicit function dispatch or safe configuration.",
        cwe_id="CWE-78",
        owasp_category="A03:2021 - Injection",
        languages=["python"],
    ),
    # ── Path Traversal ────────────────────────────────────────────────────────
    CodePattern(
        id="path-001",
        title="Path Traversal (open with user input)",
        pattern=r"""open\s*\(\s*(?:request|req|user|input|param|query|args|data)""",
        severity=Severity.HIGH,
        category="Path Traversal",
        description="Opening files using user-controlled paths can allow directory traversal attacks.",
        remediation="Resolve and validate paths against an allowed base directory using os.path.realpath().",
        cwe_id="CWE-22",
        owasp_category="A01:2021 - Broken Access Control",
        languages=["python"],
    ),
    CodePattern(
        id="path-002",
        title="Path Traversal Pattern (../)",
        pattern=r"""(?:\.\./|\.\.\\)""",
        severity=Severity.MEDIUM,
        category="Path Traversal",
        description="Relative path traversal sequence detected in code.",
        remediation="Sanitize file paths and use os.path.abspath() / Path.resolve() to prevent traversal.",
        cwe_id="CWE-22",
        owasp_category="A01:2021 - Broken Access Control",
    ),
    # ── Insecure Crypto ───────────────────────────────────────────────────────
    CodePattern(
        id="crypto-001",
        title="Insecure Hash Algorithm (MD5)",
        pattern=r"""(?:hashlib\.md5|MD5\s*\(|new\s*\(\s*['""]md5['""])""",
        severity=Severity.MEDIUM,
        category="Insecure Cryptography",
        description="MD5 is cryptographically broken and should not be used for security purposes.",
        remediation="Replace MD5 with SHA-256 or SHA-3 for security purposes. MD5 is acceptable only for non-security checksums.",
        cwe_id="CWE-327",
        owasp_category="A02:2021 - Cryptographic Failures",
    ),
    CodePattern(
        id="crypto-002",
        title="Insecure Hash Algorithm (SHA-1)",
        pattern=r"""(?:hashlib\.sha1|SHA1\s*\(|new\s*\(\s*['""]sha1['""])""",
        severity=Severity.MEDIUM,
        category="Insecure Cryptography",
        description="SHA-1 is deprecated and collision-vulnerable. Do not use for digital signatures.",
        remediation="Upgrade to SHA-256 or SHA-3.",
        cwe_id="CWE-327",
        owasp_category="A02:2021 - Cryptographic Failures",
    ),
    CodePattern(
        id="crypto-003",
        title="Hardcoded Encryption Key",
        pattern=r"""(?i)(?:secret_key|encryption_key|aes_key|cipher_key)\s*=\s*["'][^"']{8,}["']""",
        severity=Severity.CRITICAL,
        category="Insecure Cryptography",
        description="Encryption key is hardcoded in source code.",
        remediation="Load encryption keys from environment variables or a secrets manager (Vault, AWS Secrets Manager).",
        cwe_id="CWE-321",
        owasp_category="A02:2021 - Cryptographic Failures",
    ),
    CodePattern(
        id="crypto-004",
        title="Insecure Random Number Generation",
        pattern=r"""\brandom\.(?:random|randint|choice|shuffle)\b""",
        severity=Severity.MEDIUM,
        category="Insecure Cryptography",
        description="Python's random module is not cryptographically secure.",
        remediation="Use secrets module or os.urandom() for security-sensitive random generation.",
        cwe_id="CWE-338",
        owasp_category="A02:2021 - Cryptographic Failures",
        languages=["python"],
    ),
    # ── Hardcoded Credentials ─────────────────────────────────────────────────
    CodePattern(
        id="hardcred-001",
        title="Hardcoded Admin Credentials",
        pattern=r"""(?i)(?:admin|root|administrator)\s*[:=]\s*["'][^"']{1,32}["']""",
        severity=Severity.HIGH,
        category="Hardcoded Credentials",
        description="Hardcoded administrative credentials detected.",
        remediation="Remove hardcoded credentials; use environment variables and secrets management.",
        cwe_id="CWE-798",
        owasp_category="A07:2021 - Identification and Authentication Failures",
    ),
    # ── Deserialization ───────────────────────────────────────────────────────
    CodePattern(
        id="deser-001",
        title="Unsafe Pickle Deserialization",
        pattern=r"""pickle\.(?:load|loads|Unpickler)""",
        severity=Severity.CRITICAL,
        category="Insecure Deserialization",
        description="Pickle deserialization of untrusted data can lead to arbitrary code execution.",
        remediation="Never unpickle data from untrusted sources. Use JSON, MessagePack, or other safe formats.",
        cwe_id="CWE-502",
        owasp_category="A08:2021 - Software and Data Integrity Failures",
        languages=["python"],
    ),
    CodePattern(
        id="deser-002",
        title="Unsafe YAML Load",
        pattern=r"""yaml\.load\s*\([^)]*(?:Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader)|(?<!\w)None)""",
        severity=Severity.HIGH,
        category="Insecure Deserialization",
        description="yaml.load() with an unsafe loader can execute arbitrary Python code.",
        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead.",
        cwe_id="CWE-502",
        owasp_category="A08:2021 - Software and Data Integrity Failures",
        languages=["python"],
    ),
    # ── SSRF ──────────────────────────────────────────────────────────────────
    CodePattern(
        id="ssrf-001",
        title="Potential SSRF (requests with user-controlled URL)",
        pattern=r"""requests\.[a-z]+\s*\(\s*(?:url\s*=\s*)?(?:request|req|user|input|param|query|args|data|url)""",
        severity=Severity.HIGH,
        category="SSRF",
        description="Making HTTP requests with user-supplied URLs can enable Server-Side Request Forgery.",
        remediation="Validate and whitelist URLs before making server-side requests. Block internal IP ranges.",
        cwe_id="CWE-918",
        owasp_category="A10:2021 - Server-Side Request Forgery",
        languages=["python"],
    ),
    # ── Buffer Overflow (C/C++) ───────────────────────────────────────────────
    CodePattern(
        id="bof-001",
        title="Unsafe strcpy / strcat (C/C++)",
        pattern=r"""\b(?:strcpy|strcat|sprintf|gets|scanf)\s*\(""",
        severity=Severity.HIGH,
        category="Buffer Overflow",
        description="Unsafe C string functions that do not perform bounds checking.",
        remediation="Replace with safe alternatives: strncpy, strncat, snprintf, fgets.",
        cwe_id="CWE-120",
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
        languages=["c", "cpp"],
    ),
    # ── XXE ───────────────────────────────────────────────────────────────────
    CodePattern(
        id="xxe-001",
        title="XXE - Unsafe XML Parsing",
        pattern=r"""(?:etree\.parse|minidom\.parseString|lxml\.etree\.parse|xml\.dom\.minidom)""",
        severity=Severity.HIGH,
        category="XXE",
        description="XML parsing without disabling external entity processing can lead to XXE attacks.",
        remediation="Disable external entity processing: use defusedxml or configure parser with resolve_entities=False.",
        cwe_id="CWE-611",
        owasp_category="A05:2021 - Security Misconfiguration",
        languages=["python"],
    ),
    # ── Insecure Direct Object Reference ─────────────────────────────────────
    CodePattern(
        id="idor-001",
        title="IDOR - Direct Object Reference without Authorization",
        pattern=r"""(?:get_object_or_404|Model\.objects\.get|findById|getById)\s*\([^)]*(?:id|pk)\s*=\s*(?:request|req)""",
        severity=Severity.HIGH,
        category="IDOR",
        description="Direct database lookups using user-supplied IDs without authorization checks.",
        remediation="Always verify the requesting user is authorized to access the requested object.",
        cwe_id="CWE-639",
        owasp_category="A01:2021 - Broken Access Control",
    ),
    # ── Weak TLS/SSL ──────────────────────────────────────────────────────────
    CodePattern(
        id="tls-001",
        title="SSL Certificate Verification Disabled",
        pattern=r"""verify\s*=\s*False""",
        severity=Severity.HIGH,
        category="Insecure TLS",
        description="Disabling SSL certificate verification allows man-in-the-middle attacks.",
        remediation="Enable certificate verification (verify=True) and use trusted CA bundles.",
        cwe_id="CWE-295",
        owasp_category="A02:2021 - Cryptographic Failures",
    ),
]


def _short_id(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:8]


class CodeScanner:
    """Perform static analysis on source code for security vulnerabilities."""

    def __init__(self) -> None:
        self._compiled: Dict[str, Pattern[str]] = {
            p.id: p.compile() for p in VULN_PATTERNS
        }

    def scan(self, code: str, file_path: str = "<stdin>", language: str = "python") -> List[Vulnerability]:
        """Scan code and return a list of vulnerabilities."""
        findings: List[Vulnerability] = []

        for pattern_def in VULN_PATTERNS:
            if "any" not in pattern_def.languages and language not in pattern_def.languages:
                continue
            compiled = self._compiled[pattern_def.id]
            for match in compiled.finditer(code):
                line_num = code[: match.start()].count("\n") + 1
                snippet = _extract_snippet(code, line_num)
                vuln_id = f"vuln-{pattern_def.id}-{_short_id(file_path + str(line_num))}"
                findings.append(
                    Vulnerability(
                        id=vuln_id,
                        title=pattern_def.title,
                        description=pattern_def.description,
                        severity=pattern_def.severity,
                        category=pattern_def.category,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet,
                        remediation=pattern_def.remediation,
                        cwe_id=pattern_def.cwe_id,
                        owasp_category=pattern_def.owasp_category,
                    )
                )

        deduplicated = _deduplicate(findings)
        logger.info("Code scan complete file=%s findings=%d", file_path, len(deduplicated))
        return deduplicated


def _extract_snippet(code: str, line_num: int, context: int = 2) -> str:
    lines = code.splitlines()
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    return "\n".join(lines[start:end])


def _deduplicate(vulns: List[Vulnerability]) -> List[Vulnerability]:
    seen: set[str] = set()
    result: List[Vulnerability] = []
    for v in vulns:
        if v.id not in seen:
            seen.add(v.id)
            result.append(v)
    return result
