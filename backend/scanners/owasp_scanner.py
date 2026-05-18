"""OWASP Top 10 (2021) checker for web application code."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..shared.logging import get_logger
from ..shared.models import OWASPCheck, OWASPResult, Severity

logger = get_logger("owasp_scanner")


@dataclass
class OWASPCheckDef:
    owasp_id: str
    category: str
    description: str
    patterns: List[Tuple[str, str]]  # (pattern, finding_description)
    severity: Severity = Severity.HIGH
    pass_when_empty: bool = True


OWASP_CHECKS: List[OWASPCheckDef] = [
    # A01 — Broken Access Control
    OWASPCheckDef(
        owasp_id="A01:2021",
        category="Broken Access Control",
        description="Checks for missing authorization, IDOR patterns, and directory traversal.",
        severity=Severity.CRITICAL,
        patterns=[
            (r"""(?i)@app\.route.*methods.*(?:'GET'|"GET")(?!.*login_required|.*@require_)""",
             "Route handler lacks authentication decorator"),
            (r"""\.objects\.get\(\s*(?:id|pk)\s*=\s*request""",
             "Direct object reference using user-supplied ID without owner check"),
            (r"""(?:\.\./|\.\.\\)""",
             "Path traversal sequence '../' detected"),
            (r"""allow_origins\s*=\s*\[?\s*['"]\*['"]\s*\]?""",
             "CORS configured with wildcard origin (*)"),
        ],
    ),
    # A02 — Cryptographic Failures
    OWASPCheckDef(
        owasp_id="A02:2021",
        category="Cryptographic Failures",
        description="Checks for weak algorithms, hardcoded keys, and unencrypted sensitive data.",
        severity=Severity.HIGH,
        patterns=[
            (r"""hashlib\.(?:md5|sha1)\b""", "Weak hash algorithm MD5/SHA-1 in use"),
            (r"""(?i)(?:secret_key|encryption_key)\s*=\s*["'][^"']{1,32}["']""",
             "Hardcoded cryptographic key detected"),
            (r"""verify\s*=\s*False""", "SSL/TLS certificate verification disabled"),
            (r"""\brandom\.(?:random|randint)\b""",
             "Non-cryptographic random used in security context"),
        ],
    ),
    # A03 — Injection
    OWASPCheckDef(
        owasp_id="A03:2021",
        category="Injection",
        description="Detects SQL injection, command injection, XSS, and template injection patterns.",
        severity=Severity.CRITICAL,
        patterns=[
            (r"""(?:execute|query|raw)\s*\(\s*(?:f['""]|['""].*\+)""",
             "SQL query built with string concatenation"),
            (r"""subprocess\.[a-z_]+\s*\(.*shell\s*=\s*True""",
             "Subprocess call with shell=True enables command injection"),
            (r"""\beval\s*\(""", "eval() usage — code injection risk"),
            (r"""\.innerHTML\s*=\s*(?!["']<)""", "innerHTML assignment — XSS risk"),
            (r"""pickle\.loads?\s*\(""", "Pickle deserialization — code execution risk"),
            (r"""yaml\.load\s*\(""", "yaml.load without SafeLoader — code execution risk"),
        ],
    ),
    # A04 — Insecure Design
    OWASPCheckDef(
        owasp_id="A04:2021",
        category="Insecure Design",
        description="Checks for missing rate limiting, insecure defaults, and weak validation.",
        severity=Severity.MEDIUM,
        patterns=[
            (r"""(?i)debug\s*=\s*True""", "Debug mode enabled in production code"),
            (r"""(?i)secret_key\s*=\s*["'](?:secret|changeme|dev|test|dummy)["']""",
             "Weak/default secret key in use"),
            (r"""(?i)allow_all|permit_all|no_auth""", "Permissive authorization pattern detected"),
        ],
    ),
    # A05 — Security Misconfiguration
    OWASPCheckDef(
        owasp_id="A05:2021",
        category="Security Misconfiguration",
        description="Detects insecure default configurations, verbose error messages, and open permissions.",
        severity=Severity.HIGH,
        patterns=[
            (r"""(?i)SHOW_ERRORS\s*=\s*True|DEBUG\s*=\s*True""",
             "Verbose error messages enabled"),
            (r"""(?i)(?:S3|Bucket|Container).*public|ACL\s*=\s*['"]public""",
             "Cloud storage configured as public"),
            (r"""chmod\s*\(\s*['""]?0?777['"]?""", "File permissions set to world-writable (777)"),
            (r"""(?i)default_permissions\s*=\s*["'](?:allow|all)["']""",
             "Default-allow permission policy detected"),
        ],
    ),
    # A06 — Vulnerable and Outdated Components
    OWASPCheckDef(
        owasp_id="A06:2021",
        category="Vulnerable and Outdated Components",
        description="Checks for known unsafe library calls and outdated patterns.",
        severity=Severity.HIGH,
        patterns=[
            (r"""\b(?:strcpy|strcat|gets|sprintf)\s*\(""",
             "Unsafe C string function without bounds checking"),
            (r"""import\s+(?:urllib2|httplib|cookielib)""",
             "Python 2 deprecated module import"),
        ],
    ),
    # A07 — Identification and Authentication Failures
    OWASPCheckDef(
        owasp_id="A07:2021",
        category="Identification and Authentication Failures",
        description="Detects weak authentication implementations and session management issues.",
        severity=Severity.HIGH,
        patterns=[
            (r"""(?i)password\s*==\s*["'][^"']{1,20}["']""",
             "Hardcoded password comparison"),
            (r"""(?i)session\.permanent\s*=\s*True(?!.*\blifetime\b)""",
             "Permanent session without explicit timeout"),
            (r"""(?i)(?:min_length|min_password_length)\s*=\s*[0-7]\b""",
             "Weak minimum password length (< 8 characters)"),
            (r"""(?i)brute.?force|rate.?limit(?!\s*=\s*\d)""",
             "Missing rate limiting for authentication endpoint"),
        ],
    ),
    # A08 — Software and Data Integrity Failures
    OWASPCheckDef(
        owasp_id="A08:2021",
        category="Software and Data Integrity Failures",
        description="Checks for insecure deserialization and missing integrity verification.",
        severity=Severity.HIGH,
        patterns=[
            (r"""pickle\.(?:load|loads|Unpickler)""",
             "Unsafe pickle deserialization"),
            (r"""(?i)integrity\s*=\s*["']?(?:none|false|0)["']?""",
             "Integrity checking explicitly disabled"),
            (r"""(?i)(?:from|import)\s+.*?(?:untrusted|unsafe)""",
             "Import from untrusted source"),
        ],
    ),
    # A09 — Security Logging and Monitoring Failures
    OWASPCheckDef(
        owasp_id="A09:2021",
        category="Security Logging and Monitoring Failures",
        description="Checks for missing security event logging.",
        severity=Severity.MEDIUM,
        patterns=[
            (r"""except\s+(?:Exception|BaseException)?\s*(?:as\s+\w+)?\s*:\s*\n\s*pass""",
             "Exception silently swallowed — security events may be lost"),
            (r"""logging\.disable\s*\(\s*logging\.CRITICAL\s*\)""",
             "All logging disabled programmatically"),
        ],
    ),
    # A10 — Server-Side Request Forgery
    OWASPCheckDef(
        owasp_id="A10:2021",
        category="Server-Side Request Forgery (SSRF)",
        description="Detects server-side HTTP requests built from user-controlled input.",
        severity=Severity.HIGH,
        patterns=[
            (r"""requests\.\w+\s*\(\s*(?:url\s*=\s*)?(?:request|req|user_url|target_url)""",
             "HTTP request URL derived from user input — potential SSRF"),
            (r"""urllib\.request\.urlopen\s*\(\s*(?:request|req|user|input)""",
             "urlopen with user-controlled URL — potential SSRF"),
        ],
    ),
]


class OWASPScanner:
    """Run OWASP Top 10 checks against source code."""

    def scan(self, code: str, scan_id: Optional[str] = None) -> OWASPResult:
        scan_id = scan_id or str(uuid.uuid4())
        checks: List[OWASPCheck] = []
        passed = 0
        failed = 0

        for check_def in OWASP_CHECKS:
            findings: List[str] = []
            for pattern, finding_desc in check_def.patterns:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(code):
                    line_num = code[: match.start()].count("\n") + 1
                    findings.append(f"Line {line_num}: {finding_desc}")

            status = "FAIL" if findings else "PASS"
            if findings:
                failed += 1
            else:
                passed += 1

            checks.append(
                OWASPCheck(
                    category=check_def.category,
                    id=check_def.owasp_id,
                    description=check_def.description,
                    status=status,
                    findings=findings,
                    severity=check_def.severity,
                )
            )

        logger.info(
            "OWASP scan complete scan_id=%s passed=%d failed=%d",
            scan_id, passed, failed,
        )
        return OWASPResult(
            scan_id=scan_id,
            checks=checks,
            passed=passed,
            failed=failed,
            total=passed + failed,
        )
