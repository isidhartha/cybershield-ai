# CyberShield AI Architecture

## Overview

CyberShield AI is a modular security scanning platform with an AI analysis layer on top of multiple specialized scanners.

## Scanner Modules

### Secret Scanner
Regex-based detection for:
- Cloud provider keys (AWS, GCP, Azure)
- Source control tokens (GitHub, GitLab)
- Communication tokens (Slack, Discord)
- Generic API key patterns
- Private key blocks

### Code Scanner
Static analysis for OWASP Top 10:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection (SQL, Command, LDAP)
- A06: Vulnerable Components
- A07: Auth and Session failures

### Dependency Scanner
Uses OSV.dev API:
1. Parse requirements.txt / package.json / go.mod
2. Query `https://api.osv.dev/v1/query` for each package
3. Return CVEs with severity scores

### OWASP Scanner
Pattern matching against OWASP Top 10 categories in source code.

## AI Analysis Layer

After scanning, the AI layer:
1. Receives raw findings from all scanners
2. Deduplicates and prioritizes by severity
3. Generates plain-English explanations
4. Produces remediation code snippets
5. Estimates exploitability

## Report Generation

HTML reports generated with Jinja2 templates, styled with inline CSS for email compatibility.

## External Tool Integration

When external binaries are installed:
- `gitleaks` — called via subprocess, output parsed as JSON
- `trufflehog` — called via subprocess, output parsed as JSON
- `bearer` — called via subprocess, output parsed as JSON

Graceful fallback to built-in scanners when binaries are absent.
