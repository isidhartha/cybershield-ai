# CyberShield AI

**For authorized security testing and defensive use only. Always get permission before scanning systems you don't own.**

I built CyberShield AI because the security tools I kept using were either too narrow (one tool for secrets, another for CVEs, another for SAST) or too expensive. CyberShield pulls all of it into one place with an AI layer on top that actually explains what it finds in plain English, not just dumps a list of CVE numbers at you.

The target user is a developer who wants to check their own code before it ships — not a dedicated security team with enterprise tooling. It's self-hosted, runs in Docker, and gives you actionable output rather than walls of raw scanner output.

---

## What it scans

**Secrets and credentials** — Regex and entropy-based detection for API keys, tokens, private keys, connection strings, and passwords hardcoded anywhere in your codebase. It's caught AWS keys, GitHub PATs, Stripe secrets, database passwords — the things that show up in breach reports.

**Static code analysis** — Pattern matching against OWASP Top 10 vulnerabilities: SQL injection, command injection, XSS, path traversal, insecure deserialization, hardcoded credentials, weak crypto. Works across Python, JavaScript, TypeScript, Go, Java, and more.

**Dependency CVEs** — Reads your requirements files and package manifests, checks each dependency against the OSV.dev database, and tells you which packages have known vulnerabilities and how severe they are. No API key needed for this — OSV.dev is public.

**AI security review** — Goes beyond pattern matching. Sends your code to an AI model that understands context. It catches things like "this looks like a race condition that could allow privilege escalation" that a regex pattern would miss.

**Remediation suggestions** — For every finding, it tells you what to change. Not just "this is a SQL injection" but "replace this f-string with a parameterized query, here's the fixed version."

**Report generation** — Produces clean HTML security reports you can share or save. Useful when you need to show a security review to a client or a team lead.

---

## How to run it

**Prerequisites**: Docker and Docker Compose. An OpenAI API key for the AI analysis features (the scanner itself works without one).

**1. Clone the repo**

```bash
git clone https://github.com/isidhartha/cybershield-ai.git
cd cybershield-ai
```

**2. Configure**

```bash
cp .env.example .env
```

Add your API key to `.env`:

```
OPENAI_API_KEY=sk-your-key-here
```

**3. Start everything**

```bash
docker-compose up --build
```

**4. Open the dashboard**

Go to `http://localhost:3000`. Paste in code, a GitHub URL, or a file path and hit scan.

---

## Optional: Add external scanners

CyberShield has built-in scanners that work out of the box. If you have these tools installed on your system, it'll use them automatically for more comprehensive coverage:

```bash
# gitleaks — excellent for git history scanning
# Download from: https://github.com/gitleaks/gitleaks/releases

# trufflehog — high signal-to-noise secret detection
pip install trufflehog

# bearer — modern SAST with OWASP coverage
# macOS: brew install bearer/tap/bearer
# Linux: https://docs.bearer.com/reference/installation
```

If none of these are installed, the built-in scanners kick in automatically. You won't notice the difference for most use cases.

---

## API

Swagger UI at `http://localhost:8000/docs`.

```
POST /api/v1/scan/secrets      — Scan for hardcoded secrets
POST /api/v1/scan/code         — Static analysis for vulnerabilities
POST /api/v1/scan/dependencies — Check dependencies against CVE databases
POST /api/v1/scan/full         — Run all scanners at once
POST /api/v1/ai/review         — AI-powered security code review
POST /api/v1/report/generate   — Generate a security report
POST /api/v1/chat              — Security assistant chat
```

---

## Vulnerability categories

| Category | What it catches |
|---|---|
| Secrets | AWS keys, GitHub tokens, private keys, database passwords, any high-entropy string |
| Injection | SQL injection, command injection, path traversal, LDAP injection |
| Web | XSS, CSRF, open redirect, insecure headers, cookie flags |
| Auth | Hardcoded credentials, weak hashing, insecure session handling |
| Dependencies | Known CVEs from OSV.dev, outdated packages |

---

## Configuration

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | For AI analysis features | — |
| `REPORTS_DIR` | Where HTML reports are saved | `/app/reports` |
| `MAX_FILE_SIZE_MB` | Max file size for scanning | `10` |
| `SCAN_TIMEOUT` | Seconds before a scan is killed | `120` |

---

## License

MIT. Build on it, fork it, use it for your own security work.
