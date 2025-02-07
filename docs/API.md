# CyberShield AI API Reference

Base URL: `http://localhost:8000`

> All scanning endpoints accept code as strings. For authorized security testing only.

## Health

### GET /health
```json
{"status": "ok", "service": "CyberShield AI"}
```

## Scanning

### POST /api/v1/scan/secrets
Scan code for secrets and credentials.

**Request:**
```json
{
  "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
  "filename": "config.py"
}
```

**Response:**
```json
{
  "findings": [
    {
      "type": "aws_access_key",
      "severity": "critical",
      "line": 1,
      "match": "AKIA...",
      "description": "AWS Access Key ID detected"
    }
  ]
}
```

### POST /api/v1/scan/code
Static security analysis.

**Request:**
```json
{
  "code": "query = f'SELECT * FROM users WHERE id={user_id}'",
  "language": "python"
}
```

### POST /api/v1/scan/dependencies
Check dependencies for CVEs.

**Request:**
```json
{
  "packages": [{"name": "requests", "version": "2.25.0", "ecosystem": "PyPI"}]
}
```

### POST /api/v1/review/code
AI-powered security review.

**Request:**
```json
{
  "code": "...",
  "language": "python",
  "context": "web API endpoint"
}
```

### POST /api/v1/remediation
Get fix for a vulnerability.

**Request:**
```json
{
  "vulnerability_type": "sql_injection",
  "code": "...",
  "language": "python"
}
```

### POST /api/v1/cve/explain
```json
{"cve_id": "CVE-2021-44228"}
```

### POST /api/v1/report/generate
Generate HTML security report from findings array.

### POST /api/v1/chat
AI security assistant chat.

## WebSocket

### WS /ws/scan/{scan_id}
Real-time scan progress stream.
