"""CyberShield AI — FastAPI backend entry point."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from .ai.cve_explainer import CVEExplainer
from .ai.remediation import RemediationEngine
from .ai.security_assistant import SecurityAssistant
from .scanners.code_scanner import CodeScanner
from .scanners.dependency_scanner import DependencyScanner, parse_requirements_txt
from .scanners.owasp_scanner import OWASPScanner
from .scanners.report_generator import ReportGenerator
from .scanners.secret_scanner import SecretScanner
from .shared.config import get_settings
from .shared.logging import get_logger, setup_logging
from .shared.models import (
    ChatRequest,
    CVERequest,
    DependencyRequest,
    RemediationRequest,
    ReportRequest,
    ScanRequest,
    ScanResult,
    ScanStatus,
    Vulnerability,
)
from .tools.bearer_runner import BearerRunner
from .tools.gitleaks_runner import GitleaksRunner
from .tools.trufflehog_runner import TruffleHogRunner

# ── Bootstrap ──────────────────────────────────────────────────────────────────
setup_logging()
logger = get_logger("main")
settings = get_settings()

app = FastAPI(
    title="CyberShield AI",
    description="AI-powered cybersecurity copilot for code analysis, secret detection, and vulnerability scanning.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Singletons ─────────────────────────────────────────────────────────────────
_secret_scanner = SecretScanner()
_code_scanner = CodeScanner()
_dep_scanner = DependencyScanner()
_owasp_scanner = OWASPScanner()
_report_gen = ReportGenerator()
_assistant = SecurityAssistant()
_remediation = RemediationEngine()
_cve_explainer = CVEExplainer()
_gitleaks = GitleaksRunner()
_trufflehog = TruffleHogRunner()
_bearer = BearerRunner()

# ── In-memory scan store (replace with Redis in production) ────────────────────
_scan_store: Dict[str, Any] = {}


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "service": "CyberShield AI",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/api/v1/tools/status", tags=["System"])
async def tools_status() -> Dict[str, Any]:
    """Return availability of external security tools."""
    return {
        "gitleaks": _gitleaks.is_available,
        "trufflehog": _trufflehog.is_available,
        "bearer": _bearer.is_available,
        "ai_provider": settings.ai_provider,
        "ai_configured": bool(settings.openai_api_key or settings.anthropic_api_key),
    }


# ── Secret Scanning ────────────────────────────────────────────────────────────

@app.post("/api/v1/scan/secrets", tags=["Scanning"])
async def scan_secrets(request: ScanRequest) -> Dict[str, Any]:
    """Scan code or files for secrets and credentials."""
    scan_id = request.scan_id or str(uuid.uuid4())

    if not request.code and not request.file_path:
        raise HTTPException(status_code=400, detail="Provide 'code' or 'file_path'")

    code = request.code or ""
    file_path = request.file_path or "<stdin>"

    # Use gitleaks if available, otherwise built-in scanner
    secrets = _gitleaks.scan_text(code, file_path=file_path)

    # Supplement with TruffleHog for entropy detection
    if _trufflehog.is_available:
        th_secrets = _trufflehog.scan_text(code, file_path=file_path)
        secrets.extend(th_secrets)

    result = {
        "scan_id": scan_id,
        "status": ScanStatus.COMPLETED,
        "secrets": [s.model_dump() for s in secrets],
        "count": len(secrets),
        "scanner": "gitleaks" if _gitleaks.is_available else "built-in",
    }
    _scan_store[scan_id] = result
    logger.info("Secret scan complete scan_id=%s count=%d", scan_id, len(secrets))
    return result


# ── Code Scanning ──────────────────────────────────────────────────────────────

@app.post("/api/v1/scan/code", tags=["Scanning"])
async def scan_code(request: ScanRequest) -> Dict[str, Any]:
    """Static security analysis of submitted source code."""
    scan_id = request.scan_id or str(uuid.uuid4())

    if not request.code:
        raise HTTPException(status_code=400, detail="Provide 'code' field")

    language = (request.language or "python").lower()
    file_path = request.file_path or f"<stdin.{language}>"

    # Use Bearer if available, otherwise built-in scanner
    vulns = _bearer.scan_code(request.code, file_path=file_path, language=language)

    result = {
        "scan_id": scan_id,
        "status": ScanStatus.COMPLETED,
        "vulnerabilities": [v.model_dump() for v in vulns],
        "count": len(vulns),
        "summary": _severity_summary(vulns),
        "scanner": "bearer" if _bearer.is_available else "built-in",
    }
    _scan_store[scan_id] = result
    logger.info("Code scan complete scan_id=%s vulns=%d", scan_id, len(vulns))
    return result


# ── Dependency Scanning ────────────────────────────────────────────────────────

@app.post("/api/v1/scan/dependencies", tags=["Scanning"])
async def scan_dependencies(request: DependencyRequest) -> Dict[str, Any]:
    """Check pip/npm dependencies for known CVEs via OSV.dev."""
    scan_id = str(uuid.uuid4())

    if not request.dependencies:
        raise HTTPException(status_code=400, detail="Provide at least one dependency")

    deps = await _dep_scanner.batch_query(request.dependencies, ecosystem=request.ecosystem)

    vulnerable = [d for d in deps if d.vulnerabilities]
    result = {
        "scan_id": scan_id,
        "status": ScanStatus.COMPLETED,
        "ecosystem": request.ecosystem,
        "total_packages": len(deps),
        "vulnerable_packages": len(vulnerable),
        "dependencies": [d.model_dump() for d in deps],
    }
    logger.info(
        "Dependency scan complete scan_id=%s total=%d vulnerable=%d",
        scan_id, len(deps), len(vulnerable),
    )
    return result


@app.post("/api/v1/scan/dependencies/requirements", tags=["Scanning"])
async def scan_requirements_file(file: UploadFile) -> Dict[str, Any]:
    """Upload a requirements.txt and get CVE analysis."""
    content = (await file.read()).decode("utf-8", errors="ignore")
    packages = parse_requirements_txt(content)
    if not packages:
        raise HTTPException(status_code=400, detail="No packages found in requirements file")

    scan_id = str(uuid.uuid4())
    deps = await _dep_scanner.batch_query(packages, ecosystem="PyPI")
    vulnerable = [d for d in deps if d.vulnerabilities]
    return {
        "scan_id": scan_id,
        "status": ScanStatus.COMPLETED,
        "total_packages": len(deps),
        "vulnerable_packages": len(vulnerable),
        "dependencies": [d.model_dump() for d in deps],
    }


# ── OWASP Scanning ─────────────────────────────────────────────────────────────

@app.post("/api/v1/scan/owasp", tags=["Scanning"])
async def scan_owasp(request: ScanRequest) -> Dict[str, Any]:
    """Run OWASP Top 10 (2021) checks on submitted code."""
    scan_id = request.scan_id or str(uuid.uuid4())

    if not request.code:
        raise HTTPException(status_code=400, detail="Provide 'code' field")

    result = _owasp_scanner.scan(request.code, scan_id=scan_id)
    logger.info(
        "OWASP scan complete scan_id=%s passed=%d failed=%d",
        scan_id, result.passed, result.failed,
    )
    return result.model_dump()


# ── AI Code Review ─────────────────────────────────────────────────────────────

class CodeReviewRequest(BaseModel):
    code: str
    language: Optional[str] = "python"
    context: Optional[str] = None


@app.post("/api/v1/review/code", tags=["AI"])
async def ai_code_review(request: CodeReviewRequest) -> Dict[str, Any]:
    """AI-powered security-focused code review."""
    from .shared.models import ChatMessage

    prompt = (
        f"Please perform a thorough security code review of the following "
        f"{request.language} code. Identify all security vulnerabilities, "
        f"classify them by OWASP category and CWE ID, and provide specific "
        f"remediation for each finding.\n\n"
        f"```{request.language}\n{request.code}\n```"
    )
    if request.context:
        prompt += f"\n\nAdditional context: {request.context}"

    messages = [ChatMessage(role="user", content=prompt)]
    review = await _assistant.chat(messages)

    # Also run static analysis for structured findings
    vulns = _bearer.scan_code(request.code, language=request.language or "python")

    return {
        "ai_review": review,
        "static_findings": [v.model_dump() for v in vulns],
        "static_count": len(vulns),
    }


# ── Remediation ────────────────────────────────────────────────────────────────

@app.post("/api/v1/remediation", tags=["AI"])
async def get_remediation(request: RemediationRequest) -> Dict[str, Any]:
    """Get AI-generated fix suggestion for a detected vulnerability."""
    fix = await _remediation.suggest_fix(request)
    return {
        "vulnerability_id": request.vulnerability.id,
        "vulnerability_title": request.vulnerability.title,
        "language": request.language,
        "remediation": fix,
    }


# ── CVE Explanation ────────────────────────────────────────────────────────────

@app.post("/api/v1/cve/explain", tags=["AI"])
async def explain_cve(request: CVERequest) -> Dict[str, Any]:
    """Explain a CVE in plain English with attack scenarios and mitigations."""
    return await _cve_explainer.explain(
        request.cve_id, include_technical=request.include_technical
    )


# ── Report Generation ──────────────────────────────────────────────────────────

@app.post("/api/v1/report/generate", tags=["Reports"])
async def generate_report(request: ReportRequest) -> Dict[str, Any]:
    """Generate an HTML or PDF security report from scan results."""
    if request.format.lower() == "pdf":
        path = _report_gen.save_pdf(request)
        media_type = "application/pdf"
    else:
        path = _report_gen.save_html(request)
        media_type = "text/html"

    return {
        "scan_id": request.scan_id,
        "format": request.format,
        "report_path": path,
        "download_url": f"/api/v1/report/{request.scan_id}/{request.format}",
    }


@app.get("/api/v1/report/{scan_id}/html", tags=["Reports"])
async def download_html_report(scan_id: str) -> HTMLResponse:
    """Download a generated HTML report."""
    import os
    from pathlib import Path
    path = Path(settings.report_output_dir) / f"report_{scan_id}.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return HTMLResponse(content=path.read_text(encoding="utf-8"))


@app.get("/api/v1/report/{scan_id}/pdf", tags=["Reports"])
async def download_pdf_report(scan_id: str) -> FileResponse:
    """Download a generated PDF report."""
    from pathlib import Path
    path = Path(settings.report_output_dir) / f"report_{scan_id}.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="PDF report not found")
    return FileResponse(str(path), media_type="application/pdf")


# ── AI Chat ────────────────────────────────────────────────────────────────────

@app.post("/api/v1/chat", tags=["AI"])
async def chat(request: ChatRequest) -> Dict[str, Any]:
    """Chat with the AI security assistant."""
    response = await _assistant.chat(request.messages, context=request.context)
    return {"response": response, "provider": settings.ai_provider}


# ── WebSocket — Real-time Scan Progress ────────────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for real-time scan progress updates."""
    await websocket.accept()
    logger.info("WebSocket connected scan_id=%s", scan_id)

    try:
        data = await websocket.receive_json()
        code = data.get("code", "")
        language = data.get("language", "python")
        scan_types = data.get("scan_types", ["secrets", "code", "owasp"])

        total_steps = len(scan_types)
        completed = 0

        async def send_progress(step: str, pct: int, message: str, payload: Any = None) -> None:
            await websocket.send_json({
                "scan_id": scan_id,
                "step": step,
                "progress": pct,
                "message": message,
                "payload": payload,
            })

        results: Dict[str, Any] = {"scan_id": scan_id}

        if "secrets" in scan_types:
            await send_progress("secrets", 10, "Scanning for secrets and credentials...")
            secrets = _gitleaks.scan_text(code, file_path=f"ws-scan.{language}")
            results["secrets"] = [s.model_dump() for s in secrets]
            completed += 1
            pct = int((completed / total_steps) * 90) + 5
            await send_progress("secrets", pct, f"Found {len(secrets)} secret(s)", results["secrets"])

        if "code" in scan_types:
            await send_progress("code", int((completed / total_steps) * 90) + 5, "Running static analysis...")
            vulns = _bearer.scan_code(code, language=language)
            results["vulnerabilities"] = [v.model_dump() for v in vulns]
            completed += 1
            pct = int((completed / total_steps) * 90) + 5
            await send_progress("code", pct, f"Found {len(vulns)} vulnerability/ies", results["vulnerabilities"])

        if "owasp" in scan_types:
            await send_progress("owasp", int((completed / total_steps) * 90) + 5, "Running OWASP Top 10 checks...")
            owasp_result = _owasp_scanner.scan(code, scan_id=scan_id)
            results["owasp"] = owasp_result.model_dump()
            completed += 1
            await send_progress("owasp", 95, f"OWASP: {owasp_result.passed}/{owasp_result.total} passed", results["owasp"])

        _scan_store[scan_id] = results
        await send_progress("complete", 100, "Scan complete", results)

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected scan_id=%s", scan_id)
    except Exception as exc:
        logger.error("WebSocket error scan_id=%s error=%s", scan_id, exc)
        try:
            await websocket.send_json({"error": str(exc), "scan_id": scan_id})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _severity_summary(vulns: List[Vulnerability]) -> Dict[str, int]:
    summary: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        key = v.severity.value
        summary[key] = summary.get(key, 0) + 1
    return summary
