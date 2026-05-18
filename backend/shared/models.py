"""Shared Pydantic models for CyberShield AI."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class Secret(BaseModel):
    id: str
    type: str
    description: str
    masked_value: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    severity: Severity = Severity.CRITICAL
    confidence: float = 1.0


class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: str
    vulnerabilities: List[CVEInfo] = Field(default_factory=list)
    risk_score: float = 0.0


class CVEInfo(BaseModel):
    cve_id: str
    summary: str
    severity: Severity
    cvss_score: Optional[float] = None
    published: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    code: Optional[str] = None
    file_path: Optional[str] = None
    repository_url: Optional[str] = None
    language: Optional[str] = "python"
    scan_id: Optional[str] = None


class DependencyRequest(BaseModel):
    dependencies: List[Dict[str, str]]
    ecosystem: str = "PyPI"


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    context: Optional[str] = None


class RemediationRequest(BaseModel):
    vulnerability: Vulnerability
    code_context: Optional[str] = None
    language: Optional[str] = "python"


class CVERequest(BaseModel):
    cve_id: str
    include_technical: bool = True


class ReportRequest(BaseModel):
    scan_id: str
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    secrets: List[Secret] = Field(default_factory=list)
    dependencies: List[Dependency] = Field(default_factory=list)
    format: str = "html"
    title: Optional[str] = "CyberShield AI Security Report"


class ScanResult(BaseModel):
    scan_id: str
    status: ScanStatus
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    secrets: List[Secret] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)


class OWASPResult(BaseModel):
    scan_id: str
    checks: List[OWASPCheck] = Field(default_factory=list)
    passed: int = 0
    failed: int = 0
    total: int = 0


class OWASPCheck(BaseModel):
    category: str
    id: str
    description: str
    status: str
    findings: List[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM


# Fix forward references
Dependency.model_rebuild()
