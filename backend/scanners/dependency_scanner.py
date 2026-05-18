"""Dependency vulnerability scanner using the OSV.dev API."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any, Dict, List, Optional

import httpx

from ..shared.config import get_settings
from ..shared.logging import get_logger
from ..shared.models import CVEInfo, Dependency, Severity

logger = get_logger("dependency_scanner")

SEVERITY_MAP: Dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}


def _map_severity(raw: str) -> Severity:
    return SEVERITY_MAP.get(raw.upper(), Severity.MEDIUM)


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _extract_cve_ids(vuln: Dict[str, Any]) -> List[str]:
    """Pull CVE aliases from an OSV vulnerability record."""
    aliases = vuln.get("aliases", [])
    return [a for a in aliases if a.startswith("CVE-")]


def _extract_severity(vuln: Dict[str, Any]) -> Severity:
    """Determine severity from CVSS or database_specific fields."""
    for severity_entry in vuln.get("severity", []):
        score_str = severity_entry.get("score", "")
        if score_str:
            try:
                score = float(score_str.split("/")[0] if "/" in score_str else score_str)
                return _cvss_to_severity(score)
            except ValueError:
                pass

    for db_specific in [vuln.get("database_specific", {}), vuln.get("affected", [{}])[0].get("database_specific", {})] if vuln.get("affected") else [vuln.get("database_specific", {})]:
        raw = db_specific.get("severity") or db_specific.get("cvss_score")
        if raw:
            if isinstance(raw, (int, float)):
                return _cvss_to_severity(float(raw))
            return _map_severity(str(raw))
    return Severity.MEDIUM


class DependencyScanner:
    """Check pip/npm packages for known CVEs using the OSV.dev API."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.base_url = self.settings.osv_api_url

    async def scan_package(
        self, name: str, version: str, ecosystem: str = "PyPI"
    ) -> Dependency:
        """Query OSV.dev for vulnerabilities in a single package."""
        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": ecosystem},
        }

        vulns: List[CVEInfo] = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(f"{self.base_url}/query", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.warning("OSV API request failed package=%s version=%s error=%s", name, version, exc)
            data = {}

        for vuln in data.get("vulns", []):
            cve_ids = _extract_cve_ids(vuln)
            severity = _extract_severity(vuln)
            cve_id = cve_ids[0] if cve_ids else vuln.get("id", "UNKNOWN")

            refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]
            vulns.append(
                CVEInfo(
                    cve_id=cve_id,
                    summary=vuln.get("summary", "No summary available"),
                    severity=severity,
                    published=vuln.get("published"),
                    references=refs[:5],
                )
            )

        risk_score = _compute_risk(vulns)
        logger.debug("Package scanned name=%s version=%s vulns=%d", name, version, len(vulns))
        return Dependency(
            name=name,
            version=version,
            ecosystem=ecosystem,
            vulnerabilities=vulns,
            risk_score=risk_score,
        )

    async def scan_packages(
        self, packages: List[Dict[str, str]], ecosystem: str = "PyPI"
    ) -> List[Dependency]:
        """Scan multiple packages concurrently."""
        tasks = [
            self.scan_package(
                pkg["name"], pkg.get("version", ""), ecosystem=pkg.get("ecosystem", ecosystem)
            )
            for pkg in packages
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        deps: List[Dependency] = []
        for pkg, result in zip(packages, results):
            if isinstance(result, Exception):
                logger.error("Failed to scan package %s: %s", pkg.get("name"), result)
                deps.append(Dependency(name=pkg["name"], version=pkg.get("version", ""), ecosystem=ecosystem))
            else:
                deps.append(result)
        return deps

    async def batch_query(self, packages: List[Dict[str, str]], ecosystem: str = "PyPI") -> List[Dependency]:
        """Use OSV batch query endpoint for efficiency when scanning many packages."""
        queries = [
            {
                "version": pkg.get("version", ""),
                "package": {"name": pkg["name"], "ecosystem": pkg.get("ecosystem", ecosystem)},
            }
            for pkg in packages
        ]
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(f"{self.base_url}/querybatch", json={"queries": queries})
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.warning("OSV batch query failed error=%s — falling back to individual queries", exc)
            return await self.scan_packages(packages, ecosystem)

        deps: List[Dependency] = []
        for pkg, result in zip(packages, data.get("results", [])):
            vulns = []
            for vuln in result.get("vulns", []):
                cve_ids = _extract_cve_ids(vuln)
                severity = _extract_severity(vuln)
                cve_id = cve_ids[0] if cve_ids else vuln.get("id", "UNKNOWN")
                refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]
                vulns.append(
                    CVEInfo(
                        cve_id=cve_id,
                        summary=vuln.get("summary", "No summary available"),
                        severity=severity,
                        published=vuln.get("published"),
                        references=refs[:5],
                    )
                )
            deps.append(
                Dependency(
                    name=pkg["name"],
                    version=pkg.get("version", ""),
                    ecosystem=pkg.get("ecosystem", ecosystem),
                    vulnerabilities=vulns,
                    risk_score=_compute_risk(vulns),
                )
            )
        return deps


def _compute_risk(vulns: List[CVEInfo]) -> float:
    """Compute a normalised risk score 0–10 based on vulnerability severities."""
    if not vulns:
        return 0.0
    weights = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}
    total = sum(weights.get(v.severity, 0) for v in vulns)
    return min(10.0, total / max(len(vulns), 1))


def parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Parse a requirements.txt file into a list of {name, version} dicts."""
    packages: List[Dict[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if sep in line:
                name, _, version = line.partition(sep)
                packages.append({"name": name.strip(), "version": version.strip().split(",")[0]})
                break
        else:
            packages.append({"name": line, "version": ""})
    return packages


def parse_package_json(data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract dependencies from a parsed package.json dict."""
    packages: List[Dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in data.get(section, {}).items():
            clean_version = version.lstrip("^~>=<")
            packages.append({"name": name, "version": clean_version, "ecosystem": "npm"})
    return packages
