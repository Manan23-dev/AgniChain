"""Risk scoring logic."""
import os
from typing import List

from pydantic import BaseModel


class RiskScore(BaseModel):
    """Risk score model."""
    score: float
    level: str  # "high", "medium", "low"
    breakdown: dict


# Default thresholds (configurable via env)
HIGH_THRESHOLD = float(os.getenv("RISK_HIGH_THRESHOLD", "8.0"))
MEDIUM_THRESHOLD = float(os.getenv("RISK_MEDIUM_THRESHOLD", "4.0"))

# Weights
CVE_CRITICAL_WEIGHT = 3.0
CVE_HIGH_WEIGHT = 2.0
CVE_MEDIUM_WEIGHT = 1.0
CVE_LOW_WEIGHT = 0.5
DANGEROUS_PRIMITIVE_WEIGHT = 2.0
AFFECTED_FILES_WEIGHT = 0.5


def calculate_risk_score(
    cve_count_by_severity: dict,
    dangerous_findings_count: int,
    affected_files_count: int,
) -> RiskScore:
    """
    Calculate risk score from findings.
    
    Args:
        cve_count_by_severity: Dict with keys "CRITICAL", "HIGH", "MEDIUM", "LOW"
        dangerous_findings_count: Count of high-severity semantic findings
        affected_files_count: Number of files with issues
        
    Returns:
        RiskScore
    """
    # CVE contribution
    cve_score = (
        cve_count_by_severity.get("CRITICAL", 0) * CVE_CRITICAL_WEIGHT
        + cve_count_by_severity.get("HIGH", 0) * CVE_HIGH_WEIGHT
        + cve_count_by_severity.get("MEDIUM", 0) * CVE_MEDIUM_WEIGHT
        + cve_count_by_severity.get("LOW", 0) * CVE_LOW_WEIGHT
    )
    
    # Dangerous primitives contribution
    primitive_score = dangerous_findings_count * DANGEROUS_PRIMITIVE_WEIGHT
    
    # Affected files contribution (capped)
    files_score = min(affected_files_count, 10) * AFFECTED_FILES_WEIGHT
    
    total_score = cve_score + primitive_score + files_score
    
    # Determine level
    if total_score >= HIGH_THRESHOLD:
        level = "high"
    elif total_score >= MEDIUM_THRESHOLD:
        level = "medium"
    else:
        level = "low"
    
    return RiskScore(
        score=total_score,
        level=level,
        breakdown={
            "cve_score": cve_score,
            "primitive_score": primitive_score,
            "files_score": files_score,
            "cve_counts": cve_count_by_severity,
            "dangerous_findings": dangerous_findings_count,
            "affected_files": affected_files_count,
        },
    )


def aggregate_findings(scan_data: dict, correlation_data: dict) -> RiskScore:
    """
    Aggregate findings from scan and correlation data.
    
    Args:
        scan_data: Scan document data
        correlation_data: Correlation document data
        
    Returns:
        RiskScore
    """
    # Count CVEs by severity
    cve_count_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    components = correlation_data.get("components", [])
    for comp in components:
        vulns = comp.get("vulnerabilities", [])
        for vuln in vulns:
            severity = vuln.get("severity", "").upper()
            if severity in cve_count_by_severity:
                cve_count_by_severity[severity] += 1
            else:
                # Default to MEDIUM if unknown
                cve_count_by_severity["MEDIUM"] += 1
    
    # Count dangerous semantic findings
    findings = scan_data.get("findings", [])
    dangerous_findings = [f for f in findings if f.get("severity") == "high"]
    dangerous_findings_count = len(dangerous_findings)
    
    # Count affected files
    affected_files = set()
    for finding in findings:
        file_path = finding.get("file_path", "")
        if file_path:
            affected_files.add(file_path)
    affected_files_count = len(affected_files)
    
    return calculate_risk_score(
        cve_count_by_severity,
        dangerous_findings_count,
        affected_files_count,
    )

