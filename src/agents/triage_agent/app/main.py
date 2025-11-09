"""Triage Agent: Risk scoring and GitHub integration."""
import json
import logging
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from google.cloud import firestore

from github_app import create_check_run, format_pr_comment, post_pr_comment
from risk import aggregate_findings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "module": "%(name)s"}',
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Triage Agent")

# Environment variables
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
FIRESTORE_COLLECTION = os.getenv("FIRESTORE_COLLECTION", "agni_findings")
GITHUB_OWNER = os.getenv("GITHUB_OWNER")
GITHUB_REPO = os.getenv("GITHUB_REPO")

# Initialize Firestore
db = None
if GCP_PROJECT_ID:
    db = firestore.Client(project=GCP_PROJECT_ID)


@app.get("/healthz")
async def healthz():
    """Health check endpoint."""
    if not GCP_PROJECT_ID:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "reason": "GCP_PROJECT_ID not configured"},
        )
    return {"status": "healthy"}


@app.post("/triage")
async def triage_endpoint(request: Request):
    """
    Triage endpoint: aggregate findings, score risk, post to GitHub.
    
    Body: {
        "pr_number": "...",
        "commit_sha": "...",
        "owner": "...",  # optional, uses env var if not provided
        "repo": "...",   # optional, uses env var if not provided
    }
    """
    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    
    pr_number = payload.get("pr_number")
    commit_sha = payload.get("commit_sha")
    owner = payload.get("owner") or GITHUB_OWNER
    repo = payload.get("repo") or GITHUB_REPO
    
    if not all([pr_number, commit_sha]):
        raise HTTPException(
            status_code=400, detail="Missing pr_number or commit_sha"
        )
    
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not initialized")
    
    # Fetch scan and correlation documents
    scan_doc_id = f"scan_{pr_number}_{commit_sha}"
    correlation_doc_id = f"correlation_{pr_number}_{commit_sha}"
    
    scan_doc = db.collection(FIRESTORE_COLLECTION).document(scan_doc_id).get()
    correlation_doc = (
        db.collection(FIRESTORE_COLLECTION).document(correlation_doc_id).get()
    )
    
    if not scan_doc.exists:
        raise HTTPException(
            status_code=404, detail=f"Scan document not found: {scan_doc_id}"
        )
    
    if not correlation_doc.exists:
        raise HTTPException(
            status_code=404,
            detail=f"Correlation document not found: {correlation_doc_id}",
        )
    
    scan_data = scan_doc.to_dict()
    correlation_data = correlation_doc.to_dict()
    
    # Aggregate and score
    risk_score = aggregate_findings(scan_data, correlation_data)
    
    # Prepare key packages (those with vulnerabilities)
    components = correlation_data.get("components", [])
    key_packages = [
        comp
        for comp in components
        if comp.get("vulnerabilities") and len(comp.get("vulnerabilities", [])) > 0
    ]
    
    # Count CVEs
    total_cves = sum(
        len(comp.get("vulnerabilities", [])) for comp in components
    )
    
    # Count findings
    findings_count = len(scan_data.get("findings", []))
    
    # Format PR comment
    comment = format_pr_comment(
        risk_level=risk_score.level,
        risk_score=risk_score.score,
        key_packages=key_packages,
        cve_count=total_cves,
        findings_count=findings_count,
    )
    
    # Post to GitHub (if configured)
    pr_comment_success = False
    check_run_success = False
    
    if owner and repo:
        # Post PR comment
        pr_comment_success = await post_pr_comment(
            owner=owner,
            repo=repo,
            pr_number=int(pr_number),
            comment=comment,
        )
        
        # Create check run
        conclusion = "failure" if risk_score.level == "high" else "success"
        check_summary = f"Risk Level: {risk_score.level.upper()} (Score: {risk_score.score:.1f})\n\n{total_cves} CVEs found, {findings_count} semantic findings."
        
        check_run_success = await create_check_run(
            owner=owner,
            repo=repo,
            commit_sha=commit_sha,
            conclusion=conclusion,
            summary=check_summary,
        )
    else:
        logger.warning("GitHub owner/repo not configured, skipping GitHub integration")
    
    # Persist triage result
    triage_doc_id = f"triage_{pr_number}_{commit_sha}"
    triage_data = {
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "risk_score": risk_score.score,
        "risk_level": risk_score.level,
        "breakdown": risk_score.breakdown,
        "cve_count": total_cves,
        "findings_count": findings_count,
        "github_comment_posted": pr_comment_success,
        "github_check_run_created": check_run_success,
        "type": "triage",
    }
    
    db.collection(FIRESTORE_COLLECTION).document(triage_doc_id).set(triage_data)
    
    return {
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "risk_score": risk_score.score,
        "risk_level": risk_score.level,
        "breakdown": risk_score.breakdown,
        "cve_count": total_cves,
        "findings_count": findings_count,
        "github_comment_posted": pr_comment_success,
        "github_check_run_created": check_run_success,
    }


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
