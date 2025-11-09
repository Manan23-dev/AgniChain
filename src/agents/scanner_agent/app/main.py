"""Scanner Agent: GPU-backed semantic security scanner."""
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Optional

from google.cloud import firestore
from google.cloud import pubsub_v1

from analyzer import analyze_codebase
from io_utils import ArchiveFetchError, extract_archive, fetch_archive
from sbom import generate_sbom

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "module": "%(name)s"}',
)
logger = logging.getLogger(__name__)

# Environment variables
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
FIRESTORE_COLLECTION = os.getenv("FIRESTORE_COLLECTION", "aegis_findings")
PUBSUB_TOPIC = os.getenv("PUBSUB_TOPIC", "aegis-scan-requests")
SAMPLE_MODE = os.getenv("SAMPLE_MODE", "false").lower() == "true"


def validate_env():
    """Validate required environment variables."""
    if not GCP_PROJECT_ID:
        raise ValueError("GCP_PROJECT_ID environment variable is required")
    return True


def persist_scan_result(
    pr_number: str,
    commit_sha: str,
    archive_url: str,
    archive_sha256: str,
    sbom_components: list,
    findings: list,
) -> str:
    """
    Persist scan result to Firestore.
    
    Returns:
        Document ID
    """
    db = firestore.Client(project=GCP_PROJECT_ID)
    
    # Prepare document
    doc_data = {
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "archive_url": archive_url,
        "archive_sha256": archive_sha256,
        "sbom_components": [comp.dict() for comp in sbom_components],
        "findings": [f.dict() for f in findings],
        "scan_timestamp": firestore.SERVER_TIMESTAMP,
        "type": "scan",
    }
    
    # Use PR+commit as document ID for deduplication
    doc_id = f"scan_{pr_number}_{commit_sha}"
    doc_ref = db.collection(FIRESTORE_COLLECTION).document(doc_id)
    doc_ref.set(doc_data)
    
    logger.info(f"Persisted scan result: {doc_id}")
    return doc_id


def publish_summary(pr_number: str, commit_sha: str, doc_id: str):
    """Publish scan summary to Pub/Sub."""
    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(GCP_PROJECT_ID, PUBSUB_TOPIC)
    
    message_data = {
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "scan_doc_id": doc_id,
        "event_type": "scan_complete",
    }
    
    future = publisher.publish(
        topic_path,
        json.dumps(message_data).encode("utf-8"),
    )
    future.result()  # Wait for publish
    
    logger.info(f"Published scan summary for PR {pr_number}")


async def run_scan(
    archive_url: str,
    pr_number: str,
    commit_sha: str,
) -> dict:
    """
    Run full scan workflow.
    
    Returns:
        Summary dict
    """
    logger.info(f"Starting scan for PR {pr_number}, commit {commit_sha}")
    
    # Fetch archive
    try:
        fetch_result = await fetch_archive(archive_url)
        logger.info(
            f"Fetched archive: {fetch_result.size_bytes} bytes, SHA256: {fetch_result.sha256}"
        )
    except ArchiveFetchError as e:
        logger.error(f"Archive fetch failed: {e}")
        raise
    
    # Extract archive
    try:
        extracted_dir = extract_archive(fetch_result.file_path)
        logger.info(f"Extracted archive to: {extracted_dir}")
    except Exception as e:
        logger.error(f"Archive extraction failed: {e}")
        raise
    
    # Generate SBOM
    try:
        sbom_components = generate_sbom(extracted_dir)
        logger.info(f"Generated SBOM: {len(sbom_components)} components")
    except Exception as e:
        logger.error(f"SBOM generation failed: {e}")
        sbom_components = []
    
    # Run semantic analysis
    try:
        sample_mode = SAMPLE_MODE
        findings = analyze_codebase(extracted_dir, sample_mode=sample_mode)
        logger.info(f"Analysis complete: {len(findings)} findings")
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        findings = []
    
    # Persist to Firestore
    try:
        doc_id = persist_scan_result(
            pr_number=pr_number,
            commit_sha=commit_sha,
            archive_url=archive_url,
            archive_sha256=fetch_result.sha256,
            sbom_components=sbom_components,
            findings=findings,
        )
    except Exception as e:
        logger.error(f"Failed to persist scan result: {e}")
        raise
    
    # Publish summary
    try:
        publish_summary(pr_number, commit_sha, doc_id)
    except Exception as e:
        logger.warning(f"Failed to publish summary: {e}")
        # Non-fatal
    
    return {
        "doc_id": doc_id,
        "components_count": len(sbom_components),
        "findings_count": len(findings),
        "archive_sha256": fetch_result.sha256,
    }


def main():
    """Main entry point for Cloud Run Job."""
    try:
        validate_env()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    
    # Read payload from environment or stdin
    scan_payload = os.getenv("SCAN_PAYLOAD")
    if not scan_payload:
        # Try reading from stdin
        try:
            scan_payload = sys.stdin.read()
        except Exception:
            pass
    
    if not scan_payload:
        logger.error("No SCAN_PAYLOAD provided")
        sys.exit(1)
    
    try:
        payload = json.loads(scan_payload)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON payload: {e}")
        sys.exit(1)
    
    archive_url = payload.get("archive_url")
    pr_number = payload.get("pr_number")
    commit_sha = payload.get("commit_sha")
    
    if not all([archive_url, pr_number, commit_sha]):
        logger.error("Missing required fields: archive_url, pr_number, commit_sha")
        sys.exit(1)
    
    # Run scan
    try:
        result = asyncio.run(run_scan(archive_url, pr_number, commit_sha))
        logger.info(f"Scan complete: {json.dumps(result)}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
