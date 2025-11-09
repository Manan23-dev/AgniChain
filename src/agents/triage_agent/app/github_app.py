"""GitHub App integration for PR comments and check runs."""
import asyncio
import base64
import json
import logging
import os
import time
from typing import List, Optional

import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jwt import encode as jwt_encode

logger = logging.getLogger(__name__)

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_INSTALLATION_ID = os.getenv("GITHUB_INSTALLATION_ID")
GITHUB_PRIVATE_KEY_BASE64 = os.getenv("GITHUB_PRIVATE_KEY_BASE64")
GITHUB_API_BASE = "https://api.github.com"


def get_github_token() -> Optional[str]:
    """
    Generate GitHub App installation token.
    
    Returns:
        JWT token or None if credentials not configured
    """
    if not all([GITHUB_APP_ID, GITHUB_INSTALLATION_ID, GITHUB_PRIVATE_KEY_BASE64]):
        logger.warning("GitHub App credentials not fully configured")
        return None
    
    try:
        # Decode private key
        private_key_pem = base64.b64decode(GITHUB_PRIVATE_KEY_BASE64).decode("utf-8")
        
        # Parse key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
            backend=default_backend(),
        )
        
        # Generate JWT
        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued at (1 minute ago)
            "exp": now + 600,  # Expires in 10 minutes
            "iss": GITHUB_APP_ID,
        }
        
        jwt_token = jwt_encode(payload, private_key, algorithm="RS256")
        
        # Exchange for installation token
        async def fetch_installation_token():
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{GITHUB_API_BASE}/app/installations/{GITHUB_INSTALLATION_ID}/access_tokens",
                    headers={
                        "Authorization": f"Bearer {jwt_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                response.raise_for_status()
                data = response.json()
                return data.get("token")
        
        return asyncio.run(fetch_installation_token())
        
    except Exception as e:
        logger.error(f"Failed to get GitHub token: {e}", exc_info=True)
        return None


async def post_pr_comment(
    owner: str,
    repo: str,
    pr_number: int,
    comment: str,
) -> bool:
    """
    Post comment on PR.
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        comment: Comment body
        
    Returns:
        True if successful
    """
    token = get_github_token()
    if not token:
        logger.warning("Cannot post PR comment: no GitHub token")
        return False
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json={"body": comment},
            )
            response.raise_for_status()
            logger.info(f"Posted PR comment on {owner}/{repo}#{pr_number}")
            return True
    except Exception as e:
        logger.error(f"Failed to post PR comment: {e}", exc_info=True)
        return False


async def create_check_run(
    owner: str,
    repo: str,
    commit_sha: str,
    conclusion: str,  # "success", "failure", "neutral"
    summary: str,
    title: str = "Agni Chain Security Scan",
) -> bool:
    """
    Create GitHub check run.
    
    Args:
        owner: Repository owner
        repo: Repository name
        commit_sha: Commit SHA
        conclusion: Check conclusion
        summary: Check summary
        title: Check title
        
    Returns:
        True if successful
    """
    token = get_github_token()
    if not token:
        logger.warning("Cannot create check run: no GitHub token")
        return False
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{GITHUB_API_BASE}/repos/{owner}/{repo}/check-runs",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json={
                    "name": title,
                    "head_sha": commit_sha,
                    "status": "completed",
                    "conclusion": conclusion,
                    "output": {
                        "title": title,
                        "summary": summary,
                    },
                },
            )
            response.raise_for_status()
            logger.info(f"Created check run for {owner}/{repo}@{commit_sha}")
            return True
    except Exception as e:
        logger.error(f"Failed to create check run: {e}", exc_info=True)
        return False


def format_pr_comment(
    risk_level: str,
    risk_score: float,
    key_packages: List[dict],
    cve_count: int,
    findings_count: int,
) -> str:
    """
    Format PR comment with findings summary.
    
    Args:
        risk_level: Risk level (high/medium/low)
        risk_score: Risk score
        key_packages: List of packages with vulnerabilities
        cve_count: Total CVE count
        findings_count: Total semantic findings count
        
    Returns:
        Formatted comment markdown
    """
    emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(risk_level, "⚪")
    
    comment = f"""## {emoji} Agni Chain Security Scan

**Risk Level:** {risk_level.upper()} (Score: {risk_score:.1f})

### Summary
- **CVEs Found:** {cve_count}
- **Semantic Findings:** {findings_count}

### Key Packages with Vulnerabilities
"""
    
    for pkg in key_packages[:10]:  # Limit to top 10
        name = pkg.get("name", "unknown")
        version = pkg.get("version", "unknown")
        vuln_count = len(pkg.get("vulnerabilities", []))
        
        comment += f"- **{name}@{version}**: {vuln_count} vulnerability(ies)\n"
        
        # Add OSV links
        for vuln in pkg.get("vulnerabilities", [])[:3]:  # Top 3 per package
            vuln_id = vuln.get("id", "")
            if vuln_id:
                comment += f"  - [{vuln_id}](https://osv.dev/vulnerability/{vuln_id})\n"
    
    comment += """
### Recommendations
- Review and update vulnerable dependencies
- Address high-severity semantic findings
- Consider using dependency scanning in CI/CD

---
*Generated by Agni Chain Security Scanner*
"""
    
    return comment

