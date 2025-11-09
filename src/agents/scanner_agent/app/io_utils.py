"""I/O utilities for archive fetching and file operations."""
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel


class ArchiveFetchResult(BaseModel):
    """Result of archive fetch operation."""
    file_path: str
    sha256: str
    size_bytes: int


class ArchiveFetchError(Exception):
    """Raised when archive fetch fails."""
    pass


# Default limits
MAX_ARCHIVE_SIZE_MB = 500
MAX_ARCHIVE_SIZE_BYTES = MAX_ARCHIVE_SIZE_MB * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 300


async def fetch_archive(
    archive_url: str,
    max_size_bytes: int = MAX_ARCHIVE_SIZE_BYTES,
    timeout_seconds: int = FETCH_TIMEOUT_SECONDS,
) -> ArchiveFetchResult:
    """
    Fetch archive from URL with size limit and timeout.
    
    Args:
        archive_url: URL to fetch
        max_size_bytes: Maximum allowed size
        timeout_seconds: Request timeout
        
    Returns:
        ArchiveFetchResult with file path, SHA256, and size
        
    Raises:
        ArchiveFetchError on failure
    """
    parsed = urlparse(archive_url)
    if not parsed.scheme or not parsed.netloc:
        raise ArchiveFetchError(f"Invalid URL: {archive_url}")
    
    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="aegis_scan_")
    
    # Determine filename from URL or use default
    filename = os.path.basename(parsed.path) or "archive.zip"
    file_path = os.path.join(temp_dir, filename)
    
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            async with client.stream("GET", archive_url) as response:
                response.raise_for_status()
                
                total_size = 0
                sha256_hash = hashlib.sha256()
                
                with open(file_path, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        total_size += len(chunk)
                        if total_size > max_size_bytes:
                            raise ArchiveFetchError(
                                f"Archive exceeds size limit: {max_size_bytes} bytes"
                            )
                        sha256_hash.update(chunk)
                        f.write(chunk)
        
        sha256_hex = sha256_hash.hexdigest()
        
        return ArchiveFetchResult(
            file_path=file_path,
            sha256=sha256_hex,
            size_bytes=total_size,
        )
    except httpx.HTTPError as e:
        raise ArchiveFetchError(f"HTTP error fetching archive: {e}") from e
    except Exception as e:
        raise ArchiveFetchError(f"Unexpected error fetching archive: {e}") from e


def extract_archive(file_path: str, extract_to: Optional[str] = None) -> str:
    """
    Extract archive to directory.
    
    Supports: .zip, .tar, .tar.gz, .tar.bz2
    
    Args:
        file_path: Path to archive
        extract_to: Destination directory (default: same dir as archive)
        
    Returns:
        Path to extracted directory
    """
    if extract_to is None:
        extract_to = os.path.join(os.path.dirname(file_path), "extracted")
    
    os.makedirs(extract_to, exist_ok=True)
    
    import zipfile
    import tarfile
    
    if file_path.endswith(".zip"):
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            zip_ref.extractall(extract_to)
    elif file_path.endswith(".tar.gz") or file_path.endswith(".tgz"):
        with tarfile.open(file_path, "r:gz") as tar_ref:
            tar_ref.extractall(extract_to)
    elif file_path.endswith(".tar.bz2"):
        with tarfile.open(file_path, "r:bz2") as tar_ref:
            tar_ref.extractall(extract_to)
    elif file_path.endswith(".tar"):
        with tarfile.open(file_path, "r:") as tar_ref:
            tar_ref.extractall(extract_to)
    else:
        raise ValueError(f"Unsupported archive format: {file_path}")
    
    return extract_to

