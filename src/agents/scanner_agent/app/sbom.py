"""SBOM generation from package manifests."""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel


class SBOMComponent(BaseModel):
    """SBOM component model."""
    name: str
    version: str
    ecosystem: str  # "npm", "pypi", "maven", etc.
    purl: Optional[str] = None  # Package URL


def normalize_version_range(version_spec: str) -> str:
    """
    Normalize version range to a single version for SBOM.
    
    Examples:
        "^1.2.3" -> "1.2.3"
        "~1.2.3" -> "1.2.3"
        ">=1.2.3,<2.0.0" -> "1.2.3"
        "1.2.3" -> "1.2.3"
    """
    # Remove whitespace
    version_spec = version_spec.strip()
    
    # Remove common range prefixes
    version_spec = re.sub(r"^[\^~>=<]+", "", version_spec)
    
    # Handle comma-separated ranges (take first)
    if "," in version_spec:
        version_spec = version_spec.split(",")[0].strip()
        version_spec = re.sub(r"^[\^~>=<]+", "", version_spec)
    
    # Extract version number pattern
    match = re.search(r"(\d+\.\d+\.\d+)", version_spec)
    if match:
        return match.group(1)
    
    # Fallback: return as-is if no pattern matches
    return version_spec


def parse_package_json(manifest_path: Path) -> List[SBOMComponent]:
    """
    Parse package.json and extract dependencies.
    
    Args:
        manifest_path: Path to package.json
        
    Returns:
        List of SBOM components
    """
    components = []
    
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Combine dependencies and devDependencies
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        deps.update(data.get("peerDependencies", {}))
        
        for name, version_spec in deps.items():
            normalized_version = normalize_version_range(version_spec)
            purl = f"pkg:npm/{name}@{normalized_version}"
            
            components.append(
                SBOMComponent(
                    name=name,
                    version=normalized_version,
                    ecosystem="npm",
                    purl=purl,
                )
            )
    except Exception as e:
        raise ValueError(f"Failed to parse package.json: {e}") from e
    
    return components


def parse_requirements_txt(manifest_path: Path) -> List[SBOMComponent]:
    """
    Parse requirements.txt and extract dependencies.
    
    Args:
        manifest_path: Path to requirements.txt
        
    Returns:
        List of SBOM components
    """
    components = []
    
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        for line in lines:
            # Skip comments and empty lines
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Remove inline comments
            if "#" in line:
                line = line.split("#")[0].strip()
            
            # Handle -r includes (skip for now)
            if line.startswith("-r") or line.startswith("--requirement"):
                continue
            
            # Parse package spec: name==version, name>=version, etc.
            # Pattern: package_name[==|>=|<=|>|<|~=]version
            parts = re.split(r"[=<>~!]+", line, maxsplit=1)
            if len(parts) >= 1:
                name = parts[0].strip()
                version = parts[1].strip() if len(parts) > 1 else "latest"
                
                # Normalize version
                normalized_version = normalize_version_range(version)
                purl = f"pkg:pypi/{name}@{normalized_version}"
                
                components.append(
                    SBOMComponent(
                        name=name,
                        version=normalized_version,
                        ecosystem="pypi",
                        purl=purl,
                    )
                )
    except Exception as e:
        raise ValueError(f"Failed to parse requirements.txt: {e}") from e
    
    return components


def generate_sbom(extracted_dir: str) -> List[SBOMComponent]:
    """
    Generate SBOM from extracted archive.
    
    Searches for package.json and requirements.txt files.
    
    Args:
        extracted_dir: Path to extracted archive directory
        
    Returns:
        List of SBOM components
    """
    components = []
    extracted_path = Path(extracted_dir)
    
    # Find package.json files
    for package_json in extracted_path.rglob("package.json"):
        try:
            components.extend(parse_package_json(package_json))
        except Exception as e:
            # Log but continue
            print(f"Warning: Failed to parse {package_json}: {e}")
    
    # Find requirements.txt files
    for req_txt in extracted_path.rglob("requirements.txt"):
        try:
            components.extend(parse_requirements_txt(req_txt))
        except Exception as e:
            # Log but continue
            print(f"Warning: Failed to parse {req_txt}: {e}")
    
    # Deduplicate by name+version+ecosystem
    seen = set()
    unique_components = []
    for comp in components:
        key = (comp.name, comp.version, comp.ecosystem)
        if key not in seen:
            seen.add(key)
            unique_components.append(comp)
    
    return unique_components

