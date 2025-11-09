"""Semantic security analyzer for code patterns."""
import ast
import re
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel


class Finding(BaseModel):
    """Security finding model."""
    rule_id: str
    severity: str  # "high", "medium", "low"
    message: str
    file_path: str
    line_number: int
    code_snippet: Optional[str] = None


# Rule definitions
RULES = {
    "python": [
        {
            "id": "PY001",
            "severity": "high",
            "pattern": r"yaml\.load\s*\(",
            "message": "Unsafe yaml.load() without Loader parameter",
        },
        {
            "id": "PY002",
            "severity": "high",
            "pattern": r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True",
            "message": "subprocess with shell=True is dangerous",
        },
        {
            "id": "PY003",
            "severity": "high",
            "pattern": r"requests\.(get|post|put|delete)\s*\([^)]*verify\s*=\s*False",
            "message": "requests with verify=False disables SSL verification",
        },
    ],
    "javascript": [
        {
            "id": "JS001",
            "severity": "high",
            "pattern": r"child_process\.(exec|execSync)\s*\(",
            "message": "child_process.exec() can execute arbitrary commands",
        },
        {
            "id": "JS002",
            "severity": "high",
            "pattern": r"\beval\s*\(",
            "message": "eval() can execute arbitrary code",
        },
        {
            "id": "JS003",
            "severity": "medium",
            "pattern": r"http://[^\s\"']+",
            "message": "Insecure HTTP endpoint detected",
        },
    ],
}


def analyze_python_file(file_path: Path) -> List[Finding]:
    """Analyze Python file for security patterns."""
    findings = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            lines = content.split("\n")
        
        # Pattern-based scanning
        for rule in RULES["python"]:
            pattern = re.compile(rule["pattern"])
            for line_num, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            message=rule["message"],
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                        )
                    )
        
        # AST-based analysis for more complex patterns
        try:
            tree = ast.parse(content, filename=str(file_path))
            for node in ast.walk(tree):
                # Check for yaml.load without Loader
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if (
                            isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "yaml"
                            and node.func.attr == "load"
                        ):
                            # Check if Loader argument is present
                            has_loader = any(
                                kw.arg == "Loader" for kw in node.keywords
                            )
                            if not has_loader:
                                # Get line number
                                line_num = node.lineno
                                findings.append(
                                    Finding(
                                        rule_id="PY001",
                                        severity="high",
                                        message="Unsafe yaml.load() without Loader parameter",
                                        file_path=str(file_path),
                                        line_number=line_num,
                                        code_snippet=lines[line_num - 1].strip()[:100],
                                    )
                                )
        except SyntaxError:
            # Skip AST analysis if file has syntax errors
            pass
            
    except Exception as e:
        # Log but don't fail
        print(f"Warning: Failed to analyze {file_path}: {e}")
    
    return findings


def analyze_javascript_file(file_path: Path) -> List[Finding]:
    """Analyze JavaScript/TypeScript file for security patterns."""
    findings = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            lines = content.split("\n")
        
        for rule in RULES["javascript"]:
            pattern = re.compile(rule["pattern"])
            for line_num, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            message=rule["message"],
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                        )
                    )
    except Exception as e:
        print(f"Warning: Failed to analyze {file_path}: {e}")
    
    return findings


def analyze_codebase(extracted_dir: str, sample_mode: bool = False) -> List[Finding]:
    """
    Analyze codebase for security patterns.
    
    Args:
        extracted_dir: Path to extracted archive
        sample_mode: If True, return a deterministic sample finding
        
    Returns:
        List of findings
    """
    if sample_mode:
        # Return deterministic sample for smoke tests
        return [
            Finding(
                rule_id="SAMPLE001",
                severity="medium",
                message="Sample finding for smoke test",
                file_path="sample.py",
                line_number=1,
                code_snippet="sample code",
            )
        ]
    
    findings = []
    extracted_path = Path(extracted_dir)
    
    # Analyze Python files
    for py_file in extracted_path.rglob("*.py"):
        findings.extend(analyze_python_file(py_file))
    
    # Analyze JavaScript/TypeScript files
    for js_file in extracted_path.rglob("*.js"):
        findings.extend(analyze_javascript_file(js_file))
    for ts_file in extracted_path.rglob("*.ts"):
        findings.extend(analyze_javascript_file(ts_file))
    for jsx_file in extracted_path.rglob("*.jsx"):
        findings.extend(analyze_javascript_file(jsx_file))
    for tsx_file in extracted_path.rglob("*.tsx"):
        findings.extend(analyze_javascript_file(tsx_file))
    
    return findings

