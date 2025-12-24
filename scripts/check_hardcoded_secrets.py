#!/usr/bin/env python3
"""
Script to check for hardcoded secrets in code.
"""
import re
import sys
from typing import List, Tuple

def check_hardcoded_secrets(content: str, filepath: str) -> List[Tuple[int, str]]:
    """Check content for hardcoded secrets."""
    issues = []
    
    # Patterns for common hardcoded secrets
    patterns = [
        # API keys
        (r'["\']([A-Za-z0-9]{32,})["\']', 'Possible hardcoded API key or token'),
        (r'["\']([A-Za-z0-9_]{20,})["\']', 'Possible hardcoded API key or token'),
        (r'["\']([A-Za-z0-9_]{30,})["\']', 'Possible hardcoded API key or token'),
        
        # AWS keys
        (r'AKIA[0-9A-Z]{16}', 'Possible AWS Access Key ID'),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Possible AWS Secret Access Key'),
        (r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Possible AWS Access Key ID'),
        
        # Google API keys
        (r'AIza[0-9A-Za-z_-]{35}', 'Possible Google API key'),
        (r'(?i)google[_-]?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Possible Google API key'),
        
        # Generic API keys
        (r'(?i)(api[_-]?key|secret|token)["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']', 'Possible hardcoded API key or token'),
        
        # Database credentials
        (r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{1,20}["\']', 'Possible hardcoded password'),
        (r'(?i)(user|username)["\']?\s*[:=]\s*["\'][^"\']{1,20}["\']', 'Possible hardcoded username'),
        
        # URLs with credentials
        (r'https?://[a-zA-Z0-9_-]+:[^@]+@', 'URL with hardcoded credentials'),
        
        # SSH keys
        (r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'Possible hardcoded private key'),
        (r'ssh-(rsa|dss|ed25519)', 'Possible hardcoded SSH key'),
        
        # JWT tokens
        (r'eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*', 'Possible hardcoded JWT token'),
        
        # Other sensitive patterns
        (r'(?i)(client[_-]?secret)["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Possible hardcoded client secret'),
        (r'(?i)(private[_-]?key)["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Possible hardcoded private key'),
        (r'(?i)(encryption[_-]?key)["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Possible hardcoded encryption key'),
    ]
    
    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        for pattern, message in patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                # Avoid false positives for common patterns
                matched_text = match.group(0).lower()
                
                # Skip common non-sensitive patterns
                if any(skip in matched_text for skip in [
                    'password123', 'test', 'example', 'sample', 'demo', 'placeholder',
                    'your_', 'my_', 'default', 'secret_key_base', 'development'
                ]):
                    continue
                
                # Skip if the matched text is part of a configuration assignment
                if 'os.getenv' in line.lower() or 'config.get' in line.lower():
                    continue
                
                issues.append((line_num, f"{message} on line {line_num}: {line.strip()}"))
    
    return issues

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_hardcoded_secrets.py <file_path>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        sys.exit(1)
    
    issues = check_hardcoded_secrets(content, filepath)
    
    for line_num, issue in issues:
        print(f"Hardcoded secret found in {filepath}:{line_num}: {issue}")
    
    # Exit with error code if issues found
    if issues:
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()