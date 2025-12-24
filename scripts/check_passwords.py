#!/usr/bin/env python3
"""
Script to check for common password patterns in code.
"""
import re
import sys
from typing import List, Tuple


def check_password_patterns(content: str, filepath: str) -> List[Tuple[int, str]]:
    """Check content for common password patterns."""
    issues = []

    # Common password patterns to look for
    patterns = [
        (r'password\s*=\s*["\'][^"\']{1,10}["\']', "Possible weak password assignment"),
        (r'passwd\s*=\s*["\'][^"\']{1,10}["\']', "Possible weak password assignment"),
        (r'pwd\s*=\s*["\'][^"\']{1,10}["\']', "Possible weak password assignment"),
        (r'admin\s*:\s*["\'][^"\']{1,10}["\']', "Possible weak admin credentials"),
        (r'user\s*:\s*["\'][^"\']{1,10}["\']', "Possible weak user credentials"),
        (r'root\s*:\s*["\'][^"\']{1,10}["\']', "Possible weak root credentials"),
        (r"123456", "Common password pattern found"),
        (r"password123", "Common password pattern found"),
        (r"admin123", "Common password pattern found"),
        (r"qwerty", "Common password pattern found"),
        (r"letmein", "Common password pattern found"),
        (r"welcome", "Common password pattern found"),
        (r"monkey", "Common password pattern found"),
        (r"dragon", "Common password pattern found"),
        (r"abc123", "Common password pattern found"),
        (r"123456789", "Common password pattern found"),
        (r'password\s*=\s*["\']test["\']', "Test password found"),
        (r'password\s*=\s*["\']123["\']', "Weak numeric password found"),
        (r'password\s*=\s*["\']1234["\']', "Weak numeric password found"),
        (r'password\s*=\s*["\']12345["\']', "Weak numeric password found"),
    ]

    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern, message in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(
                    (line_num, f"{message} on line {line_num}: {line.strip()}")
                )

    return issues


def main():
    if len(sys.argv) < 2:
        print("Usage: python check_passwords.py <file_path>")
        sys.exit(1)

    filepath = sys.argv[1]

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        sys.exit(1)

    issues = check_password_patterns(content, filepath)

    for line_num, issue in issues:
        print(f"Password pattern found in {filepath}:{line_num}: {issue}")

    # Exit with error code if issues found
    if issues:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
