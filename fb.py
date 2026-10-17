#!/usr/bin/env python3
"""Audit a local password wordlist without contacting any online service."""

from __future__ import annotations

import argparse
import base64
import csv
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

DEFAULT_PASSWORD_FILE = Path(__file__).with_name("passwords.txt")
MIN_PASSWORD_LENGTH = 12
COMMON_PASSWORDS = {
    "123456",
    "[REDACTED]",
    "password",
    "qwerty",
    "letmein",
    "admin",
    "welcome",
}


LOCK_DIR = Path(os.environ.get("LOCK_DIR", "/tmp/password-auditor-locks"))


@contextmanager
def file_lock(resource: Path, exclusive: bool = False):
    """Hold an advisory process lock for a resource."""
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock_name = hashlib.sha256(str(resource.absolute()).encode("utf-8")).hexdigest() + ".lock"
    lock_path = LOCK_DIR / lock_name
    with lock_path.open("w", encoding="ascii") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
HASH_PREFIX = "scrypt$"


def hash_password(password: str) -> str:
    """Return a salted, memory-hard scrypt password hash."""
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii")
    encoded_digest = base64.urlsafe_b64encode(digest).decode("ascii")
    return f"{HASH_PREFIX}n=16384,r=8,p=1${encoded_salt}${encoded_digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a hash created by hash_password."""
    try:
        prefix, parameters, encoded_salt, encoded_digest = stored_hash.strip().split("$")
        if prefix != HASH_PREFIX.rstrip("$") or parameters != "n=16384,r=8,p=1":
            return False
        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        expected = base64.urlsafe_b64decode(encoded_digest.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def password_issues(password: str) -> list[str]:
    """Return policy issues for one password without exposing its value."""
    issues: list[str] = []
    lowered = password.casefold()
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append("too_short")
    if lowered in COMMON_PASSWORDS:
        issues.append("common")
    if not re.search(r"[a-z]", password):
        issues.append("missing_lowercase")
    if not re.search(r"[A-Z]", password):
        issues.append("missing_uppercase")
    if not re.search(r"\d", password):
        issues.append("missing_digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("missing_symbol")
    return issues


def audit_password_file(path: Path) -> tuple[int, int, dict[str, int]]:
    """Audit non-empty lines and return total, compliant, and issue counts."""
    if not path.is_file():
        raise FileNotFoundError(path)
    total = compliant = 0
    issue_counts: dict[str, int] = {}
    with file_lock(path):
        with path.open("r", encoding="utf-8", errors="replace") as password_file:
            for raw_password in password_file:
                password = raw_password.rstrip("\r\n")
                if not password:
                    continue
                total += 1
                issues = password_issues(password)
                if not issues:
                    compliant += 1
                for issue in issues:
                    issue_counts[issue] = issue_counts.get(issue, 0) + 1
    return total, compliant, issue_counts


def report_data(total: int, compliant: int, issues: dict[str, int]) -> dict[str, object]:
    """Build a serializable aggregate report without password values."""
    return {
        "audited_entries": total,
        "policy_compliant_entries": compliant,
        "entries_with_issues": total - compliant,
        "issue_counts": dict(sorted(issues.items())),
    }


def write_report(
    stream: TextIO, report: dict[str, object], output_format: str
) -> None:
    """Write an aggregate report as text, JSON, or CSV."""
    if output_format == "json":
        json.dump(report, stream, indent=2)
        stream.write("\n")
    elif output_format == "csv":
        writer = csv.writer(stream)
        writer.writerow(("metric", "value"))
        writer.writerow(("audited_entries", report["audited_entries"]))
        writer.writerow(("policy_compliant_entries", report["policy_compliant_entries"]))
        writer.writerow(("entries_with_issues", report["entries_with_issues"]))
        for issue, count in report["issue_counts"].items():
            writer.writerow((f"issue:{issue}", count))
    else:
        print(f"Audited entries: {report['audited_entries']}", file=stream)
        print(f"Policy-compliant entries: {report['policy_compliant_entries']}", file=stream)
        print(f"Entries with issues: {report['entries_with_issues']}", file=stream)
        if report["issue_counts"]:
            print("Issue counts:", file=stream)
            for issue, count in report["issue_counts"].items():
                print(f"  {issue}: {count}", file=stream)
        print("Rotate exposed credentials before production use; no network requests were made, and password values were not displayed.", file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a local password wordlist without attempting logins."
    )
    parser.add_argument("password_file", nargs="?", type=Path, default=DEFAULT_PASSWORD_FILE)
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--output", type=Path, help="write the aggregate report to a file")
    parser.add_argument("--hash", action="store_true", help="hash one password locally")
    parser.add_argument("--verify", metavar="HASH", help="verify one password against a stored hash")
    args = parser.parse_args(argv)

    if args.hash or args.verify:
        password = getpass.getpass("Password: ")
        if args.hash:
            print(hash_password(password))
            return 0
        result = verify_password(password, args.verify)
        print("valid" if result else "invalid")
        return 0 if result else 1

    try:
        total, compliant, issues = audit_password_file(args.password_file)
    except FileNotFoundError:
        parser.error(f"password file not found: {args.password_file}")
    report = report_data(total, compliant, issues)
    if args.output:
        with file_lock(args.output, exclusive=True):
            with args.output.open("w", encoding="utf-8", newline="") as output:
                write_report(output, report, args.format)
    else:
        write_report(sys.stdout, report, args.format)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
