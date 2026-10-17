import json

import pytest

from fb import (
    LOCK_DIR,
    audit_password_file,
    hash_password,
    main,
    password_issues,
    report_data,
    verify_password,
    write_report,
)


def test_password_issues_detects_policy_failures():
    issues = password_issues("short")
    assert "too_short" in issues
    assert "missing_uppercase" in issues
    assert "missing_digit" in issues
    assert "missing_symbol" in issues


def test_hash_and_verify_password():
    stored_hash = hash_password("LongEnough!42")
    assert stored_hash.startswith("scrypt$")
    assert verify_password("LongEnough!42", stored_hash)
    assert not verify_password("wrong", stored_hash)


def test_strong_password_has_no_issues():
    assert password_issues("LongEnough!42") == []


def test_file_lock_directory_created(tmp_path):
    password_file = tmp_path / "locked-passwords.txt"
    password_file.write_text("LongEnough!42\n", encoding="utf-8")
    audit_password_file(password_file)
    assert LOCK_DIR.exists()


def test_audit_ignores_blank_lines(tmp_path):
    path = tmp_path / "passwords.txt"
    path.write_text("weak\n\nLongEnough!42\n", encoding="utf-8")
    assert audit_password_file(path)[:2] == (2, 1)


def test_json_report_contains_aggregate_data(tmp_path):
    path = tmp_path / "report.json"
    report = report_data(3, 1, {"too_short": 2})
    with path.open("w", encoding="utf-8") as stream:
        write_report(stream, report, "json")
    assert json.loads(path.read_text(encoding="utf-8"))["entries_with_issues"] == 2


def test_main_writes_csv_report(tmp_path):
    passwords = tmp_path / "passwords.txt"
    output = tmp_path / "report.csv"
    passwords.write_text("weak\nLongEnough!42\n", encoding="utf-8")
    assert main([str(passwords), "--format", "csv", "--output", str(output)]) == 0
    assert "audited_entries,2" in output.read_text(encoding="utf-8")
