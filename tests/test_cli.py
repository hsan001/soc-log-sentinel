"""
test_cli.py - Unit Tests for Command-Line Interface
"""

import os
import tempfile
import pytest
from sentinel.cli import main, create_parser


def test_cli_version(capsys):
    parser = create_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--version"])


def test_cli_no_args(capsys):
    result = main([])
    assert result == 1


def test_cli_missing_file():
    result = main(["nonexistent_file_path.log"])
    assert result == 1


def test_cli_sample_auth_evaluation():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auth_log = os.path.join(base, "samples", "auth.log")
    rules_dir = os.path.join(base, "rules")
    
    result = main(["--file", auth_log, "--rules", rules_dir, "--quiet"])
    assert result == 0


def test_cli_json_export():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auth_log = os.path.join(base, "samples", "auth.log")
    rules_dir = os.path.join(base, "rules")

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
        tmp_json = tmp.name

    try:
        result = main([
            auth_log,
            "--rules", rules_dir,
            "--export", "json",
            "-j", tmp_json,
            "--quiet"
        ])
        assert result == 0
        assert os.path.exists(tmp_json)
        assert os.path.getsize(tmp_json) > 50
    finally:
        if os.path.exists(tmp_json):
            os.remove(tmp_json)


def test_cli_threshold_override():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auth_log = os.path.join(base, "samples", "auth.log")
    rules_dir = os.path.join(base, "rules")

    result = main([
        auth_log,
        "--rules", rules_dir,
        "--threshold", "2",
        "--quiet"
    ])
    assert result == 0
