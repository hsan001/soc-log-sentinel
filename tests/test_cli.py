import os
import json
import pytest
from src.cli import main


def test_cli_execution_with_samples(tmp_path):
    auth_file = tmp_path / "auth.log"
    auth_file.write_text(
        "Nov 05 10:15:10 host sshd[1]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
        "Nov 05 10:15:11 host sshd[1]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
        "Nov 05 10:15:12 host sshd[1]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
    )
    md_out = tmp_path / "out.md"
    json_out = tmp_path / "out.json"

    ret = main([
        str(auth_file),
        "-t", "2",
        "-m", str(md_out),
        "-j", str(json_out),
        "-q"
    ])
    assert ret == 0
    assert md_out.exists()
    assert json_out.exists()

    with open(json_out) as f:
        data = json.load(f)
        assert data["metadata"]["total_alerts"] == 1
        assert data["alerts"][0]["category"] == "SSH Brute-Force Attempt"


def test_cli_missing_file():
    ret = main(["non_existent_log_file_12345.log"])
    assert ret == 1
