from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from faire_cuan import ToolError
from faire_cuan.tools import openssl


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    return tmp_path / "pub.pem"


class TestComputeKeyFingerprint:
    def test_produces_correct_format(self, key_file: Path):
        der_bytes = b"test-public-key-der-content"
        proc = CompletedProcess(args=[], returncode=0, stdout=der_bytes, stderr=b"")
        with patch("subprocess.run", return_value=proc):
            result = openssl.compute_key_fingerprint(key_file)

        expected_digest = hashlib.sha256(der_bytes).digest()
        expected_b64 = base64.b64encode(expected_digest).decode().rstrip("=")
        assert result == f"SHA256:{expected_b64}"

    def test_strips_base64_padding(self, key_file: Path):
        der_bytes = b"x" * 10
        proc = CompletedProcess(args=[], returncode=0, stdout=der_bytes, stderr=b"")
        with patch("subprocess.run", return_value=proc):
            result = openssl.compute_key_fingerprint(key_file)

        assert "=" not in result

    def test_raises_tool_error_on_failure(self, key_file: Path):
        proc = CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"invalid PEM format")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="invalid PEM format"):
                openssl.compute_key_fingerprint(key_file)
