from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from faire_cuan import ValidationError, VerificationError
from faire_cuan.verify import run_verify


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    kf = tmp_path / "cosign.pub"
    kf.write_text("-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n")
    return kf


@pytest.fixture()
def _mock_auth(tmp_path: Path):
    with (
        patch("faire_cuan.verify.setup_ca_bundle"),
        patch("faire_cuan.verify.create_docker_auth", return_value=tmp_path / "auth"),
    ):
        yield


class TestInputValidation:
    def test_rejects_non_digest_pinned_image(self, key_file: Path):
        with pytest.raises(ValidationError, match="digest-pinned"):
            run_verify("registry.io/repo:latest", key_file)

    def test_rejects_key_file_with_no_keys(self, tmp_path: Path):
        key_file = tmp_path / "empty.pub"
        key_file.write_text("")
        with pytest.raises(ValidationError, match="found 0"):
            run_verify("img@sha256:abc", key_file)

    def test_rejects_key_file_with_multiple_keys(self, tmp_path: Path):
        key_file = tmp_path / "multi.pub"
        key_file.write_text(
            "-----BEGIN PUBLIC KEY-----\nA\n-----END PUBLIC KEY-----\n"
            "-----BEGIN PUBLIC KEY-----\nB\n-----END PUBLIC KEY-----\n"
        )
        with pytest.raises(ValidationError, match="found 2"):
            run_verify("img@sha256:abc", key_file)


@pytest.mark.usefixtures("_mock_auth")
class TestSignatureVerification:
    @patch("faire_cuan.verify.openssl.compute_key_fingerprint", return_value="SHA256:abc123")
    def test_oci11_succeeds(self, _mock_fp, key_file: Path):
        oci11_ok = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("faire_cuan.verify.cosign.verify", return_value=oci11_ok) as mock_verify:
            result = run_verify("img@sha256:abc", key_file)

        assert result.fingerprint == "SHA256:abc123"
        mock_verify.assert_called_once()
        assert mock_verify.call_args[1]["oci11"] is True

    @patch("faire_cuan.verify.openssl.compute_key_fingerprint", return_value="SHA256:abc123")
    def test_falls_back_to_tag_based(self, _mock_fp, key_file: Path):
        oci11_fail = CompletedProcess(args=[], returncode=1, stdout="", stderr="no oci referrer")
        tag_ok = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("faire_cuan.verify.cosign.verify", side_effect=[oci11_fail, tag_ok]) as mock_verify:
            result = run_verify("img@sha256:abc", key_file)

        assert result.fingerprint == "SHA256:abc123"
        assert mock_verify.call_count == 2
        assert mock_verify.call_args_list[1][1]["oci11"] is False

    @patch("faire_cuan.verify.openssl.compute_key_fingerprint", return_value="SHA256:abc123")
    def test_raises_verification_error_when_both_fail(self, _mock_fp, key_file: Path):
        oci11_fail = CompletedProcess(args=[], returncode=1, stdout="", stderr="oci11 error")
        tag_fail = CompletedProcess(args=[], returncode=1, stdout="", stderr="tag error")
        with patch("faire_cuan.verify.cosign.verify", side_effect=[oci11_fail, tag_fail]):
            with pytest.raises(VerificationError, match="OCI referrer error") as exc_info:
                run_verify("img@sha256:abc", key_file)

        assert "oci11 error" in str(exc_info.value)
        assert "tag error" in str(exc_info.value)
