from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from faire_cuan import ToolError
from faire_cuan.tools import cosign


@pytest.fixture()
def docker_config(tmp_path: Path) -> Path:
    return tmp_path / ".docker"


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    return tmp_path / "cosign.pub"


class TestVerify:
    def test_returns_completed_process(self, key_file: Path, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            result = cosign.verify("img@sha256:abc", key_file, docker_config=docker_config)

        assert result is proc

    def test_nonzero_exit_code_returned_not_raised(self, key_file: Path, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="signature mismatch")
        with patch("subprocess.run", return_value=proc):
            result = cosign.verify("img@sha256:abc", key_file, docker_config=docker_config)

        assert result.returncode == 1

    def test_oci11_mode(self, key_file: Path, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc) as mock_run:
            cosign.verify("img@sha256:abc", key_file, oci11=True, docker_config=docker_config)
        assert "--experimental-oci11=true" in mock_run.call_args[0][0]

        with patch("subprocess.run", return_value=proc) as mock_run:
            cosign.verify("img@sha256:abc", key_file, oci11=False, docker_config=docker_config)
        assert "--experimental-oci11=true" not in mock_run.call_args[0][0]


class TestCopy:
    def test_succeeds_silently(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            cosign.copy("src", "dst", docker_config=docker_config)

    def test_raises_tool_error_on_failure(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="unauthorized access")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="unauthorized access"):
                cosign.copy("src", "dst", docker_config=docker_config)


class TestDownloadAttestation:
    def test_yields_parsed_json_objects(self, docker_config: Path):
        line1 = json.dumps({"payloadType": "application/vnd.in-toto+json"})
        line2 = json.dumps({"payloadType": "application/vnd.dsse+json"})
        proc = CompletedProcess(args=[], returncode=0, stdout=f"{line1}\n{line2}\n", stderr="")
        with patch("subprocess.run", return_value=proc):
            results = list(cosign.download_attestation("img@sha256:abc", docker_config=docker_config))

        assert len(results) == 2
        assert results[0]["payloadType"] == "application/vnd.in-toto+json"

    def test_empty_output_yields_nothing(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            assert list(cosign.download_attestation("img@sha256:abc", docker_config=docker_config)) == []

    def test_stderr_is_logged_not_raised(self, docker_config: Path, caplog):
        proc = CompletedProcess(args=[], returncode=0, stdout="{}\n", stderr="some warning")
        with caplog.at_level("WARNING", logger="faire_cuan.tools.cosign"):
            with patch("subprocess.run", return_value=proc):
                list(cosign.download_attestation("img@sha256:abc", docker_config=docker_config))

        assert "some warning" in caplog.text


class TestAttachSbom:
    def test_succeeds_silently(self, tmp_path: Path, docker_config: Path):
        sbom = tmp_path / "sbom.json"
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            cosign.attach_sbom("img@sha256:abc", sbom, docker_config=docker_config)

    def test_custom_sbom_type(self, tmp_path: Path, docker_config: Path):
        sbom = tmp_path / "sbom.spdx"
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc) as mock_run:
            cosign.attach_sbom("img@sha256:abc", sbom, sbom_type="spdx", docker_config=docker_config)

        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index("--type") + 1] == "spdx"

    def test_raises_tool_error_on_failure(self, tmp_path: Path, docker_config: Path):
        sbom = tmp_path / "sbom.json"
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="timeout exceeded")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="timeout exceeded"):
                cosign.attach_sbom("img@sha256:abc", sbom, docker_config=docker_config)
