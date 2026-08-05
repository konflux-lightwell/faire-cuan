from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from faire_cuan import ToolError
from faire_cuan.tools import oras


@pytest.fixture()
def docker_config(tmp_path: Path) -> Path:
    return tmp_path / ".docker"


class TestManifestFetch:
    def test_returns_parsed_json(self, docker_config: Path):
        manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        proc = CompletedProcess(args=[], returncode=0, stdout=json.dumps(manifest), stderr="")
        with patch("subprocess.run", return_value=proc):
            assert oras.manifest_fetch("img@sha256:abc", docker_config=docker_config) == manifest

    def test_raises_tool_error_on_failure(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="401 Unauthorized")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="401 Unauthorized"):
                oras.manifest_fetch("img@sha256:abc", docker_config=docker_config)


class TestPull:
    def test_returns_path_to_first_file(self, tmp_path: Path, docker_config: Path):
        output_dir = tmp_path / "output"
        proc = CompletedProcess(args=[], returncode=0, stdout="first.json\nsecond.json\n", stderr="")
        with patch("subprocess.run", return_value=proc):
            result = oras.pull("img@sha256:abc", output_dir, docker_config=docker_config)

        assert result == output_dir / "first.json"

    def test_raises_tool_error_on_failure(self, tmp_path: Path, docker_config: Path):
        output_dir = tmp_path / "output"
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="pull denied")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="oras pull failed"):
                oras.pull("img@sha256:abc", output_dir, docker_config=docker_config)

    def test_raises_tool_error_when_no_files_returned(self, tmp_path: Path, docker_config: Path):
        output_dir = tmp_path / "output"
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="no files"):
                oras.pull("img@sha256:abc", output_dir, docker_config=docker_config)


class TestDiscover:
    def test_returns_parsed_json(self, docker_config: Path):
        discovery = {"manifests": [{"digest": "sha256:abc"}]}
        proc = CompletedProcess(args=[], returncode=0, stdout=json.dumps(discovery), stderr="")
        with patch("subprocess.run", return_value=proc):
            assert oras.discover("img@sha256:abc", artifact_type="sbom", docker_config=docker_config) == discovery

    def test_raises_tool_error_on_failure(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="network timeout")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="network timeout"):
                oras.discover("img@sha256:abc", artifact_type="sbom", docker_config=docker_config)


class TestAttach:
    def test_succeeds_silently(self, tmp_path: Path, docker_config: Path):
        files = [tmp_path / "file.json"]
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            oras.attach("img@sha256:abc", files, artifact_type="sbom", docker_config=docker_config)

    def test_raises_tool_error_on_failure(self, tmp_path: Path, docker_config: Path):
        files = [tmp_path / "file.json"]
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="disk quota exceeded")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="disk quota exceeded"):
                oras.attach("img@sha256:abc", files, artifact_type="sbom", docker_config=docker_config)
