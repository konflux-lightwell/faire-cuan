from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from faire_cuan import ToolError
from faire_cuan.tools import skopeo


@pytest.fixture()
def docker_config(tmp_path: Path) -> Path:
    return tmp_path / ".docker"


class TestCopy:
    def test_succeeds_silently(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            skopeo.copy("docker://src", "docker://dst", docker_config=docker_config)

    def test_override_os_option(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc) as mock_run:
            skopeo.copy("docker://src", "docker://dst", override_os="linux", docker_config=docker_config)
        assert "--override-os" in mock_run.call_args[0][0]

        with patch("subprocess.run", return_value=proc) as mock_run:
            skopeo.copy("docker://src", "docker://dst", docker_config=docker_config)
        assert "--override-os" not in mock_run.call_args[0][0]

    def test_raises_tool_error_on_failure(self, docker_config: Path):
        proc = CompletedProcess(args=[], returncode=1, stdout="", stderr="connection refused")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolError, match="connection refused"):
                skopeo.copy("docker://src", "docker://dst", docker_config=docker_config)
