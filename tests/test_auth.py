from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from faire_cuan import ToolError
from faire_cuan.auth import create_docker_auth, home_docker_config, setup_ca_bundle


class TestSetupCaBundle:
    def test_sets_env_var_when_file_exists(self, tmp_path, monkeypatch):
        ca_file = tmp_path / "ca-bundle.crt"
        ca_file.write_text("CERT DATA")
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)

        setup_ca_bundle(ca_file)

        import os

        assert os.environ["SSL_CERT_FILE"] == str(ca_file)

    def test_does_nothing_when_path_is_none(self, monkeypatch):
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)

        setup_ca_bundle(None)

        import os

        assert "SSL_CERT_FILE" not in os.environ

    def test_does_nothing_when_file_does_not_exist(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)

        setup_ca_bundle(tmp_path / "nonexistent.crt")

        import os

        assert "SSL_CERT_FILE" not in os.environ


class TestCreateDockerAuth:
    def test_writes_config_json_on_success(self, tmp_path):
        auth_dir = tmp_path / "docker-auth"
        auth_json = '{"auths": {"registry.example.com": {"auth": "dXNlcjpwYXNz"}}}'

        with patch("faire_cuan.auth.subprocess.run") as mock_run:
            mock_run.return_value = CompletedProcess(
                args=[],
                returncode=0,
                stdout=auth_json,
                stderr="",
            )

            result = create_docker_auth("registry.example.com/image@sha256:abc", auth_dir)

        assert result == auth_dir
        assert (auth_dir / "config.json").read_text() == auth_json

    def test_raises_tool_error_on_failure(self, tmp_path):
        with patch("faire_cuan.auth.subprocess.run") as mock_run:
            mock_run.return_value = CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="auth failed",
            )

            with pytest.raises(ToolError, match="auth failed"):
                create_docker_auth("img@sha256:abc", tmp_path / "auth")


class TestHomeDockerConfig:
    def test_returns_home_docker_path(self):
        assert home_docker_config() == Path.home() / ".docker"
