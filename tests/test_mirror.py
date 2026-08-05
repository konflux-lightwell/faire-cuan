from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from faire_cuan.mirror import run_mirror


class TestRunMirror:
    @patch("faire_cuan.mirror.cosign.copy")
    @patch("faire_cuan.mirror.home_docker_config")
    @patch("faire_cuan.mirror.setup_ca_bundle")
    def test_copies_source_to_dest(self, mock_ca, mock_docker, mock_copy):
        mock_docker.return_value = Path.home() / ".docker"

        run_mirror("src@sha256:abc", "dest:latest")

        mock_copy.assert_called_once_with(
            "src@sha256:abc",
            "dest:latest",
            docker_config=Path.home() / ".docker",
        )

    @patch("faire_cuan.mirror.cosign.copy")
    @patch("faire_cuan.mirror.home_docker_config")
    @patch("faire_cuan.mirror.setup_ca_bundle")
    def test_sets_up_ca_bundle(self, mock_ca, mock_docker, mock_copy):
        mock_docker.return_value = Path.home() / ".docker"
        ca = Path("/certs/ca.crt")

        run_mirror("src@sha256:abc", "dest:latest", ca_bundle=ca)

        mock_ca.assert_called_once_with(ca)
