from __future__ import annotations

import os
import subprocess
from pathlib import Path

from faire_cuan import ToolError


def setup_ca_bundle(ca_bundle: Path | None) -> None:
    if ca_bundle and ca_bundle.is_file():
        os.environ["SSL_CERT_FILE"] = str(ca_bundle)


def create_docker_auth(image_ref: str, auth_dir: Path) -> Path:
    result = subprocess.run(
        ["select-oci-auth", image_ref],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ToolError(f"select-oci-auth failed: {result.stderr}")

    auth_dir.mkdir(parents=True, exist_ok=True)
    config_path = auth_dir / "config.json"
    config_path.write_text(result.stdout)
    return auth_dir


def home_docker_config() -> Path:
    return Path.home() / ".docker"
