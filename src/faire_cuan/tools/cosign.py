from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Iterator
from pathlib import Path

from faire_cuan import ToolError

logger = logging.getLogger(__name__)


def verify(
    image: str,
    key_file: Path,
    *,
    oci11: bool = False,
    docker_config: Path,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        "cosign",
        "verify",
        "--key",
        str(key_file),
        "--insecure-ignore-tlog=true",
    ]
    if oci11:
        cmd.append("--experimental-oci11=true")
    cmd.append(image)

    return subprocess.run(cmd, capture_output=True, text=True, env=_env(docker_config))


def copy(source: str, dest: str, *, force: bool = True, docker_config: Path) -> None:
    cmd = ["cosign", "copy"]
    if force:
        cmd.append("--force")
    cmd.extend([source, dest])

    result = subprocess.run(cmd, capture_output=True, text=True, env=_env(docker_config))
    if result.returncode != 0:
        raise ToolError(f"cosign copy failed: {result.stderr}")


def download_attestation(image: str, *, docker_config: Path) -> Iterator[dict]:
    result = subprocess.run(
        ["cosign", "download", "attestation", image],
        capture_output=True,
        text=True,
        env=_env(docker_config),
    )
    if result.stderr:
        logger.warning("cosign download attestation stderr: %s", result.stderr)
    for line in result.stdout.strip().splitlines():
        if line:
            yield json.loads(line)


def attach_sbom(
    image: str,
    sbom_path: Path,
    *,
    sbom_type: str = "cyclonedx",
    docker_config: Path,
) -> None:
    cmd = [
        "cosign",
        "attach",
        "sbom",
        "--sbom",
        str(sbom_path),
        "--type",
        sbom_type,
        image,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=_env(docker_config))
    if result.returncode != 0:
        raise ToolError(f"cosign attach sbom failed: {result.stderr}")


def _env(docker_config: Path) -> dict[str, str]:
    import os

    env = os.environ.copy()
    env["DOCKER_CONFIG"] = str(docker_config)
    return env
