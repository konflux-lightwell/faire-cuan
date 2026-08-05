from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from faire_cuan import ToolError


def manifest_fetch(image: str, *, docker_config: Path | None = None) -> dict:
    result = subprocess.run(
        ["oras", "manifest", "fetch", image],
        capture_output=True,
        text=True,
        env=_env(docker_config),
    )
    if result.returncode != 0:
        raise ToolError(f"oras manifest fetch failed: {result.stderr}")
    return json.loads(result.stdout)


def pull(image: str, output_dir: Path, *, docker_config: Path | None = None) -> Path:
    result = subprocess.run(
        [
            "oras",
            "pull",
            "--no-tty",
            "--output",
            str(output_dir),
            image,
            "--format",
            'go-template={{range .files}}{{.path}}{{"\\n"}}{{end}}',
        ],
        capture_output=True,
        text=True,
        env=_env(docker_config),
    )
    if result.returncode != 0:
        raise ToolError(f"oras pull failed: {result.stderr}")

    files = result.stdout.strip().splitlines()
    if not files:
        raise ToolError("oras pull returned no files")
    return output_dir / files[0]


def discover(
    image: str,
    *,
    artifact_type: str,
    docker_config: Path | None = None,
) -> dict:
    result = subprocess.run(
        [
            "oras",
            "discover",
            "--artifact-type",
            artifact_type,
            "--format",
            "json",
            image,
        ],
        capture_output=True,
        text=True,
        env=_env(docker_config),
    )
    if result.returncode != 0:
        raise ToolError(f"oras discover failed: {result.stderr}")
    return json.loads(result.stdout)


def attach(
    image: str,
    files: list[Path],
    *,
    artifact_type: str,
    cwd: Path | None = None,
    docker_config: Path | None = None,
) -> None:
    cmd = [
        "oras",
        "attach",
        "--no-tty",
        "--artifact-type",
        artifact_type,
        image,
    ]
    cmd.extend(str(f) for f in files)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=cwd,
        env=_env(docker_config),
    )
    if result.returncode != 0:
        raise ToolError(f"oras attach failed: {result.stderr}")


def _env(docker_config: Path | None) -> dict[str, str]:
    env = os.environ.copy()
    if docker_config:
        env["DOCKER_CONFIG"] = str(docker_config)
    return env
