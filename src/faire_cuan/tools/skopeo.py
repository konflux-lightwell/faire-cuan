from __future__ import annotations

import os
import subprocess
from pathlib import Path

from faire_cuan import ToolError


def copy(
    source: str,
    dest: str,
    *,
    override_os: str | None = None,
    docker_config: Path | None = None,
) -> None:
    cmd = ["skopeo", "copy"]
    if override_os:
        cmd.extend(["--override-os", override_os])
    cmd.extend([source, dest])

    env = os.environ.copy()
    if docker_config:
        env["DOCKER_CONFIG"] = str(docker_config)

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise ToolError(f"skopeo copy failed: {result.stderr}")
