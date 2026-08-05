from __future__ import annotations

import base64
import hashlib
import subprocess
from pathlib import Path

from faire_cuan import ToolError


def compute_key_fingerprint(key_file: Path) -> str:
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(key_file), "-outform", "DER"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise ToolError(f"openssl pkey failed: {result.stderr.decode()}")

    digest = hashlib.sha256(result.stdout).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{b64}"
