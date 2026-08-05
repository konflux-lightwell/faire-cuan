from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class VerifyResult:
    fingerprint: str


def run_verify(source_image: str, key_file: Path, *, ca_bundle: Path | None = None) -> VerifyResult:
    raise NotImplementedError
