from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ImageInfo:
    image_url: str
    image_digest: str
    image_ref: str


@dataclass
class GitCoordinates:
    url: str
    commit: str


@dataclass
class ResultsOutput:
    image: ImageInfo
    git: GitCoordinates
    sbom_blob_url: str


def run_results(
    source_image: str,
    dest_image: str,
    workdir: Path,
    *,
    ca_bundle: Path | None = None,
) -> ResultsOutput:
    raise NotImplementedError
