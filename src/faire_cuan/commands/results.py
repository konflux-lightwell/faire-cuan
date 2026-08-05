from __future__ import annotations

import argparse
from pathlib import Path

from faire_cuan.results import run_results
from faire_cuan.tekton import write_result


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("results", help="Extract results, SBOM, sources, and attestation data")
    parser.add_argument("--source-image", required=True, help="Digest-pinned source OCI image reference")
    parser.add_argument("--image", required=True, help="Destination image reference")
    parser.add_argument("--ca-bundle", type=Path, default=None, help="Path to CA bundle for TLS verification")
    parser.add_argument("--workdir", required=True, type=Path, help="Working directory for extracted artifacts")
    parser.add_argument("--results-dir", required=True, type=Path, help="Directory to write Tekton results")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    result = run_results(args.source_image, args.image, args.workdir, ca_bundle=args.ca_bundle)

    write_result(args.results_dir, "IMAGE_URL", result.image.image_url)
    write_result(args.results_dir, "IMAGE_DIGEST", result.image.image_digest)
    write_result(args.results_dir, "IMAGE_REF", result.image.image_ref)
    write_result(args.results_dir, "SBOM_BLOB_URL", result.sbom_blob_url)
    write_result(args.results_dir, "CHAINS-GIT_URL", result.git.url)
    write_result(args.results_dir, "CHAINS-GIT_COMMIT", result.git.commit)
    return 0
