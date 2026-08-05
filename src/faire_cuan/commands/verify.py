from __future__ import annotations

import argparse
import sys
from pathlib import Path

from faire_cuan.tekton import write_result
from faire_cuan.verify import run_verify


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("verify", help="Verify cosign signature on a source image")
    parser.add_argument("--source-image", required=True, help="Digest-pinned source OCI image reference")
    parser.add_argument("--key-file", required=True, type=Path, help="Path to cosign public key (PEM)")
    parser.add_argument("--ca-bundle", type=Path, default=None, help="Path to CA bundle for TLS verification")
    parser.add_argument("--results-dir", required=True, type=Path, help="Directory to write Tekton results")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from faire_cuan import VerificationError

    try:
        result = run_verify(args.source_image, args.key_file, ca_bundle=args.ca_bundle)
        write_result(args.results_dir, "VERIFICATION_KEY_FINGERPRINT", result.fingerprint)
        return 0
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 12
