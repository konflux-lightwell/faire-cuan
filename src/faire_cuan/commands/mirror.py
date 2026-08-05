from __future__ import annotations

import argparse
from pathlib import Path

from faire_cuan.mirror import run_mirror


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("mirror", help="Mirror image with all referrers to destination registry")
    parser.add_argument("--source-image", required=True, help="Digest-pinned source OCI image reference")
    parser.add_argument("--image", required=True, help="Destination image reference")
    parser.add_argument("--ca-bundle", type=Path, default=None, help="Path to CA bundle for TLS verification")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    run_mirror(args.source_image, args.image, ca_bundle=args.ca_bundle)
    return 0
