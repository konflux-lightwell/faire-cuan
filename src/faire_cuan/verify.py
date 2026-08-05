from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from faire_cuan import ValidationError, VerificationError
from faire_cuan.auth import create_docker_auth, setup_ca_bundle
from faire_cuan.tools import cosign, openssl

logger = logging.getLogger(__name__)


@dataclass
class VerifyResult:
    fingerprint: str


def run_verify(source_image: str, key_file: Path, *, ca_bundle: Path | None = None) -> VerifyResult:
    if "@sha256:" not in source_image:
        raise ValidationError("SOURCE_IMAGE must be digest-pinned (contain @sha256:)")

    _validate_single_key(key_file)

    fingerprint = openssl.compute_key_fingerprint(key_file)
    logger.info("Key fingerprint: %s", fingerprint)

    setup_ca_bundle(ca_bundle)
    docker_config = create_docker_auth(source_image, Path("/tmp/auth"))

    _verify_signature(source_image, key_file, docker_config)

    return VerifyResult(fingerprint=fingerprint)


def _validate_single_key(key_file: Path) -> None:
    text = key_file.read_text()
    key_count = text.count("-----BEGIN PUBLIC KEY-----")
    if key_count != 1:
        raise ValidationError(f"secret must contain exactly one public key, found {key_count}")


def _verify_signature(image: str, key_file: Path, docker_config: Path) -> None:
    # Try OCI referrer signatures first (cosign v2+ via --experimental-oci11).
    # Fall back to tag-based (.sig tag) for images signed with cosign v1.
    oci11_result = cosign.verify(image, key_file, oci11=True, docker_config=docker_config)
    if oci11_result.returncode == 0:
        logger.info("Signature verified (OCI referrer)")
        return

    tag_result = cosign.verify(image, key_file, oci11=False, docker_config=docker_config)
    if tag_result.returncode == 0:
        logger.info("Signature verified (tag-based)")
        return

    raise VerificationError(
        "could not verify signature via OCI referrer or tag-based lookup\n"
        f"--- OCI referrer error ---\n{oci11_result.stderr}\n"
        f"--- tag-based error ---\n{tag_result.stderr}"
    )
