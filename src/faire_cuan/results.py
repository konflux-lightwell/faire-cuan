from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from faire_cuan import ToolError, ValidationError
from faire_cuan.auth import create_docker_auth, home_docker_config, setup_ca_bundle
from faire_cuan.retry import retry
from faire_cuan.tools import cosign, oras, skopeo

logger = logging.getLogger(__name__)

BUILD_INDEX_ARTIFACT_TYPE = "application/vnd.redhat.gav-index-build+json"


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
    setup_ca_bundle(ca_bundle)
    src_docker_config = home_docker_config()
    dst_docker_config = create_docker_auth(dest_image, Path("/tmp/dst-auth"))

    image_info = _compute_image_info(source_image, dest_image)

    oci_dir = workdir / "source-oci"
    layer_path = _download_oci_layout(source_image, oci_dir, src_docker_config)

    sbom_dir = workdir / "sbom"
    sbom_path = _extract_sbom(layer_path, source_image, sbom_dir, src_docker_config)

    sbom_blob_url = ""
    if sbom_path:
        sbom_blob_url = _attach_sbom(sbom_path, image_info, dst_docker_config)

    source_dir = workdir / "source"
    _extract_sources(layer_path, source_dir)

    git = _extract_git_coordinates(source_image, src_docker_config)

    index_dir = workdir / "index"
    _attach_build_index(source_image, image_info.image_ref, index_dir, src_docker_config, dst_docker_config)

    return ResultsOutput(image=image_info, git=git, sbom_blob_url=sbom_blob_url)


# --- Pure helpers ---


def _parse_repo(image: str) -> str:
    ref = image.split("@")[0]
    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")
    if last_colon > last_slash:
        ref = ref[:last_colon]
    return ref


def _compute_image_info(source_image: str, dest_image: str) -> ImageInfo:
    digest = source_image.split("@", 1)[1]
    dest_repo = _parse_repo(dest_image)
    return ImageInfo(
        image_url=dest_image,
        image_digest=digest,
        image_ref=f"{dest_repo}@{digest}",
    )


def _decode_dsse_payload(envelope: dict) -> dict:
    raw = envelope.get("dsseEnvelope", {}).get("payload") or envelope["payload"]
    return json.loads(base64.b64decode(raw))


def _get_oci_layer_path(oci_dir: Path) -> Path:
    index = json.loads((oci_dir / "index.json").read_text())
    manifest_digest = index["referrers"][0]["digest"].removeprefix("sha256:")
    manifest = json.loads((oci_dir / "blobs" / "sha256" / manifest_digest).read_text())
    layer_digest = manifest["layers"][0]["digest"].removeprefix("sha256:")
    return oci_dir / "blobs" / "sha256" / layer_digest


# --- Side-effecting functions ---


def _download_oci_layout(source_image: str, oci_dir: Path, docker_config: Path) -> Path:
    source_repo = _parse_repo(source_image)
    source_digest = source_image.split("@", 1)[1]
    digest_ref = f"{source_repo}@{source_digest}"

    skopeo.copy(
        f"docker://{digest_ref}",
        f"oci:{oci_dir}:artifact",
        override_os="linux",
        docker_config=docker_config,
    )
    return _get_oci_layer_path(oci_dir)


def _extract_sbom(layer_path: Path, source_image: str, sbom_dir: Path, docker_config: Path) -> Path | None:
    sbom_dir.mkdir(parents=True, exist_ok=True)
    sbom_file = sbom_dir / "cyclonedx.json"

    try:
        with zipfile.ZipFile(layer_path) as zf:
            data = zf.read("build-output/cyclonedx.json")
        if data:
            sbom_file.write_bytes(data)
            logger.info("Extracted CycloneDX SBOM from OCI layer")
            return sbom_file
    except (KeyError, zipfile.BadZipFile):
        pass

    logger.info("CycloneDX SBOM not in OCI layer, checking attestations...")
    for envelope in cosign.download_attestation(source_image, docker_config=docker_config):
        try:
            statement = _decode_dsse_payload(envelope)
        except (KeyError, json.JSONDecodeError):
            continue
        if statement.get("predicateType") == "https://cyclonedx.org/bom":
            sbom_data = json.dumps(statement["predicate"]).encode()
            sbom_file.write_bytes(sbom_data)
            logger.info("Extracted CycloneDX SBOM from attestation")
            return sbom_file

    logger.warning("No CycloneDX SBOM found; skipping SBOM attachment")
    return None


def _attach_sbom(sbom_path: Path, image_info: ImageInfo, docker_config: Path) -> str:
    retry(lambda: cosign.attach_sbom(image_info.image_ref, sbom_path, docker_config=docker_config))
    dest_repo = _parse_repo(image_info.image_ref)
    sbom_hash = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
    return f"{dest_repo}@sha256:{sbom_hash}"


def _extract_sources(layer_path: Path, source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(layer_path) as zf:
        tar_bytes = zf.read("build-output/sources/sources.tar.gz")
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            sep = member.name.find("/")
            if sep < 0:
                continue
            member.name = member.name[sep + 1 :]
            if not member.name:
                continue
            tf.extract(member, source_dir, filter="data")


def _extract_git_coordinates(source_image: str, docker_config: Path) -> GitCoordinates:
    for envelope in cosign.download_attestation(source_image, docker_config=docker_config):
        try:
            statement = _decode_dsse_payload(envelope)
        except (KeyError, json.JSONDecodeError):
            continue
        if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
            continue

        predicate = statement["predicate"]
        build_def = predicate["buildDefinition"]
        git_url = build_def["externalParameters"]["repository"]["uri"]

        for dep in build_def.get("resolvedDependencies", []):
            if dep.get("name") == "repository":
                return GitCoordinates(url=git_url, commit=dep["digest"]["gitCommit"])

    raise ValidationError(f"SLSA provenance v1 attestation not found on {source_image}")


def _attach_build_index(
    source_image: str,
    dest_ref: str,
    index_dir: Path,
    src_docker_config: Path,
    dst_docker_config: Path,
) -> None:
    try:
        manifest = oras.manifest_fetch(source_image, docker_config=src_docker_config)
    except ToolError:
        return

    build_id = manifest.get("annotations", {}).get("dev.lightwell.build-id")
    if not build_id:
        return

    source_repo = _parse_repo(source_image)
    index_ref = f"{source_repo}:idx-{build_id}"

    try:
        discovery = oras.discover(dest_ref, artifact_type=BUILD_INDEX_ARTIFACT_TYPE, docker_config=dst_docker_config)
        if len(discovery.get("manifests") or []):
            logger.info("Build index JSON already attached on %s, skipping", dest_ref)
            return
    except ToolError:
        pass

    index_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = oras.pull(index_ref, index_dir, docker_config=src_docker_config)

    retry(
        lambda: oras.attach(
            dest_ref,
            [Path(artifact_path.name)],
            artifact_type=BUILD_INDEX_ARTIFACT_TYPE,
            cwd=artifact_path.parent,
            docker_config=dst_docker_config,
        )
    )
    logger.info("Attached build index JSON as referrer on %s", dest_ref)
