from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from faire_cuan import ValidationError
from faire_cuan.results import (
    _compute_image_info,
    _decode_dsse_payload,
    _extract_git_coordinates,
    _extract_sbom,
    _extract_sources,
    _get_oci_layer_path,
    _parse_repo,
    run_results,
)

# --- Fixtures ---


def _make_attestation(predicate_type: str, predicate: dict, *, use_dsse_envelope: bool = False):
    statement = json.dumps({"predicateType": predicate_type, "predicate": predicate})
    payload = base64.b64encode(statement.encode()).decode()
    if use_dsse_envelope:
        return {"dsseEnvelope": {"payload": payload}}
    return {"payload": payload}


def _make_slsa_attestation(git_url: str = "https://github.com/org/repo", git_commit: str = "abc123"):
    return _make_attestation(
        "https://slsa.dev/provenance/v1",
        {
            "buildDefinition": {
                "externalParameters": {"repository": {"uri": git_url}},
                "resolvedDependencies": [
                    {"name": "repository", "digest": {"gitCommit": git_commit}},
                ],
            }
        },
    )


@pytest.fixture()
def oci_layer(tmp_path: Path) -> Path:
    layer_path = tmp_path / "layer.zip"
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="top/main.java")
        content = b"public class Main {}"
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    with zipfile.ZipFile(layer_path, "w") as zf:
        zf.writestr("build-output/cyclonedx.json", '{"bomFormat": "CycloneDX"}')
        zf.writestr("build-output/sources/sources.tar.gz", tar_buffer.getvalue())
    return layer_path


@pytest.fixture()
def oci_layout(tmp_path: Path) -> tuple[Path, Path]:
    oci_dir = tmp_path / "oci"
    blobs = oci_dir / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    layer_content = b"fake-layer"
    layer_hash = hashlib.sha256(layer_content).hexdigest()
    (blobs / layer_hash).write_bytes(layer_content)

    manifest = json.dumps({"layers": [{"digest": f"sha256:{layer_hash}"}]})
    manifest_hash = hashlib.sha256(manifest.encode()).hexdigest()
    (blobs / manifest_hash).write_text(manifest)

    index = json.dumps({"referrers": [{"digest": f"sha256:{manifest_hash}"}]})
    (oci_dir / "index.json").write_text(index)

    return oci_dir, blobs / layer_hash


# --- Pure helper tests ---


class TestParseRepo:
    def test_strips_tag(self):
        assert _parse_repo("quay.io/org/repo:latest") == "quay.io/org/repo"

    def test_strips_digest(self):
        assert _parse_repo("quay.io/org/repo@sha256:abc") == "quay.io/org/repo"

    def test_strips_tag_and_digest(self):
        assert _parse_repo("quay.io/org/repo:v1@sha256:abc") == "quay.io/org/repo"

    def test_preserves_port(self):
        assert _parse_repo("registry.io:5000/org/repo:tag") == "registry.io:5000/org/repo"


class TestComputeImageInfo:
    def test_computes_all_fields(self):
        info = _compute_image_info("src.io/repo@sha256:aaa", "dest.io/repo:tag")
        assert info.image_url == "dest.io/repo:tag"
        assert info.image_digest == "sha256:aaa"
        assert info.image_ref == "dest.io/repo@sha256:aaa"


class TestDecodeDssePayload:
    def test_standard_payload(self):
        data = {"predicateType": "test"}
        envelope = {"payload": base64.b64encode(json.dumps(data).encode()).decode()}
        assert _decode_dsse_payload(envelope) == data

    def test_dsse_envelope_payload(self):
        data = {"predicateType": "test"}
        envelope = {"dsseEnvelope": {"payload": base64.b64encode(json.dumps(data).encode()).decode()}}
        assert _decode_dsse_payload(envelope) == data

    def test_dsse_envelope_takes_precedence(self):
        inner = {"from": "dsseEnvelope"}
        outer = {"from": "payload"}
        envelope = {
            "dsseEnvelope": {"payload": base64.b64encode(json.dumps(inner).encode()).decode()},
            "payload": base64.b64encode(json.dumps(outer).encode()).decode(),
        }
        assert _decode_dsse_payload(envelope)["from"] == "dsseEnvelope"


class TestGetOciLayerPath:
    def test_resolves_layer_from_index(self, oci_layout):
        oci_dir, expected_layer = oci_layout
        assert _get_oci_layer_path(oci_dir) == expected_layer


# --- Behavioral tests ---


class TestExtractSbom:
    def test_extracts_from_oci_layer(self, oci_layer: Path, tmp_path: Path):
        sbom_dir = tmp_path / "sbom"
        with patch("faire_cuan.results.cosign"):
            result = _extract_sbom(oci_layer, "img@sha256:abc", sbom_dir, tmp_path / "auth")

        assert result is not None
        assert json.loads(result.read_text())["bomFormat"] == "CycloneDX"

    def test_falls_back_to_attestation(self, tmp_path: Path):
        layer_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(layer_path, "w"):
            pass

        sbom_dir = tmp_path / "sbom"
        attestation = _make_attestation("https://cyclonedx.org/bom", {"components": []})

        with patch("faire_cuan.results.cosign.download_attestation", return_value=[attestation]):
            result = _extract_sbom(layer_path, "img@sha256:abc", sbom_dir, tmp_path / "auth")

        assert result is not None
        assert json.loads(result.read_text())["components"] == []

    def test_returns_none_when_not_found(self, tmp_path: Path):
        layer_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(layer_path, "w"):
            pass

        sbom_dir = tmp_path / "sbom"
        with patch("faire_cuan.results.cosign.download_attestation", return_value=[]):
            result = _extract_sbom(layer_path, "img@sha256:abc", sbom_dir, tmp_path / "auth")

        assert result is None


class TestExtractSources:
    def test_extracts_with_strip_components(self, oci_layer: Path, tmp_path: Path):
        source_dir = tmp_path / "source"
        _extract_sources(oci_layer, source_dir)

        assert (source_dir / "main.java").read_bytes() == b"public class Main {}"


class TestExtractGitCoordinates:
    def test_extracts_from_slsa_v1(self, tmp_path: Path):
        attestation = _make_slsa_attestation(git_url="https://github.com/org/repo", git_commit="deadbeef")
        with patch("faire_cuan.results.cosign.download_attestation", return_value=[attestation]):
            git = _extract_git_coordinates("img@sha256:abc", tmp_path / "auth")

        assert git.url == "https://github.com/org/repo"
        assert git.commit == "deadbeef"

    def test_raises_when_no_slsa_provenance(self, tmp_path: Path):
        with patch("faire_cuan.results.cosign.download_attestation", return_value=[]):
            with pytest.raises(ValidationError, match="SLSA provenance"):
                _extract_git_coordinates("img@sha256:abc", tmp_path / "auth")


class TestRunResults:
    @patch("faire_cuan.results._attach_build_index")
    @patch("faire_cuan.results._extract_git_coordinates")
    @patch("faire_cuan.results._extract_sources")
    @patch("faire_cuan.results._attach_sbom")
    @patch("faire_cuan.results._extract_sbom")
    @patch("faire_cuan.results._download_oci_layout")
    @patch("faire_cuan.results.create_docker_auth")
    @patch("faire_cuan.results.home_docker_config")
    @patch("faire_cuan.results.setup_ca_bundle")
    def test_orchestrates_all_steps(
        self,
        mock_ca,
        mock_home,
        mock_dst_auth,
        mock_download,
        mock_sbom,
        mock_attach_sbom,
        mock_sources,
        mock_git,
        mock_build_index,
        tmp_path,
    ):
        from faire_cuan.results import GitCoordinates

        mock_home.return_value = tmp_path / "home-docker"
        mock_dst_auth.return_value = tmp_path / "dst-auth"
        mock_download.return_value = tmp_path / "layer.zip"
        mock_sbom.return_value = tmp_path / "sbom" / "cyclonedx.json"
        mock_attach_sbom.return_value = "dest.io/repo@sha256:sbomhash"
        mock_git.return_value = GitCoordinates(url="https://github.com/org/repo", commit="abc123")

        result = run_results("src.io/repo@sha256:aaa", "dest.io/repo:tag", tmp_path / "work")

        assert result.image.image_url == "dest.io/repo:tag"
        assert result.image.image_digest == "sha256:aaa"
        assert result.image.image_ref == "dest.io/repo@sha256:aaa"
        assert result.sbom_blob_url == "dest.io/repo@sha256:sbomhash"
        assert result.git.url == "https://github.com/org/repo"
        assert result.git.commit == "abc123"

    @patch("faire_cuan.results._attach_build_index")
    @patch("faire_cuan.results._extract_git_coordinates")
    @patch("faire_cuan.results._extract_sources")
    @patch("faire_cuan.results._extract_sbom")
    @patch("faire_cuan.results._download_oci_layout")
    @patch("faire_cuan.results.create_docker_auth")
    @patch("faire_cuan.results.home_docker_config")
    @patch("faire_cuan.results.setup_ca_bundle")
    def test_empty_sbom_blob_url_when_no_sbom(
        self,
        mock_ca,
        mock_home,
        mock_dst_auth,
        mock_download,
        mock_sbom,
        mock_sources,
        mock_git,
        mock_build_index,
        tmp_path,
    ):
        from faire_cuan.results import GitCoordinates

        mock_home.return_value = tmp_path / "home-docker"
        mock_dst_auth.return_value = tmp_path / "dst-auth"
        mock_download.return_value = tmp_path / "layer.zip"
        mock_sbom.return_value = None
        mock_git.return_value = GitCoordinates(url="https://github.com/org/repo", commit="abc123")

        result = run_results("src.io/repo@sha256:aaa", "dest.io/repo:tag", tmp_path / "work")

        assert result.sbom_blob_url == ""
