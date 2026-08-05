# Faire-Cuan

Faire-Cuan handles the importing of OCI artifacts that were built outside of Konflux.

The tool handles three stages of the import pipeline:

1. **Verify** that a source image's cosign signature is valid against a known public key
2. **Mirror** the image and all its OCI referrers (signatures, attestations, SBOMs) to a destination registry
3. **Extract results** including image coordinates, SBOM, git provenance from SLSA attestations, and build index metadata

## Installation

Faire-Cuan requires Python 3.11+ and has no runtime dependencies beyond the standard library. It expects `cosign`, `oras`, `skopeo`, and `openssl` to be available on `PATH`.

```bash
pip install .
```

## Usage

### Verify a source image

Verify the cosign signature on a digest-pinned source image and write the verification key fingerprint as a Tekton result.

```bash
faire-cuan verify \
  --source-image registry.example.com/org/repo@sha256:abc123 \
  --key-file /path/to/cosign.pub \
  --results-dir /tekton/results \
  --ca-bundle /path/to/ca-bundle.crt  # optional
```

### Mirror an image

Copy the source image and all its OCI referrers to a destination registry.

```bash
faire-cuan mirror \
  --source-image registry.example.com/org/repo@sha256:abc123 \
  --image dest-registry.example.com/org/repo:tag \
  --ca-bundle /path/to/ca-bundle.crt  # optional
```

### Extract results

Extract image metadata, SBOM, and git provenance from SLSA attestations, then write them as Tekton results.

```bash
faire-cuan results \
  --source-image registry.example.com/org/repo@sha256:abc123 \
  --image dest-registry.example.com/org/repo:tag \
  --workdir /workspace/artifacts \
  --results-dir /tekton/results \
  --ca-bundle /path/to/ca-bundle.crt  # optional
```

Output results: `IMAGE_URL`, `IMAGE_DIGEST`, `IMAGE_REF`, `SBOM_BLOB_URL`, `CHAINS-GIT_URL`, `CHAINS-GIT_COMMIT`.

## Development

Install in editable mode with dev dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Run the full CI suite (tests, linting, security scan, dependency audit):

```bash
tox
```

Individual checks:

```bash
ruff check src/ tests/    # lint
ruff format src/ tests/   # format
bandit -r src/faire_cuan/ -ll  # security
pip-audit                 # dependency audit
```

## About the name

Lightwell projects follow an Irish-language naming convention. *Faire-Cuan* (faire: watch, guard; cuan: harbor, haven) means "harbor watch" — fitting for a tool that stands guard over artifacts entering the internal registry.
