# Stage 1: build the wheel
FROM registry.access.redhat.com/ubi10/python-312-minimal@sha256:7039183fe52b41759b1780edaba0edd7d665c7db500893332a39f7f486806d71 as builder

USER 0
WORKDIR /build

COPY pyproject.toml .
COPY src/ src/

RUN mkdir /venv && chown -R 1001:0 /build /venv
USER 1001

RUN python3.12 -m venv /venv && \
    /venv/bin/pip install . --no-deps --no-cache-dir

# Stage 2: runtime image with OCI tools
FROM quay.io/konflux-ci/task-runner:2.0.0@sha256:4b01fbf98fa7155f5c21443c285f88853864ae7cc66981cf6b543fc6ba16b81b

COPY --from=builder /venv /venv

USER taskuser

ENTRYPOINT ["/venv/bin/oci-artifact-importer"]
