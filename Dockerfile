# Stage 1: build the wheel
FROM registry.access.redhat.com/ubi10/python-312-minimal@sha256:a6f574a388d6291b70e2f1c5cfce70796afe2461df168807f5b62b43b70dae19 as builder

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

ENTRYPOINT ["/venv/bin/faire-cuan"]
