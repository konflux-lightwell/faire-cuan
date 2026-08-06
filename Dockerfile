# Stage 1: build the wheel
FROM registry.access.redhat.com/ubi9/python-311@sha256:8ab8ca30cfe498980be839d63a70e9a150e74e0144a934a8e9b2c9b7f7e3907c AS builder

USER 0
WORKDIR /build

COPY pyproject.toml .
COPY src/ src/

RUN chown -R 1001:0 /build
USER 1001

RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /build/dist

# Stage 2: runtime image with OCI tools
FROM quay.io/konflux-ci/task-runner:2.0.0@sha256:4b01fbf98fa7155f5c21443c285f88853864ae7cc66981cf6b543fc6ba16b81b

WORKDIR /opt/faire-cuan

COPY --from=builder /build/dist/*.whl /tmp/

RUN pip install --no-cache-dir /tmp/*.whl \
 && rm -rf /tmp/*.whl

ENTRYPOINT ["faire-cuan"]
