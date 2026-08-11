# Stage 1: build the wheel
FROM registry.access.redhat.com/ubi10/python-312-minimal@sha256:3f3c6dda26caa5b2200fba25721c7a970b1acd4677bbc9865bf25dce62da918a as builder

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
