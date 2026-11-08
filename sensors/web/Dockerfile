# Immutable official release: frozen upstream Python dependencies, no pip resolve.
FROM thinkst/opencanary@sha256:4e51338e3b6e349652b0604be656d9b8fc1cde2cd40409b2e956f1da3eb673a1 AS baseline
FROM baseline AS patched
COPY request_evidence.py /opencanary/opencanary/modules/request_evidence.py
COPY patches/request-evidence.patch apply_patch.py /tmp/cheesetrap-patch/
RUN /opencanary/.venv/bin/python /tmp/cheesetrap-patch/apply_patch.py && rm -rf /tmp/cheesetrap-patch
