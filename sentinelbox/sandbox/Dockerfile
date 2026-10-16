# SentinelBox AI - Stage 5 sandbox image.
#
# BASE_IMAGE is REQUIRED and must be pinned by digest (name@sha256:<64 hex>) or by image ID (sha256:<64 hex>).
# There is deliberately no default: a floating tag such as "latest" would make the image contents unknowable.
# Build with:  python -m sentinelbox.sandbox build --base-image <pinned reference>
# (the build command stages a minimal context and refuses an unpinned base before calling Docker).
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

LABEL io.sentinelbox.sandbox="1" \
      io.sentinelbox.component="sandbox-workload" \
      io.sentinelbox.synthetic="true"

# Only fixed, non-secret settings. The host verifies the final container environment equals this image's environment.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONPATH=/app

# Root-owned, not writable by the runtime user. The staged context contains only the files the workload needs.
WORKDIR /app
COPY sentinelbox/ /app/sentinelbox/

# Numeric non-root user and group. No packages are installed: the workload uses the standard library only.
USER 65532:65532

HEALTHCHECK NONE
# Fixed entry point. Everything the job needs arrives on stdin; the container accepts no command-line arguments.
ENTRYPOINT ["python", "-B", "-s", "-m", "sentinelbox.sandbox_workload"]
CMD []
