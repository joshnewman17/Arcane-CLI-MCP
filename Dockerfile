# syntax=docker/dockerfile:1.29

ARG PYTHON_VERSION=3.12

# --- 1. Fetch the pinned arcane-cli release ------------------------------------
FROM debian:bookworm-slim AS cli
# renovate: datasource=github-releases depName=getarcaneapp/arcane extractVersion=^v(?<version>.+)$
ARG ARCANE_CLI_VERSION=2.17.3
# Optional: pin the tarball checksum, e.g. --build-arg ARCANE_CLI_SHA256=<sha256 of arcane-cli_linux_amd64.tar.gz>
ARG ARCANE_CLI_SHA256=""
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    arch="${TARGETARCH:-amd64}"; \
    url="https://github.com/getarcaneapp/arcane/releases/download/v${ARCANE_CLI_VERSION#v}/arcane-cli_linux_${arch}.tar.gz"; \
    echo "Downloading ${url}"; \
    curl -fsSL -o /tmp/cli.tgz "$url"; \
    if [ -n "$ARCANE_CLI_SHA256" ]; then echo "${ARCANE_CLI_SHA256}  /tmp/cli.tgz" | sha256sum -c -; fi; \
    mkdir -p /out && tar -xzf /tmp/cli.tgz -C /out arcane-cli; \
    chmod 0755 /out/arcane-cli; \
    /out/arcane-cli --version

# --- 2. Build the Python package and its dependencies ----------------------------
FROM python:${PYTHON_VERSION}-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
COPY skills ./skills
# The venv gets no pip of its own; the base image's pip installs into it. pip is a build tool
# with its own CVEs and is never needed at runtime, so it must not reach the final image.
RUN python -m venv --without-pip /opt/venv \
 && pip --python /opt/venv/bin/python install .

# --- 3. Runtime ------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim
# renovate: datasource=github-releases depName=getarcaneapp/arcane extractVersion=^v(?<version>.+)$
ARG ARCANE_CLI_VERSION=2.17.3
# Unraid convention: nobody:users (99:100), so /data on the array is writable.
ARG PUID=99
ARG PGID=100

LABEL org.opencontainers.image.title="arcane-cli-mcp" \
      org.opencontainers.image.description="Remote MCP server for Arcane, wrapping arcane-cli" \
      io.getarcane.cli.version="${ARCANE_CLI_VERSION}"

# Remove pip (and the ensurepip wheels) from the runtime image; nothing installs packages at runtime.
RUN python -m pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3.*/ensurepip

RUN set -eu; \
    getent group "${PGID}" >/dev/null || groupadd -g "${PGID}" arcane; \
    getent passwd "${PUID}" >/dev/null && userdel "$(getent passwd "${PUID}" | cut -d: -f1)" || true; \
    useradd -u "${PUID}" -g "${PGID}" -M -d /nonexistent -s /usr/sbin/nologin arcane; \
    mkdir -p /data && chown "${PUID}:${PGID}" /data

COPY --from=cli /out/arcane-cli /usr/local/bin/arcane-cli
COPY --from=build /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARCANE_CLI_PATH=/usr/local/bin/arcane-cli \
    ARCANE_MCP_STATE_DIR=/tmp/arcane-cli-mcp \
    AUDIT_LOG_PATH=/data/audit.log \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080

USER ${PUID}:${PGID}
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=40s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('MCP_PORT','8080')}/healthz\", timeout=35).status == 200 else 1)"]

ENTRYPOINT ["arcane-cli-mcp"]
CMD ["--transport", "http"]
