# syntax=docker/dockerfile:1.4

FROM python:3.12-slim-bookworm AS wheel-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  libpq-dev \
  python3-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /setup
COPY requirements.txt /setup/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip wheel \
  && python -m pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt boto3

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  libpq5 \
  && rm -rf /var/lib/apt/lists/*

# Debugger toolchains available to the sandboxed debug service, plus the
# esp-coredump support data. Versions pinned to the IDF v5.5.4 tools.json
# manifest; update them as a unit when bumping IDF version.
#
# This is the seam for non-Espressif targets: a riscv32-esp-elf, arm-none-eabi
# or gdb-multiarch toolchain is another install_toolchain.sh call plus another
# make_jail_manifest.py call below, not new code.
ARG GDB_VERSION=16.3_20250913
ARG ROM_ELFS_VERSION=20241011
ARG IDF_VERSION=v5.5.4

ARG TARGETARCH
COPY tools/install_toolchain.sh /usr/local/bin/install_toolchain.sh
RUN set -eux \
  && apt-get update && apt-get install -y --no-install-recommends curl \
  && case "${TARGETARCH}" in \
  amd64) \
  GDB_URL="https://github.com/espressif/binutils-gdb/releases/download/esp-gdb-v${GDB_VERSION}/xtensa-esp-elf-gdb-${GDB_VERSION}-x86_64-linux-gnu.tar.gz" \
  GDB_SHA256="16d05c9104ff84529ac3799abb04d5666c193131ab461f153040721728b48730" ;; \
  arm64) \
  GDB_URL="https://github.com/espressif/binutils-gdb/releases/download/esp-gdb-v${GDB_VERSION}/xtensa-esp-elf-gdb-${GDB_VERSION}-aarch64-linux-gnu.tar.gz" \
  GDB_SHA256="ecbd53ba28cf24301be8260249bfcfb60567f938f4402797617c8a0fc170dc7d" ;; \
  *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
  esac \
  && install_toolchain.sh "${GDB_URL}" "${GDB_SHA256}" \
  "/opt/esp/tools/xtensa-esp-elf-gdb/${GDB_VERSION}" \
  && install_toolchain.sh \
  "https://github.com/espressif/esp-rom-elfs/releases/download/${ROM_ELFS_VERSION}/esp-rom-elfs-${ROM_ELFS_VERSION}.tar.gz" \
  "921f000164a421c7628fbfee55b173384aafaa51883adc65cd27bf9b0af9e9a9" \
  "/opt/esp/tools/esp-rom-elfs/${ROM_ELFS_VERSION}" \
  && mkdir -p /opt/esp/idf/tools/idf_py_actions \
  && curl -fsSL "https://raw.githubusercontent.com/espressif/esp-idf/${IDF_VERSION}/tools/idf_py_actions/roms.json" \
  -o /opt/esp/idf/tools/idf_py_actions/roms.json \
  && apt-get purge -y --auto-remove curl \
  && rm -rf /var/lib/apt/lists/*

# bubblewrap builds the debug sandbox; ncurses-base supplies the terminfo entry
# for the xterm-256color terminal the browser presents.
RUN apt-get update && apt-get install -y --no-install-recommends \
  bubblewrap \
  ncurses-base \
  && rm -rf /var/lib/apt/lists/*

# One unprivileged account per concurrent debug session. A distinct uid per
# session is what makes cross-session ptrace/kill a kernel-level EPERM and
# makes the per-uid RLIMIT_NPROC a real per-session fork-bomb guard, so the
# count here *is* the concurrency limit (see gdb_app/uidpool.py).
# Explicit groupadd because `useradd -N` would create no group, and the session
# work directory is owned root:<session group>.
ARG GDB_SESSION_SLOTS=32
RUN set -eux; for i in $(seq 0 $((GDB_SESSION_SLOTS - 1))); do \
  groupadd -g $((100000 + i)) "gdbrun${i}"; \
  useradd -u $((100000 + i)) -g $((100000 + i)) -M -s /usr/sbin/nologin "gdbrun${i}"; \
  done

ENV IDF_PATH=/opt/esp/idf
ENV ESP_ROM_ELF_DIR=/opt/esp/tools/esp-rom-elfs/${ROM_ELFS_VERSION}/
ENV PATH=/opt/esp/tools/xtensa-esp-elf-gdb/${GDB_VERSION}/xtensa-esp-elf-gdb/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /setup
COPY --from=wheel-builder /wheels /wheels
COPY requirements.txt /setup/requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends curl
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt boto3 \
  && rm -rf /wheels

WORKDIR /code
COPY server.py .
COPY decode_module_coredump.py /code
COPY device_url.py .
COPY app/ app/
COPY templates/ templates/
# Alembic migrations + config, so `alembic stamp head` / `alembic upgrade head`
# can run inside the container at deploy time.
COPY alembic.ini .
COPY alembic/ alembic/
# MCP server (run via `uvicorn mcp_server:app`).
COPY mcp_server.py .
COPY mcp_app/ mcp_app/
# Cron sidecar (run via `python cron_runner.py`, see docker-compose.yml's
# `cron` service).
COPY cron_runner.py .
# Sandboxed interactive debug service (run via `uvicorn gdb_server:app`, see
# docker-compose.yml's `esp-crash-gdb` service).
COPY gdb_server.py .
COPY gdb_app/ gdb_app/
COPY toolchains.py gdb_tickets.py ./
COPY tools/ tools/

# Record each toolchain's jail bind list (its ldd closure plus the data files
# and environment it needs), then prove every one of them actually runs inside
# a real bubblewrap jail. Doing both at build time is the point: an incomplete
# library closure becomes a failed build here instead of a debugger that dies
# with "error while loading shared libraries" in front of a user later.
ARG ROM_ELFS_VERSION=20241011
ARG GDB_VERSION=16.3_20250913
RUN python tools/make_jail_manifest.py \
  --name xtensa-esp-elf \
  --arch xtensa \
  --version "${GDB_VERSION}" \
  --exe "/opt/esp/tools/xtensa-esp-elf-gdb/${GDB_VERSION}/xtensa-esp-elf-gdb/bin/xtensa-esp-elf-gdb-no-python" \
  --converter esp_coredump \
  --extra "/opt/esp/tools/esp-rom-elfs/${ROM_ELFS_VERSION}" \
  --extra /opt/esp/idf/tools/idf_py_actions/roms.json \
  --env "ESP_ROM_ELF_DIR=/opt/esp/tools/esp-rom-elfs/${ROM_ELFS_VERSION}/" \
  --env IDF_PATH=/opt/esp/idf
RUN python tools/smoke_test_jail.py

ENV FLASK_APP=server.py
ENV FLASK_RUN_PORT=8000
ENV FLASK_RUN_HOST=0.0.0.0

ENV FLASK_ENV development
#CMD ["flask", "--app", "server", "run", "--debug"]
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers", "8", "--timeout", "120", "server:app"]
