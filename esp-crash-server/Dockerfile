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

# ESP tool versions pinned to IDF v5.5.4 tools.json manifest.
# Update these as a unit when bumping IDF version.
ARG GDB_VERSION=16.3_20250913
ARG ROM_ELFS_VERSION=20241011
ARG IDF_VERSION=v5.5.4

ARG TARGETARCH
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
  && ROM_ELFS_URL="https://github.com/espressif/esp-rom-elfs/releases/download/${ROM_ELFS_VERSION}/esp-rom-elfs-${ROM_ELFS_VERSION}.tar.gz" \
  && ROM_ELFS_SHA256="921f000164a421c7628fbfee55b173384aafaa51883adc65cd27bf9b0af9e9a9" \
  && mkdir -p \
  /opt/esp/tools/xtensa-esp-elf-gdb/${GDB_VERSION} \
  /opt/esp/tools/esp-rom-elfs/${ROM_ELFS_VERSION} \
  /opt/esp/idf/tools/idf_py_actions \
  && curl -fsSL "${GDB_URL}" -o /tmp/gdb.tar.gz \
  && echo "${GDB_SHA256}  /tmp/gdb.tar.gz" | sha256sum -c - \
  && tar xzf /tmp/gdb.tar.gz -C /opt/esp/tools/xtensa-esp-elf-gdb/${GDB_VERSION}/ \
  && curl -fsSL "${ROM_ELFS_URL}" -o /tmp/rom-elfs.tar.gz \
  && echo "${ROM_ELFS_SHA256}  /tmp/rom-elfs.tar.gz" | sha256sum -c - \
  && tar xzf /tmp/rom-elfs.tar.gz -C /opt/esp/tools/esp-rom-elfs/${ROM_ELFS_VERSION}/ \
  && curl -fsSL "https://raw.githubusercontent.com/espressif/esp-idf/${IDF_VERSION}/tools/idf_py_actions/roms.json" \
  -o /opt/esp/idf/tools/idf_py_actions/roms.json \
  && rm -f /tmp/gdb.tar.gz /tmp/rom-elfs.tar.gz \
  && apt-get purge -y --auto-remove curl \
  && rm -rf /var/lib/apt/lists/*

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
COPY templates/ templates/

ENV FLASK_APP=server.py
ENV FLASK_RUN_PORT=8000
ENV FLASK_RUN_HOST=0.0.0.0

ENV FLASK_ENV development
#CMD ["flask", "--app", "server", "run", "--debug"]
CMD ["gunicorn"  , "-b", "0.0.0.0:8000", "server:app"]