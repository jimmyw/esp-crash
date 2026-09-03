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


WORKDIR /setup
COPY --from=wheel-builder /wheels /wheels
COPY requirements.txt /setup/requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends curl
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt boto3 \
  && rm -rf /wheels

WORKDIR /code
COPY server.py .
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
# Toolchains themselves are NOT baked in: they are packages built by
# toolchains/recipes/ and bind-mounted read-only at /opt/toolchains, so adding
# a chip family needs no image rebuild. Only the recipes travel with the source,
# for whoever builds a package.
COPY toolchains/ toolchains/

ENV FLASK_APP=server.py
ENV FLASK_RUN_PORT=8000
ENV FLASK_RUN_HOST=0.0.0.0

ENV FLASK_ENV development
#CMD ["flask", "--app", "server", "run", "--debug"]
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers", "8", "--timeout", "120", "server:app"]
