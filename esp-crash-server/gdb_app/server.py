"""The interactive debug service: one sandboxed gdb per WebSocket.

An ASGI app, separate from the Flask web application, for two reasons: the web
app runs under gunicorn's synchronous workers and cannot serve WebSockets, and
this process is the only one that needs the extra kernel privileges bubblewrap
requires. It follows the same shape as mcp_app/server.py - its own uvicorn
entrypoint, and a bare Flask app whose only job is to own the SQLAlchemy
session so the ACL-scoped functions in mcp_app/tools.py can run unchanged.

Protocol, once the socket is open:

    server -> client   binary frames  raw pty bytes, straight to xterm.js
                       text frames    JSON control: {"t": "status"|"error"|"exit", ...}
    client -> server   binary frames  raw keystrokes, straight to the pty
                       text frames    JSON control: {"t": "resize", "cols":…, "rows":…}

Splitting raw bytes onto the binary channel keeps the terminal stream free of
any escaping, and leaves the text channel available for structured control -
including, later, a GDB/MI mode driven over the same session machinery.
"""
import asyncio
import json
import os
import re
import time

from flask import Flask
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute

import gdb_tickets
import toolchains
from app.config import database_uri
from app.models import db
from mcp_app import tools

from . import jail, materialize
from .uidpool import PoolExhausted, SessionPool

# Close codes. 1000/1001 are the standard normal cases; the 4xxx range is
# application-defined, which lets the browser tell "you are not allowed" apart
# from "the debugger exited" without parsing message text.
CLOSE_OK = 1000
CLOSE_UNAUTHORIZED = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_UNAVAILABLE = 4503
CLOSE_TIMEOUT = 4408
CLOSE_INTERNAL = 4500

READ_CHUNK = 65536

# A terminal needs a carriage return to get back to column zero; a bare newline
# only moves down. Text that reaches the terminal channel from anywhere other
# than the pty has therefore to be normalised, or it renders as a staircase.
_BARE_NEWLINE = re.compile(r"\r?\n")


def to_crlf(text):
    """Normalise line endings for the terminal channel.

    The pty already applies ONLCR, so gdb's own output arrives correctly. This
    is for everything else we write there - converter reports and symbol
    notes - which is ordinary Python text with bare newlines in it.
    """
    return _BARE_NEWLINE.sub("\r\n", text)


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return int(default)


def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be set for the gdb session server")
    return value


def _make_db_app():
    """A bare Flask app that only owns the DB session (no routes/blueprints) -
    same approach as mcp_app/server.py:_make_db_app."""
    flask_app = Flask("esp_crash_gdb_db")
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = database_uri()
    flask_app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
    db.init_app(flask_app)
    return flask_app


class SessionServer:
    def __init__(self, flask_app, signer, pool, idle_seconds, max_seconds):
        self.flask_app = flask_app
        self.signer = signer
        self.pool = pool
        self.replay = gdb_tickets.ReplayGuard()
        self.idle_seconds = idle_seconds
        self.max_seconds = max_seconds

    # ---------------------------------------------------------------- helpers

    async def _blocking(self, fn, *args):
        """Run blocking work (subprocess, file I/O) off the event loop.

        Materialization spawns esp-coredump and gdb and can take seconds on a
        large core; doing that inline would stall every other live session's
        terminal, which is exactly the symptom that makes an interactive tool
        feel broken.
        """
        return await asyncio.get_running_loop().run_in_executor(None, fn, *args)

    def _authorize(self, gh_user, crash_id):
        """Resolve the crash and its toolchain, or raise NotDebuggable.

        Runs the ACL check again here even though the web app already did it
        before issuing the ticket: the ticket proves provenance, not
        entitlement, so an access revoked between minting and connecting must
        still take effect.
        """
        with self.flask_app.app_context():
            artifacts = tools.get_debug_artifacts(gh_user, crash_id)
            if artifacts is None:
                return None, None
            name = artifacts["toolchain"]
            tc = toolchains.get(name)
            if tc is None:
                available = ", ".join(toolchains.names()) or "none installed"
                if not name:
                    raise materialize.NotDebuggable(
                        f"No debug toolchain is configured for project "
                        f"'{artifacts['project_name']}'. Set one in the "
                        f"project's settings (available: {available}).")
                raise materialize.NotDebuggable(
                    f"Project '{artifacts['project_name']}' is configured to use "
                    f"toolchain '{name}', which is not installed on this server "
                    f"(available: {available}).")
            return artifacts, tc

    def _fetch_module_elf(self, sha1):
        with self.flask_app.app_context():
            return tools.get_module_elf(sha1)

    # ------------------------------------------------------------- entrypoint

    async def session(self, websocket):
        # Accept first, then reject with a close code, rather than refusing the
        # handshake. Closing before accept makes Starlette reject with HTTP 403,
        # which reaches the browser as an opaque code 1006 with no detail - and
        # an expired ticket is an ordinary event (a page left open for a minute)
        # that the client should be able to recognise and retry. The ticket
        # check is a signature verification against an in-memory set, so
        # accepting first costs nothing and nothing downstream is touched.
        await websocket.accept()
        try:
            gh_user, crash_id, jti = self.signer.verify(
                websocket.query_params.get("ticket"))
            self.replay.consume(jti)
        except gdb_tickets.InvalidTicket as e:
            await self._say(websocket, "error", f"Session not authorised: {e}.")
            await self._shut(websocket, CLOSE_UNAUTHORIZED)
            return

        try:
            artifacts, toolchain = await self._blocking(
                self._authorize, gh_user, crash_id)
        except materialize.NotDebuggable as e:
            await self._say(websocket, "error", str(e))
            await self._shut(websocket, CLOSE_FORBIDDEN)
            return
        if artifacts is None:
            # Missing and forbidden are deliberately indistinguishable, matching
            # mcp_app/tools.py's contract.
            await self._say(websocket, "error", "Crash not found.")
            await self._shut(websocket, CLOSE_FORBIDDEN)
            return

        try:
            lease = await self.pool.acquire()
        except PoolExhausted:
            await self._say(websocket, "error",
                            "All debug session slots are currently in use. "
                            "Please try again in a moment.")
            await self._shut(websocket, CLOSE_UNAVAILABLE)
            return

        try:
            await self._run(websocket, lease, artifacts, toolchain)
        finally:
            await self.pool.release(lease)

    async def _run(self, websocket, lease, artifacts, toolchain):
        await self._say(websocket, "status",
                        f"Preparing crash {artifacts['crash_id']} "
                        f"({toolchain.name}/{toolchain.arch})...")
        try:
            prepared = await self._blocking(
                materialize.prepare, artifacts, toolchain, lease,
                self._fetch_module_elf)
        except materialize.NotDebuggable as e:
            await self._say(websocket, "error", str(e))
            await self._shut(websocket, CLOSE_FORBIDDEN)
            return
        except Exception:                                    # noqa: BLE001
            self.flask_app.logger.exception(
                "materializing crash %s failed", artifacts["crash_id"])
            await self._say(websocket, "error",
                            "Preparing the debug session failed unexpectedly.")
            await self._shut(websocket, CLOSE_INTERNAL)
            return

        # Preparation output - which module symbols resolved, then the
        # symbolicated report - is terminal *content*, not a lifecycle event, so
        # it goes on the binary channel alongside the debugger's own output
        # rather than through a status frame. That also puts it through to_crlf,
        # which is what multi-line text needs: the status path was writing
        # embedded bare newlines straight to xterm.js and staircasing the report.
        await self._echo(websocket, prepared.preamble())

        spec = jail.JailSpec(toolchain=toolchain, workdir=lease.workdir,
                             uid=lease.uid, gid=lease.gid, tier=jail.SESSION)
        try:
            pty_jail = await self._blocking(jail.PtyJail, spec, prepared.argv)
        except Exception:                                    # noqa: BLE001
            self.flask_app.logger.exception("starting the sandboxed debugger failed")
            await self._say(websocket, "error", "Could not start the debugger.")
            await self._shut(websocket, CLOSE_INTERNAL)
            return

        self.flask_app.logger.info(
            "debug session %s started: crash=%s toolchain=%s uid=%s pid=%s",
            lease.session_id, artifacts["crash_id"], toolchain.name,
            lease.uid, pty_jail.pid)
        try:
            code = await self._pump(websocket, pty_jail)
            await self._shut(websocket, code)
        finally:
            await self._blocking(pty_jail.close)
            self.flask_app.logger.info("debug session %s ended", lease.session_id)

    # ------------------------------------------------------------------ pumps

    async def _pump(self, websocket, pty_jail):
        """Shuttle bytes between the socket and the pty until one side ends.

        The pty master is watched with add_reader rather than read in a thread
        so that teardown is immediate: a blocking read in an executor would
        keep a thread parked until the debugger happened to produce output.
        """
        loop = asyncio.get_running_loop()
        outbound = asyncio.Queue()
        eof = asyncio.Event()
        fd = pty_jail.master_fd
        state = {"last": time.monotonic(), "start": time.monotonic()}

        def on_readable():
            try:
                data = os.read(fd, READ_CHUNK)
            except (OSError, BlockingIOError):
                data = b""
            if data:
                outbound.put_nowait(data)
            else:
                # EOF on the master means the debugger exited and closed its
                # end - the normal end of a session.
                loop.remove_reader(fd)
                eof.set()

        loop.add_reader(fd, on_readable)
        try:
            watchdog = asyncio.create_task(self._watchdog(state))
            tasks = [
                asyncio.create_task(self._to_client(websocket, outbound)),
                asyncio.create_task(self._from_client(websocket, pty_jail, state)),
                asyncio.create_task(eof.wait()),
                watchdog,
            ]
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

            # The watchdog only ever finishes by firing, so its presence in
            # `done` is what distinguishes "we ended this" from "the debugger
            # exited" or "the client went away".
            if watchdog in done:
                reason = watchdog.result()
                await self._say(websocket, "error",
                                f"Debug session closed ({reason} limit reached).")
                return CLOSE_TIMEOUT
            return CLOSE_OK
        finally:
            try:
                loop.remove_reader(fd)
            except (OSError, ValueError):
                pass
            # Anything the debugger printed on its way out is still worth
            # showing - a panic message on exit is exactly what the user wants.
            await self._drain(websocket, outbound)

    async def _to_client(self, websocket, outbound):
        while True:
            data = await outbound.get()
            await websocket.send_bytes(data)

    async def _drain(self, websocket, outbound):
        try:
            while not outbound.empty():
                await websocket.send_bytes(outbound.get_nowait())
        except Exception:                                    # noqa: BLE001
            pass    # the socket may already be gone; nothing useful to do

    async def _from_client(self, websocket, pty_jail, state):
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            state["last"] = time.monotonic()
            if (data := message.get("bytes")) is not None:
                os.write(pty_jail.master_fd, data)
            elif (text := message.get("text")) is not None:
                self._control(pty_jail, text)

    def _control(self, pty_jail, text):
        """Handle a client control frame. Malformed frames are ignored rather
        than fatal: a terminal should not disappear because a resize event
        arrived garbled."""
        try:
            msg = json.loads(text)
            if msg.get("t") == "resize":
                pty_jail.set_winsize(int(msg["rows"]), int(msg["cols"]))
        except (ValueError, KeyError, TypeError, OSError):
            pass

    async def _watchdog(self, state):
        """End sessions that are idle or simply too old.

        Both limits exist because a session holds a pool identity and a work
        directory for as long as it lives, and a forgotten browser tab would
        otherwise hold one indefinitely.
        """
        while True:
            await asyncio.sleep(5)
            now = time.monotonic()
            if now - state["last"] > self.idle_seconds:
                return "idle"
            if now - state["start"] > self.max_seconds:
                return "max"

    async def _echo(self, websocket, text):
        """Write text to the terminal channel, with terminal line endings."""
        try:
            await websocket.send_bytes(to_crlf(text).encode())
        except Exception:                                    # noqa: BLE001
            pass

    async def _say(self, websocket, kind, message):
        try:
            await websocket.send_text(json.dumps({"t": kind, "message": message}))
        except Exception:                                    # noqa: BLE001
            pass

    @staticmethod
    async def _shut(websocket, code):
        """Close, tolerating a client that has already gone.

        A client can disconnect at any point - including between our error
        message and our close frame - and uvicorn surfaces that as
        ClientDisconnected from the send. There is nothing to do about it, and
        letting it escape logs an ASGI traceback for what is ordinary
        behaviour.
        """
        try:
            await websocket.close(code=code)
        except Exception:                                    # noqa: BLE001
            pass


def build_app():
    flask_app = _make_db_app()
    signer = gdb_tickets.TicketSigner(
        _require_env("GDB_TICKET_SECRET"),
        ttl_seconds=_env_int("GDB_TICKET_TTL_SECONDS", gdb_tickets.DEFAULT_TTL_SECONDS),
    )
    pool = SessionPool()
    if not pool.capacity:
        raise RuntimeError(
            "no session accounts found - the image must create gdbrun0..N users "
            "(see the Dockerfile); without them there is no per-session uid to "
            "isolate sandboxes with")

    server = SessionServer(
        flask_app=flask_app, signer=signer, pool=pool,
        idle_seconds=_env_int("GDB_SESSION_IDLE_SECONDS", 300),
        max_seconds=_env_int("GDB_SESSION_MAX_SECONDS", 1800),
    )

    # Answers on "/" as well as "/health", and to HEAD and OPTIONS as well as
    # GET, because a reverse proxy's default health check is whatever the proxy
    # felt like: HAProxy's bare `option httpchk` sends `OPTIONS /`, and OPNsense
    # offers `GET /`. A check that 404s marks the server DOWN and the proxy then
    # answers "503 No server is available" - which looks nothing like a
    # misconfigured health check, so it is worth simply passing them all.
    async def health(_request):
        return PlainTextResponse("ok\n", status_code=200)

    async def info(_request):
        """Which toolchains this server can actually run. Handy when a project
        is configured with a name that is not installed."""
        return PlainTextResponse(
            json.dumps({
                "toolchains": [
                    {"name": t.name, "arch": t.arch, "version": t.version}
                    for t in toolchains.installed().values()
                ],
                "capacity": pool.capacity,
                "available": pool.available,
            }),
            media_type="application/json",
        )

    CHECK_METHODS = ["GET", "HEAD", "OPTIONS"]

    def routes_at(prefix):
        return [
            Route(f"{prefix}/", health, methods=CHECK_METHODS),
            Route(f"{prefix}/health", health, methods=CHECK_METHODS),
            Route(f"{prefix}/v1/info", info),
            WebSocketRoute(f"{prefix}/v1/session", server.session),
        ]

    # Also serve under a path prefix when one is configured, so this can sit
    # behind a path route on an existing domain (wss://host/gdb/v1/session)
    # instead of needing its own subdomain, DNS record and certificate. Both
    # forms are registered rather than only the prefixed one, so the reverse
    # proxy may either strip the prefix or pass it through - and the container
    # stays directly reachable for health checks either way.
    prefix = os.environ.get("GDB_PATH_PREFIX", "").strip().rstrip("/")
    if prefix and not prefix.startswith("/"):
        prefix = "/" + prefix

    return Starlette(routes=routes_at("") + (routes_at(prefix) if prefix else []))
