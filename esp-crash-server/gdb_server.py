"""uvicorn entrypoint for the sandboxed interactive gdb service.

Run with: uvicorn gdb_server:app --host 0.0.0.0 --port 8002
(see the `esp-crash-gdb` service in docker-compose.yml)
"""
from gdb_app.server import build_app

app = build_app()
