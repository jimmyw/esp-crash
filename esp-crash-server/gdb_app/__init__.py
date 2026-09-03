"""Sandboxed interactive debugger service.

See `gdb_app/server.py` for the WebSocket protocol, `gdb_app/jail.py` for the
bubblewrap sandbox, `gdb_app/materialize.py` for turning stored crash blobs
into a work directory, and `gdb_app/converters/` for the per-target seam that
turns an uploaded crash artifact into something gdb can open.
"""
