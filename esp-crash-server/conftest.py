"""Ensures esp-crash-server/ is on sys.path so `import server`, `import
device_url`, etc. resolve from tests/*.py regardless of collection order.

Deliberately holds no fixtures: the Flask/DB fixtures (including the autouse
Postgres cleanup) live in tests/conftest.py so they only apply to the tests
in that directory, not to the pure-logic tests at this root
(test_decode_module_coredump.py, test_device_url.py), which have no
Postgres/Docker dependency.
"""
