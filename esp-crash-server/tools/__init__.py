"""Build-time tooling for the debug sandbox.

A package (rather than loose scripts) only so `tools.make_jail_manifest`'s
ldd-closure logic can be imported by `tools.smoke_test_jail` instead of
duplicated there.
"""
