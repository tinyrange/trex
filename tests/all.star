"""Manifest of Starlark test suites shipped with trex."""

load(":stdlib_test.star", stdlib = "TEST_SUITE")
load(":stdlib_internal_test.star", stdlib_internal = "TEST_SUITE")
load(":emulation_conformance_test.star", emulation_conformance = "TEST_SUITE")

TEST_SUITES = [
    stdlib,
    stdlib_internal,
    emulation_conformance,
]
