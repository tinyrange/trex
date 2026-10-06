"""Manifest of Starlark test suites shipped with trex."""

load(":stdlib_test.star", stdlib = "TEST_SUITE")
load(":stdlib_internal_test.star", stdlib_internal = "TEST_SUITE")
load(":emulation_conformance_test.star", emulation_conformance = "TEST_SUITE")
load(":reactos_test.star", reactos = "TEST_SUITE")
load(":media_decode_test.star", media_decode = "TEST_SUITE")

load(":scs_test.star", scs = "TEST_SUITE")

load(":linux_test.star", linux = "TEST_SUITE")

TEST_SUITES = [
    linux,
    scs,
    media_decode,
    reactos,
    stdlib,
    stdlib_internal,
    emulation_conformance,
]
