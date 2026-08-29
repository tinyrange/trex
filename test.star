"""Runs the public trex policy and standard-library tests."""

load("//tests:all.star", "TEST_SUITES")
load("//tests:testing.star", run_tests = "run")

def main(args):
    if len(args) > 1:
        error("Usage: test.star [filter]")
    run_tests(TEST_SUITES, pattern = args[0] if args else "")
