"""Compatibility facade for the neutral Windows PE execution environment."""

load("@stdlib//windows/emulation:runner.star", neutral_run = "run")

run = neutral_run
