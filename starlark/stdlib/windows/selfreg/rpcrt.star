"""Compatibility facade for the neutral Windows RPC emulator."""

load("@stdlib//windows/emulation:rpc.star", neutral_rpc_plugin = "rpc_plugin", neutral_rpc_proxy_plugin = "rpc_proxy_plugin")

rpc_plugin = neutral_rpc_plugin
rpc_proxy_plugin = neutral_rpc_proxy_plugin
