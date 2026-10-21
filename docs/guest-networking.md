# Guest internet access

VM Ethernet switches are isolated by default. Native trex executions can
explicitly grant outbound internet with `trex -allow-internet script.star`.
The permission also works with `-repl` and `-serve`; it does not automatically
attach a NIC or change isolated switches. Embedders opt in with
`starlarkfrontend.Program.AllowInternet`.

```python
lan = vmm.switch(internet = True, mac = "02:54:52:00:00:01")
nic = vmm.network("ethernet", switch = lan, mac = "02:54:52:00:00:01")
# Pass networks = [nic] to vmm.machine(...).
```

Use one guest per internet switch; its MAC must match the switch's `mac`
(default `02:54:52:00:00:01`). DHCP assigns `10.42.0.2/24`, with gateway and
DNS at `10.42.0.1`. Configure the same values manually for guests without DHCP.
Each switch gets its own endpoint. Runtime teardown closes its connections
and packet pump. This works with backends supporting the Ethernet-switch
transport, not arbitrary backend-specific network kinds.

The initial gateway proxies public IPv4 TCP and DNS through the native host.
Private/LAN, loopback, link-local and multicast destinations are blocked;
it never binds an inbound host listener. IPv6 and UDP other than queries to
the internal DNS service are not forwarded (including QUIC). This is not a
VPN, port-forwarding mechanism or general-purpose router.

`vmm.switch()` without `internet=True` retains the pure in-memory multi-guest
switch behavior, without DHCP, DNS or any host attachment. Requesting internet
without the capability fails before a gateway is created. The portable Starlark
adapter accepts an embedding-provided factory; native sockets and packet-pump
ownership live behind `vmm/ethernet/native`.
