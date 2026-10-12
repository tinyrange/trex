# Authenticated scripted web applications with VM consoles

Ordinary `-serve` handlers and the embedded VM viewer remain unchanged.
`web.application` composes the existing request/response system with a dynamic
VM workspace and a native authentication adapter:

```python
def main(args):
    consoles = vmm.workspace({})
    machines = {}
    def handle(request):
        # Script owns routes, HTML/JS, VM construction, and lifecycle policy.
        # After constructing a VM in an authenticated POST handler:
        # id = consoles.add("Machine name", vm)
        # machines[id] = vm
        # After explicit cleanup: vm.close(); consoles.remove(id)
        return web.response("application page", headers={"Content-Type": "text/html"})
    return web.application(handle, consoles=consoles, public=["/"])
```

`web.application(handler, consoles=None, public=[], origin="")` returns an
application descriptor. `public` is an exact list of bootstrap/asset paths;
only GET/HEAD requests at those paths bypass authentication. Do not put guest,
archive, or private API routes in that list. Other requests require the session
bearer token. Mutations require a same-origin Origin header; reads may omit it.
The complete random-token URL is printed at startup. The script's public page
must transfer the fragment to its tab's session storage and remove it from
history before making authenticated requests.

The plain-HTTP native listener permits loopback or an exact IP assigned to an
up local `tailscale0` interface, in the Tailscale IPv4/IPv6 ranges. Merely choosing
a `100.x` address does not grant access: ownership by that tunnel is checked.
Wildcard and LAN listeners remain blocked. For direct tunnel access, leave
`origin` empty; same-origin authentication still applies. Other tunnel/interface
layouts can use the loopback HTTPS-proxy option.

`origin` may specify one exact external **HTTPS** origin for a trusted HTTPS reverse proxy. It has no path,
credentials, query, or fragment. Forwarded headers never change Origin policy.
The configured origin is also used in the printed URL. This is not a TLS listener
or a replacement for proxy configuration and access control.

Native console routes mounted beside the script:

- `GET /console/client.js`: existing self-contained protocol client; import
  `RFB` and `keySym`. No library/CDN is required.
- `GET /console/rfb?vm=ID&token=TOKEN`: authenticated, same-origin WebSocket/RFB
  connection, with one controller per VM ID. The script controls selection.

The embedded viewer's page and create API are not mounted under `/console`.
Normal built-in VM/workspace serving still uses its original routes and UI.

`vmm.workspace({})` may start empty. `workspace.add(name, vm)` validates display
support and returns a monotonically allocated ID. Duplicate names are rejected.
`workspace.remove(id)` unregisters a display **without closing its VM**; callers
must explicitly close/own it. IDs are never reused, so an old browser URL cannot
select a new replacement machine. The workspace releases removed references.
Recipe handlers and optional workspace factories share one Starlark execution
mutex. Console streaming and input stay independent of that mutex. Image
construction in a handler is synchronous, so other scripted HTTP handlers wait;
existing RFB sessions continue to operate.

`web.browse(root, request, path="/relative/path")` supports mounting a native
archive tree under a script-selected prefix. The optional path changes only
resolution; method, query, pagination, and raw/range response behavior are
preserved. Traversal/backslashes/NULs remain rejected by the native resolver.

For consumer tests, `TestScriptedWebApplicationFixture` accepts `TREX_WEB_ROOT`
and `TREX_WEB_FIXTURE`. The script returns an application and defines ordered
`TEST_CASES` tuples `(method, path, status, required_substring, forbidden_substring)`.
Test-only `test_vm()` produces an in-memory display handle; `test_vm_counts()`
returns started/closed counts. No real VM is booted by these fixtures.
`TREX_WEB_JS_TEST` adds a consumer Node test; `TREX_WEB_LIVE_TEST` selects an
explicit consumer live smoke. Use `go test -count=1` for subprocess/live checks.
