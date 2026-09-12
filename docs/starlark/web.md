# Starlark web applications

trex can run a Starlark script as an HTTP application:

```console
trex -serve 127.0.0.1:8080 app.star argument...
```

The script's `main(args)` function performs application initialization and
returns a request handler. The handler receives an immutable request record and
returns a string, bytes, file, `None`, or a response created by the `web`
namespace.

```python
def main(args):
    greeting = args[0] if args else "hello"

    def handle(request):
        if request.path == "/":
            return web.response(
                "<h1>%s</h1>" % html.escape(greeting),
                headers = {"Content-Type": "text/html; charset=utf-8"},
            )
        return web.response("not found\n", status = 404)

    return handle
```

Requests expose `method`, decoded `path`, `raw_query`, `query`, `headers`,
`cookies`, `host`, and `body`. Header names are lowercase. Query parameters use
their first value.

The generic response primitives are:

- `web.response(body="", status=200, headers={})`
- `web.file(file, name="download", status=200, headers={})`, including MIME,
  range, and conditional request handling
- `web.redirect(location, status=303)`
- `web.zip(filesystem, path, name="download.zip")`, streamed directly from a
  trex filesystem without host extraction

`filesystem.host(root)` is the native host backend. Like parsed trex
filesystems, it supports indexed path lookup, `.find(path)`, and directory
`.files`. This keeps operating-system traversal behind a filesystem adapter and
lets applications use the same interface for host, ISO9660, FAT, NTFS, and UDF
content.

The `html`, `url`, and `regexp` namespaces provide format-neutral helpers useful
to web applications. Compiled regular expressions expose `find_all` and
`replace_all`; each match has `start`, `end`, `text`, and `groups` fields.

For recursive archive and filesystem browsing, use `auto(source)` with
`web.browse(root, request)`. See [Automatic file views](auto.md) for the Go
registry, JSON route, range handling, and single-page browser example.

## Request timing logs

The native `-serve` listener writes JSON request logs to stderr. Each
`http.request.start` has a matching `http.request.end` with `request_id`, method,
path, status, bytes written and millisecond timings: `duration_ms` is total
wall time, `queue_ms` is waiting for the shared Starlark handler lock,
`handler_ms` is handler execution, and `stream_ms` is response writing (including
lazy file decoding). Browser requests also include `browse_ms` with `resolve`,
`metadata` and `children` durations, which are subsets of handler time.

Start records identify outstanding requests. End records include cancellation
and transport write errors when observed. A successful HTTP status alone does
not prove that a client received a complete download. Only the browser query
controls `json`, `raw`, `offset` and `limit` are logged; cookies, authorization
headers and arbitrary query parameters are not. Request IDs are process-local;
use timestamps and the service invocation to distinguish restarts.

Embedded Go callers can set `Application.RequestLogger` before serving requests;
it is optional and defaults to disabled outside the native listener.
