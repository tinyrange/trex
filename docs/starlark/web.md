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
