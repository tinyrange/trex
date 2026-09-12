package star

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strconv"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	autostar "github.com/tinyrange/trex/auto/star"
	"go.starlark.net/starlark"
)

// web.browse is a route primitive, not a server. Applications keep control of
// routing and HTML while recursive resolution uses the portable Go auto API.
func webBrowseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var root *autostar.Value
	var request starlark.Value
	if err := starlark.UnpackArgs("web.browse", args, kwargs, "root", &root, "request", &request); err != nil {
		return nil, err
	}
	a, ok := request.(starlark.HasAttrs)
	if !ok {
		return nil, fmt.Errorf("web.browse: invalid request")
	}
	get := func(name string) starlark.Value { v, _ := a.Attr(name); return v }
	method, _ := starlark.AsString(get("method"))
	name, _ := starlark.AsString(get("path"))
	if method != "GET" && method != "HEAD" {
		r := browseError(http.StatusMethodNotAllowed, "use GET or HEAD")
		r.headers["Allow"] = "GET, HEAD"
		return r, nil
	}
	query, ok := get("query").(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("web.browse: invalid query")
	}
	q := func(key string) string {
		v, _, _ := query.Get(starlark.String(key))
		s, _ := starlark.AsString(v)
		return s
	}
	node, err := root.Node.Resolve(name)
	if err != nil {
		status := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, fs.ErrNotExist):
			status = http.StatusNotFound
		case errors.Is(err, fs.ErrInvalid):
			status = http.StatusBadRequest
		case errors.Is(err, auto.ErrLimit):
			status = http.StatusRequestEntityTooLarge
		}
		return browseError(status, err.Error()), nil
	}
	if q("json") != "1" && node.Reader() != nil {
		return &starlarkWebResponse{kind: "file", status: 200, body: nil, file: adapter.File(node.Reader()), name: path.Base(name), headers: map[string]string{"Content-Type": "application/octet-stream", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox"}}, nil
	}
	metadata, err := node.Metadata()
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, auto.ErrLimit) {
			status = http.StatusRequestEntityTooLarge
		}
		return browseError(status, err.Error()), nil
	}
	result := map[string]any{"path": name, "entry": metadata}
	if metadata.Container {
		offset, limit := 0, 500
		if s := q("offset"); s != "" {
			offset, err = strconv.Atoi(s)
			if err != nil || offset < 0 {
				return browseError(400, "invalid offset"), nil
			}
		}
		if s := q("limit"); s != "" {
			limit, err = strconv.Atoi(s)
			if err != nil || limit < 1 || limit > 1000 {
				return browseError(400, "limit must be between 1 and 1000"), nil
			}
		}
		children, err := node.Children()
		if err != nil {
			status := 422
			if errors.Is(err, auto.ErrLimit) {
				status = 413
			}
			return browseError(status, err.Error()), nil
		}
		start := min(offset, len(children))
		end := start + min(limit, len(children)-start)
		entries := make([]auto.Metadata, 0, end-start)
		for _, child := range children[start:end] {
			entries = append(entries, child.Summary())
		}
		result["children"] = entries
		result["total"] = len(children)
		result["offset"] = start
		if end < len(children) {
			result["next_offset"] = end
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &starlarkWebResponse{kind: "body", status: 200, body: starlark.Bytes(data), headers: map[string]string{"Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff"}}, nil
}
func browseError(status int, message string) *starlarkWebResponse {
	data, _ := json.Marshal(map[string]any{"error": message, "status": status})
	return &starlarkWebResponse{kind: "body", status: status, body: starlark.Bytes(data), headers: map[string]string{"Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff"}}
}
