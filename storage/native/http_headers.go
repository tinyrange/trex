package native

import (
	"fmt"
	"net/http"
	"strings"

	"go.starlark.net/starlark"
)

// Request headers are caller-owned metadata. Framing/routing remain owned by
// net/http, and JSON content type remains owned by this JSON-specific API.
func requestHeaders(value starlark.Value) (http.Header, error) {
	if value == nil || value == starlark.None {
		return nil, nil
	}
	dict, ok := value.(*starlark.Dict)
	if !ok || dict.Len() > 64 {
		return nil, fmt.Errorf("headers: expected at most 64 string-to-string fields")
	}
	headers := make(http.Header, dict.Len())
	size := 0
	for _, item := range dict.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok || name == "" {
			return nil, fmt.Errorf("headers: expected nonempty string name")
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return nil, fmt.Errorf("headers: invalid field name")
			}
		}
		text, ok := starlark.AsString(item[1])
		if !ok {
			return nil, fmt.Errorf("headers: expected string value")
		}
		for _, c := range text {
			if c < 32 && c != '\t' || c == 127 {
				return nil, fmt.Errorf("headers: invalid control character")
			}
		}
		canonical := http.CanonicalHeaderKey(name)
		switch canonical {
		case "Host", "Content-Length", "Transfer-Encoding", "Connection", "Content-Type", "Idempotency-Key", "X-Idempotency-Key":
			return nil, fmt.Errorf("headers: framing, routing, replay policy and JSON content type cannot be overridden")
		}
		if _, duplicate := headers[canonical]; duplicate {
			return nil, fmt.Errorf("headers: duplicate case-insensitive name")
		}
		size += len(name) + len(text) + 4
		if size > 64<<10 {
			return nil, fmt.Errorf("headers: exceeds 64KiB")
		}
		headers.Set(canonical, text)
	}
	return headers, nil
}
