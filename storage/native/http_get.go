package native

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// HTTPGet reads a bounded response into memory. HTTP transfer compression is
// handled by the native client; format compression remains the parser's job.
// No HEAD request, byte ranges, retries, disk cache or host intermediates.
func HTTPGet(ctx context.Context, client *http.Client, location string, maximum int64) (*starfile.Bytes, error) {
	if maximum <= 0 || maximum > 128<<20 {
		return nil, fmt.Errorf("http_get: maximum must be 1..128MiB")
	}
	u, err := url.Parse(location)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("http_get: expected HTTP(S) URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http_get: HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, fmt.Errorf("http_get: response size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("http_get: response size limit")
	}
	return &starfile.Bytes{Data: data}, nil
}
func httpGetBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var location string
	maximum := int64(64 << 20)
	timeout := 60
	if err := starlark.UnpackArgs("http_get", args, kwargs, "url", &location, "maximum?", &maximum, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if timeout < 1 || timeout > 3600 {
		return nil, fmt.Errorf("http_get: timeout must be 1..3600 seconds")
	}
	ctx := context.Background()
	if resources, err := lifecycle.ForThread(thread); err == nil {
		ctx = resources.Context()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	return HTTPGet(ctx, &http.Client{}, location, maximum)
}
