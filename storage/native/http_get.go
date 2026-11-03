package native

import (
	"bytes"
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
	return httpRead(ctx, client, http.MethodGet, location, nil, maximum, nil)
}

// HTTPPostJSON sends a bounded JSON body, without retries or redirects.
func HTTPPostJSON(ctx context.Context, client *http.Client, location string, body []byte, maximum int64) (*starfile.Bytes, error) {
	return httpPostJSONHeaders(ctx, client, location, body, maximum, nil)
}

func httpPostJSONHeaders(ctx context.Context, client *http.Client, location string, body []byte, maximum int64, headers http.Header) (*starfile.Bytes, error) {
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("http_post_json: body exceeds 1MiB")
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return httpRead(ctx, &copyClient, http.MethodPost, location, body, maximum, headers)
}

func httpDo(ctx context.Context, client *http.Client, method, location string, body []byte, maximum int64, headers http.Header) (*http.Response, error) {
	operation := "http_get"
	if method == http.MethodPost {
		operation = "http_post_json"
	}
	if maximum <= 0 || maximum > 128<<20 {
		return nil, fmt.Errorf("%s: maximum must be 1..128MiB", operation)
	}
	u, err := url.Parse(location)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%s: expected HTTP(S) URL", operation)
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, method, location, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, describeTLSError(err)
	}
	return response, nil
}

func httpRead(ctx context.Context, client *http.Client, method, location string, body []byte, maximum int64, headers http.Header) (*starfile.Bytes, error) {
	operation := "http_get"
	if method == http.MethodPost {
		operation = "http_post_json"
	}
	response, err := httpDo(ctx, client, method, location, body, maximum, headers)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Keep server validation errors observable without unbounded reads or
		// rendering untrusted response bytes as terminal control sequences.
		limit := min(maximum, int64(4096))
		diagnostic, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
		truncated := int64(len(diagnostic)) > limit
		if truncated {
			diagnostic = diagnostic[:limit]
		}
		suffix := ""
		if truncated {
			suffix = " (body truncated)"
		}
		if len(diagnostic) != 0 {
			return nil, fmt.Errorf("%s: HTTP status %d: body=%q%s", operation, response.StatusCode, diagnostic, suffix)
		}
		if readErr != nil {
			return nil, fmt.Errorf("%s: HTTP status %d: reading error body: %w", operation, response.StatusCode, readErr)
		}
		return nil, fmt.Errorf("%s: HTTP status %d", operation, response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, fmt.Errorf("%s: response size limit", operation)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s: response size limit", operation)
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

func httpPostJSONBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var location, body string
	var captureResponse bool
	httpVersion := "auto"
	roots := starlark.Value(starlark.None)
	headerValues := starlark.Value(starlark.None)
	maximum := int64(8 << 20)
	timeout := 60
	if err := starlark.UnpackArgs("http_post_json", args, kwargs, "url", &location, "body", &body, "maximum?", &maximum, "timeout?", &timeout, "tls_roots?", &roots, "response?", &captureResponse, "headers?", &headerValues, "http_version?", &httpVersion); err != nil {
		return nil, err
	}
	if timeout < 1 || timeout > 3600 {
		return nil, fmt.Errorf("http_post_json: timeout must be 1..3600 seconds")
	}
	ctx := context.Background()
	if resources, err := lifecycle.ForThread(thread); err == nil {
		ctx = resources.Context()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	headers, err := requestHeaders(headerValues)
	if err != nil {
		return nil, err
	}
	client, err := httpClientWithRoots(roots)
	if err != nil {
		return nil, err
	}
	client, err = httpClientVersion(client, httpVersion)
	if err != nil {
		return nil, err
	}
	if roots != starlark.None || httpVersion != "auto" {
		defer client.CloseIdleConnections()
	}
	if captureResponse {
		return httpPostJSONResponseHeaders(ctx, client, location, []byte(body), maximum, headers)
	}
	return httpPostJSONHeaders(ctx, client, location, []byte(body), maximum, headers)
}
