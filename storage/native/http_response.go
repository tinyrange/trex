package native

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// httpPostJSONResponse observes status and bounded content even for non-200
// responses. Transport/TLS failures remain errors; redirects are never followed.
// A read failure is retained alongside any received bytes and HTTP metadata.
func httpPostJSONResponse(ctx context.Context, client *http.Client, location string, body []byte, maximum int64) (*starlark.Dict, error) {
	return httpPostJSONResponseHeaders(ctx, client, location, body, maximum, nil)
}

func httpPostJSONResponseHeaders(ctx context.Context, client *http.Client, location string, body []byte, maximum int64, headers http.Header) (*starlark.Dict, error) {
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("http_post_json: body exceeds 1MiB")
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpDo(ctx, &copyClient, http.MethodPost, location, body, maximum, headers)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	truncated := int64(len(data)) > maximum
	if truncated {
		data = data[:maximum]
	}
	readError := ""
	if readErr != nil {
		readError = readErr.Error()
	}
	encodings := make([]starlark.Value, len(response.TransferEncoding))
	for i, v := range response.TransferEncoding {
		encodings[i] = starlark.String(v)
	}
	fields := starlark.StringDict{
		"status":            starlark.String(response.Status),
		"status_code":       starlark.MakeInt(response.StatusCode),
		"protocol":          starlark.String(response.Proto),
		"headers":           responseHeaders(response.Header),
		"trailers":          responseHeaders(response.Trailer),
		"content_length":    starlark.MakeInt64(response.ContentLength),
		"transfer_encoding": starlark.NewList(encodings),
		"uncompressed":      starlark.Bool(response.Uncompressed),
		"body":              &starfile.Bytes{Data: data},
		"body_truncated":    starlark.Bool(truncated),
		"read_error":        starlark.String(readError),
		"complete":          starlark.Bool(!truncated && readErr == nil),
	}
	if response.TLS != nil {
		fields["tls_alpn"] = starlark.String(response.TLS.NegotiatedProtocol)
		fields["tls_version"] = starlark.MakeInt(int(response.TLS.Version))
		fields["tls_server_name"] = starlark.String(response.TLS.ServerName)
	}
	result := starlark.NewDict(len(fields))
	for key, value := range fields {
		_ = result.SetKey(starlark.String(key), value)
	}
	result.Freeze()
	return result, nil
}

func responseHeaders(headers http.Header) *starlark.Dict {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := starlark.NewDict(len(keys))
	for _, key := range keys {
		values := make([]starlark.Value, len(headers[key]))
		for i, value := range headers[key] {
			values[i] = starlark.String(value)
		}
		_ = result.SetKey(starlark.String(key), starlark.NewList(values))
	}
	result.Freeze()
	return result
}
