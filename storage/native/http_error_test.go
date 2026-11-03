package native

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type errorBodyTransport struct{ body io.ReadCloser }

func (r errorBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 400, Body: r.body, Header: make(http.Header)}, nil
}

type countedErrorBody struct {
	reads  int
	closed bool
}

func (b *countedErrorBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.reads += len(p)
	return len(p), nil
}
func (b *countedErrorBody) Close() error { b.closed = true; return nil }

func TestHTTPErrorDiagnosticBoundedAndEscaped(t *testing.T) {
	for _, maximum := range []int64{7, 8192} {
		b := &countedErrorBody{}
		client := &http.Client{Transport: errorBodyTransport{b}}
		_, err := HTTPPostJSON(context.Background(), client, "https://example.invalid", nil, maximum)
		bound := int(min(maximum, 4096))
		if err == nil || !strings.Contains(err.Error(), "HTTP status 400") || !strings.Contains(err.Error(), "body truncated") {
			t.Fatalf("missing bounded status/body diagnostic: %v", err)
		}
		if b.reads != bound+1 || !b.closed {
			t.Fatalf("read %d bytes (bound %d), closed=%v", b.reads, bound+1, b.closed)
		}
	}
	client := &http.Client{Transport: errorBodyTransport{io.NopCloser(strings.NewReader("invalid Products\n\x1b[31m"))}}
	_, err := HTTPPostJSON(context.Background(), client, "https://example.invalid", nil, 1024)
	if err == nil || !strings.Contains(err.Error(), "invalid Products") || strings.ContainsAny(err.Error(), "\n\x1b") || strings.Contains(err.Error(), "truncated") {
		t.Fatalf("unsafe or missing server diagnostic: %v", err)
	}
}
