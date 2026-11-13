package native

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

type soapRoundTrip func(*http.Request) (*http.Response, error)

func (f soapRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func locationRequest() windowsupdate.Request {
	return windowsupdate.Request{Endpoint: windowsupdate.ClientSecured, Action: locationLookupAction, Body: []byte("same exact identity and profile"), UserAgent: "test"}
}

func TestLocationLookupRecoversStalledPartialBody(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(locationRequest().Body) {
			t.Error("changed request")
		}
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("partial-secret"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte("complete"))
	}))
	defer server.Close()
	var messages []string
	transport := Transport{Observe: func(s string) { messages = append(messages, s) }}
	response, err := transport.lookup(context.Background(), server.Client(), server.URL, locationRequest(), 1024,
		locationRetryPolicy{attempts: 3, attemptLimit: 100 * time.Millisecond, totalLimit: 2 * time.Second, backoff: time.Millisecond})
	if err != nil || string(response.Body) != "complete" || calls.Load() != 2 {
		t.Fatalf("response=%q calls=%d err=%v", response.Body, calls.Load(), err)
	}
	text := strings.Join(messages, "\n")
	if !strings.Contains(text, "bytes 14/100") || !strings.Contains(text, "retrying") || strings.Contains(text, "partial-secret") {
		t.Fatalf("diagnostics: %s", text)
	}
}

func TestLocationLookupExhaustionAndCancellation(t *testing.T) {
	for _, mode := range []string{"exhaust", "parent-deadline", "total-deadline", "cancel-backoff"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			parent := context.Background()
			var cancel context.CancelFunc = func() {}
			if mode == "parent-deadline" {
				parent, cancel = context.WithTimeout(parent, 60*time.Millisecond)
			}
			if mode == "cancel-backoff" {
				parent, cancel = context.WithCancel(parent)
			}
			defer cancel()
			client := &http.Client{Transport: soapRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if mode == "cancel-backoff" {
					return &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": {"30"}}, Body: io.NopCloser(strings.NewReader("busy"))}, nil
				}
				<-r.Context().Done()
				return nil, r.Context().Err()
			})}
			transport := Transport{Observe: func(s string) {
				if mode == "cancel-backoff" && strings.Contains(s, "retrying") {
					cancel()
				}
			}}
			total := time.Second
			if mode == "total-deadline" {
				total = 60 * time.Millisecond
			}
			_, err := transport.lookup(parent, client, "https://example.invalid", locationRequest(), 1024,
				locationRetryPolicy{attempts: 3, attemptLimit: 100 * time.Millisecond, totalLimit: total, backoff: time.Millisecond})
			wantCalls, wantErr := int32(3), error(context.DeadlineExceeded)
			if mode != "exhaust" {
				wantCalls = 1
			}
			if mode == "cancel-backoff" {
				wantErr = context.Canceled
			}
			if calls.Load() != wantCalls || !errors.Is(err, wantErr) {
				t.Fatalf("calls=%d err=%v", calls.Load(), err)
			}
		})
	}
}

func TestLocationLookupRetryStatusesAndPermanentFailures(t *testing.T) {
	for _, status := range []int{200, 400, 401, 403, 408, 429, 500, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: soapRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("SOAP fault or body")), Header: make(http.Header)}, nil
			})}
			response, err := (Transport{}).lookup(context.Background(), client, "https://example.invalid", locationRequest(), 1024,
				locationRetryPolicy{attempts: 3, attemptLimit: time.Second, totalLimit: time.Second, backoff: time.Millisecond})
			wantCalls := 1
			switch status {
			case 408, 429, 502, 503, 504:
				wantCalls = 3
			}
			if calls != wantCalls || err != nil || response.StatusCode != status {
				t.Fatalf("calls=%d response=%v err=%v", calls, response, err)
			}
		})
	}
	for _, mode := range []string{"certificate", "limit", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: soapRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "certificate" {
					return nil, x509.UnknownAuthorityError{}
				}
				if mode == "cancelled" {
					return nil, context.Canceled
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("too large")), Header: make(http.Header)}, nil
			})}
			_, err := (Transport{}).lookup(context.Background(), client, "https://example.invalid", locationRequest(), 2,
				locationRetryPolicy{attempts: 3, attemptLimit: time.Second, totalLimit: time.Second, backoff: time.Millisecond})
			if calls != 1 || err == nil {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestTransportRetriesOnlyLocationLookupAndClosesBodies(t *testing.T) {
	for _, lookup := range []bool{false, true} {
		calls, closed := 0, 0
		request := locationRequest()
		if !lookup {
			request.Action = "other"
		}
		client := &http.Client{Transport: soapRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			data, _ := io.ReadAll(r.Body)
			if string(data) != string(request.Body) {
				t.Error("request body was not replayed")
			}
			body := &soapTestBody{Reader: strings.NewReader("ok"), closed: &closed}
			if calls == 1 {
				body.err = io.ErrUnexpectedEOF
			}
			return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
		})}
		response, err := (Transport{Client: client}).Do(context.Background(), request)
		if lookup && (err != nil || string(response.Body) != "ok" || calls != 2) {
			t.Fatalf("lookup calls=%d body=%q err=%v", calls, response.Body, err)
		}
		if !lookup && (err == nil || calls != 1 || len(response.Body) != 0) {
			t.Fatalf("other action calls=%d err=%v", calls, err)
		}
		if closed != calls {
			t.Fatalf("closed %d of %d bodies", closed, calls)
		}
	}
}

type soapTestBody struct {
	*strings.Reader
	err    error
	closed *int
}

func (r *soapTestBody) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF && r.err != nil {
		return n, r.err
	}
	return n, err
}
func (r *soapTestBody) Close() error { *r.closed++; return nil }

func TestLocationRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"2", 2 * time.Second}, {now.Add(5 * time.Second).Format(http.TimeFormat), 5 * time.Second},
		{"-1", time.Second}, {"invalid", time.Second}, {"0", time.Second}, {"9223372036854775807", 24 * time.Hour},
	} {
		if got := lookupDelay(tc.header, time.Second, now); got != tc.want {
			t.Fatalf("%q delay=%s want=%s", tc.header, got, tc.want)
		}
	}
}
