package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

const locationLookupAction = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2"

type locationRetryPolicy struct {
	attempts                          int
	attemptLimit, totalLimit, backoff time.Duration
}

type soapObservation struct {
	status               int
	bytes                int
	length               int64
	protocol, retryAfter string
	headers, elapsed     time.Duration
}

// sendSOAP consumes and closes every response, including failed/truncated ones.
// A partial body is never returned to the protocol parser or a later attempt.
func sendSOAP(ctx context.Context, client *http.Client, endpoint string, request windowsupdate.Request, maximum int64) (windowsupdate.Response, soapObservation, error) {
	started := time.Now()
	observation := soapObservation{length: -1}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(request.Body))
	if err != nil {
		return windowsupdate.Response{}, observation, fmt.Errorf("create request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	httpRequest.Header.Set("User-Agent", request.UserAgent)
	httpRequest.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(httpRequest)
	observation.headers = time.Since(started)
	observation.elapsed = observation.headers
	if err != nil {
		return windowsupdate.Response{}, observation, err
	}
	defer response.Body.Close()
	observation.status, observation.length, observation.protocol = response.StatusCode, response.ContentLength, response.Proto
	observation.retryAfter = response.Header.Get("Retry-After")
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	observation.bytes, observation.elapsed = len(body), time.Since(started)
	// Limits are terminal even if a malicious/buggy reader also returns an error.
	if int64(len(body)) > maximum {
		return windowsupdate.Response{}, observation, fmt.Errorf("response exceeds %d-byte limit", maximum)
	}
	if err != nil {
		return windowsupdate.Response{}, observation, fmt.Errorf("read response after %d bytes (Content-Length %d, HTTP %d, %s, headers %s, elapsed %s): %w",
			len(body), observation.length, observation.status, observation.protocol, observation.headers.Round(time.Millisecond), observation.elapsed.Round(time.Millisecond), err)
	}
	return windowsupdate.Response{StatusCode: response.StatusCode, Body: body}, observation, nil
}

func transientLookupError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var network net.Error
	return errors.As(err, &network) && (network.Timeout() || network.Temporary())
}

func transientLookupStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func lookupDelay(header string, fallback time.Duration, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(header), 10, 64); err == nil && seconds >= 0 {
		// No overflow and no retry earlier than a long server-requested delay:
		// the total operation context will expire before such a delay elapses.
		if seconds > 86400 {
			return 24 * time.Hour
		}
		return max(fallback, time.Duration(seconds)*time.Second)
	}
	if date, err := http.ParseTime(header); err == nil {
		return max(fallback, date.Sub(now))
	}
	return fallback
}

func (t Transport) lookup(parent context.Context, client *http.Client, endpoint string, request windowsupdate.Request, maximum int64, policy locationRetryPolicy) (windowsupdate.Response, error) {
	ctx, cancel := context.WithTimeout(parent, policy.totalLimit)
	defer cancel()
	for attempt := 1; attempt <= policy.attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return windowsupdate.Response{}, err
		}
		if t.Observe != nil {
			t.Observe(fmt.Sprintf("Windows Update locations: attempt %d/%d", attempt, policy.attempts))
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, policy.attemptLimit)
		response, observation, err := sendSOAP(attemptCtx, client, endpoint, request, maximum)
		cancelAttempt()
		if t.Observe != nil {
			t.Observe(fmt.Sprintf("Windows Update locations: attempt %d/%d HTTP %d %s, bytes %d/%d, headers %s, elapsed %s, complete=%t",
				attempt, policy.attempts, observation.status, observation.protocol, observation.bytes, observation.length,
				observation.headers.Round(time.Millisecond), observation.elapsed.Round(time.Millisecond), err == nil))
		}
		// Caller cancellation is terminal, including cancellation during a body
		// read or a retry delay. Never give a retry a fresh parent deadline.
		if ctx.Err() != nil {
			return windowsupdate.Response{}, fmt.Errorf("location lookup stopped after attempt %d: %w", attempt, ctx.Err())
		}
		retry := transientLookupError(err)
		if err == nil {
			retry = transientLookupStatus(response.StatusCode)
		}
		if observation.status != 0 && observation.status != http.StatusOK && !transientLookupStatus(observation.status) {
			retry = false
		}
		if !retry || attempt == policy.attempts {
			if err != nil {
				return windowsupdate.Response{}, fmt.Errorf("location lookup attempt %d/%d: %w", attempt, policy.attempts, err)
			}
			return response, nil
		}
		// Release an idle connection after a stalled/truncated response instead
		// of deliberately carrying the same failed connection into the retry.
		client.CloseIdleConnections()
		delay := lookupDelay(observation.retryAfter, policy.backoff*time.Duration(1<<(attempt-1)), time.Now())
		if t.Observe != nil {
			t.Observe(fmt.Sprintf("Windows Update locations: transient failure; retrying in %s", delay))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return windowsupdate.Response{}, fmt.Errorf("location lookup retry wait: %w", ctx.Err())
		case <-timer.C:
		}
	}
	panic("invalid location retry policy")
}
