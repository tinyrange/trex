package qemu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestQMPInterleavesEventsAndCorrelatesConcurrentReplies(t *testing.T) {
	clientChannel, targetChannel := net.Pipe()
	defer targetChannel.Close()
	targetErr := make(chan error, 1)
	go func() {
		decoder := json.NewDecoder(targetChannel)
		encoder := json.NewEncoder(targetChannel)
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{}}}); err != nil {
			targetErr <- err
			return
		}
		var capabilities map[string]any
		if err := decoder.Decode(&capabilities); err != nil {
			targetErr <- err
			return
		}
		if capabilities["execute"] != "qmp_capabilities" {
			targetErr <- fmt.Errorf("first command = %v", capabilities["execute"])
			return
		}
		if err := encoder.Encode(map[string]any{"return": map[string]any{}, "id": capabilities["id"]}); err != nil {
			targetErr <- err
			return
		}
		requests := make([]map[string]any, 2)
		for index := range requests {
			if err := decoder.Decode(&requests[index]); err != nil {
				targetErr <- err
				return
			}
		}
		if err := encoder.Encode(map[string]any{"event": "STOP", "data": map[string]any{"reason": "test"}}); err != nil {
			targetErr <- err
			return
		}
		for index := len(requests) - 1; index >= 0; index-- {
			if err := encoder.Encode(map[string]any{"return": requests[index]["execute"], "id": requests[index]["id"]}); err != nil {
				targetErr <- err
				return
			}
		}
		targetErr <- nil
	}()

	events := make(chan string, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := newQMPClient(ctx, clientChannel, func(name string, _ any) { events <- name })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	type result struct {
		command string
		value   any
		err     error
	}
	results := make(chan result, 2)
	for _, command := range []string{"query-status", "query-cpus-fast"} {
		command := command
		go func() {
			value, err := client.Call(ctx, command, nil)
			results <- result{command: command, value: value, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil || result.value != result.command {
			t.Fatalf("%s reply = %v, %v", result.command, result.value, result.err)
		}
	}
	if event := <-events; event != "STOP" {
		t.Fatalf("event = %q", event)
	}
	if err := <-targetErr; err != nil {
		t.Fatal(err)
	}
}

func qmpTestClient(t *testing.T) (*qmpClient, net.Conn, *json.Decoder, *json.Encoder) {
	t.Helper()
	transport, peer := net.Pipe()
	client := startQMPClient(transport, nil)
	t.Cleanup(func() { peer.Close(); client.Close() })
	decoder, encoder := json.NewDecoder(peer), json.NewEncoder(peer)
	result := make(chan error, 1)
	go func() {
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{}}); err != nil {
			result <- err
			return
		}
		var command map[string]any
		if err := decoder.Decode(&command); err != nil {
			result <- err
			return
		}
		result <- encoder.Encode(map[string]any{"id": command["id"], "return": map[string]any{}})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.negotiate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	return client, peer, decoder, encoder
}

func awaitQMPError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("QMP operation did not finish")
		return nil
	}
}

func TestQMPGreetingCancellationJoinsReader(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			transport, peer := net.Pipe()
			defer peer.Close()
			client := startQMPClient(transport, nil)
			defer client.Close()
			if partial {
				if _, err := io.WriteString(peer, `{"QMP":`); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- client.negotiate(ctx) }()
			cancel()
			if err := awaitQMPError(t, result); !errors.Is(err, context.Canceled) {
				t.Fatalf("negotiate: %v", err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.readDone:
			default:
				t.Fatal("Close returned before the decoder exited")
			}
		})
	}
}

func TestQMPInvalidGreetingClosesTransport(t *testing.T) {
	transport, peer := net.Pipe()
	defer peer.Close()
	result := make(chan error, 1)
	go func() {
		client, err := newQMPClient(context.Background(), transport, nil)
		if client != nil {
			client.Close()
		}
		result <- err
	}()
	if _, err := io.WriteString(peer, "{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := awaitQMPError(t, result); err == nil {
		t.Fatal("accepted invalid greeting")
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("failed greeting left transport open: %v", err)
	}
}

func TestQMPWriteCancellationClosesPartialStream(t *testing.T) {
	client, peer, _, _ := qmpTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := client.Call(ctx, "query-status", nil); result <- err }()
	// A prefix proves the write began, while withholding the rest keeps it
	// blocked regardless of the host's socket-buffer size.
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := awaitQMPError(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled partial write: %v", err)
	}
	if _, err := client.Call(context.Background(), "quit", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("reused a partial command stream: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQMPQueuedWriteCancellationPreservesActiveCommand(t *testing.T) {
	client, peer, _, encoder := qmpTestClient(t)
	first := make(chan error, 1)
	go func() {
		_, err := client.Call(context.Background(), "query-status", nil)
		first <- err
	}()
	prefix := make([]byte, 1)
	if _, err := io.ReadFull(peer, prefix); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() { _, err := client.Call(ctx, "must-not-send", nil); second <- err }()
	if err := awaitQMPError(t, second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued call: %v", err)
	}
	decoder := json.NewDecoder(io.MultiReader(bytes.NewReader(prefix), peer))
	var command map[string]any
	if err := decoder.Decode(&command); err != nil {
		t.Fatal(err)
	}
	if command["execute"] != "query-status" {
		t.Fatalf("wrong active command: %v", command)
	}
	if err := encoder.Encode(map[string]any{"id": command["id"], "return": "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := awaitQMPError(t, first); err != nil {
		t.Fatalf("queued cancellation interrupted active command: %v", err)
	}
}

func TestQMPReplyTimeoutPreservesCorrelation(t *testing.T) {
	client, _, decoder, encoder := qmpTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := client.Call(ctx, "first", nil); first <- err }()
	var old map[string]any
	if err := decoder.Decode(&old); err != nil {
		t.Fatal(err)
	}
	// Acquire write ownership to prove Call has completed its write and
	// stopped the cancellation callback before canceling its reply wait.
	client.writes <- struct{}{}
	cancel()
	<-client.writes
	if err := awaitQMPError(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("reply wait: %v", err)
	}
	second := make(chan error, 1)
	go func() {
		value, err := client.Call(context.Background(), "second", nil)
		if err == nil && value != "second reply" {
			err = fmt.Errorf("reply = %v", value)
		}
		second <- err
	}()
	var next map[string]any
	if err := decoder.Decode(&next); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Encode(map[string]any{"id": old["id"], "return": "late reply"}); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Encode(map[string]any{"id": next["id"], "return": "second reply"}); err != nil {
		t.Fatal(err)
	}
	if err := awaitQMPError(t, second); err != nil {
		t.Fatal(err)
	}
}

func TestQEMUStopFailureAndCancellation(t *testing.T) {
	for _, mode := range []string{"missing QMP", "blocked quit", "accepted but stalled", "already exited"} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{})
			if mode == "already exited" {
				close(done)
			}
			var killed atomic.Bool
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- stopQEMU(ctx, done, func(ctx context.Context) error {
					if _, bounded := ctx.Deadline(); !bounded {
						return fmt.Errorf("missing shutdown deadline")
					}
					switch mode {
					case "missing QMP":
						return io.ErrClosedPipe
					case "blocked quit":
						<-ctx.Done()
						return ctx.Err()
					}
					return nil
				}, func() error {
					killed.Store(true)
					close(done)
					return os.ErrProcessDone
				})
			}()
			if err := awaitQMPError(t, result); err != nil {
				t.Fatal(err)
			}
			if got, want := killed.Load(), mode != "already exited"; got != want {
				t.Fatalf("kill = %t, want %t", got, want)
			}
		})
	}
}
