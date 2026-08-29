package qemu

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
