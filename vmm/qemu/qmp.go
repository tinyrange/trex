package qemu

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	channelpkg "github.com/tinyrange/trex/channel"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type qmpReply struct {
	value any
	err   error
}

// qmpClient has exactly one decoder goroutine. Calls are correlated by ID, so
// typed lifecycle methods and diagnostic QMP calls cannot steal each other's
// replies or asynchronous events.
type qmpClient struct {
	channel channelpkg.ByteChannel
	decoder *json.Decoder
	encoder *json.Encoder

	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[uint64]chan qmpReply
	closed  error
	nextID  atomic.Uint64
	event   func(string, any)
	done    chan struct{}
}

func newQMPClient(ctx context.Context, channel channelpkg.ByteChannel, event func(string, any)) (*qmpClient, error) {
	client := &qmpClient{
		channel: channel, decoder: json.NewDecoder(channel), encoder: json.NewEncoder(channel),
		pending: make(map[uint64]chan qmpReply), event: event, done: make(chan struct{}),
	}
	var greeting map[string]any
	if err := client.decoder.Decode(&greeting); err != nil {
		return nil, fmt.Errorf("QMP greeting: %w", err)
	}
	if _, ok := greeting["QMP"]; !ok {
		return nil, fmt.Errorf("QMP greeting is missing QMP metadata")
	}
	go client.readLoop()
	if _, err := client.Call(ctx, "qmp_capabilities", nil); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("QMP capabilities: %w", err)
	}
	return client, nil
}

func (c *qmpClient) Call(ctx context.Context, command string, arguments map[string]any) (any, error) {
	id := c.nextID.Add(1)
	reply := make(chan qmpReply, 1)
	c.mu.Lock()
	if c.closed != nil {
		err := c.closed
		c.mu.Unlock()
		return nil, err
	}
	c.pending[id] = reply
	c.mu.Unlock()

	request := map[string]any{"execute": command, "id": id}
	if len(arguments) != 0 {
		request["arguments"] = arguments
	}
	c.writeMu.Lock()
	err := c.encoder.Encode(request)
	c.writeMu.Unlock()
	if err != nil {
		c.removePending(id)
		return nil, err
	}
	select {
	case result := <-reply:
		return result.value, result.err
	case <-ctx.Done():
		c.removePending(id)
		return nil, ctx.Err()
	case <-c.done:
		c.mu.Lock()
		err := c.closed
		c.mu.Unlock()
		return nil, err
	}
}

func (c *qmpClient) readLoop() {
	for {
		var message map[string]any
		if err := c.decoder.Decode(&message); err != nil {
			c.fail(err)
			return
		}
		if event, ok := message["event"].(string); ok {
			if c.event != nil {
				c.event(event, message["data"])
			}
			continue
		}
		id, ok := jsonNumberUint64(message["id"])
		if !ok {
			continue
		}
		result := qmpReply{value: message["return"]}
		if qmpError, ok := message["error"].(map[string]any); ok {
			result.err = &vmmapi.Error{Code: vmmapi.ErrorBackend, Message: fmt.Sprint(qmpError["class"]), Detail: fmt.Sprint(qmpError["desc"])}
		}
		c.mu.Lock()
		pending := c.pending[id]
		delete(c.pending, id)
		c.mu.Unlock()
		if pending != nil {
			pending <- result
		}
	}
}

func (c *qmpClient) removePending(id uint64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *qmpClient) fail(err error) {
	c.mu.Lock()
	if c.closed != nil {
		c.mu.Unlock()
		return
	}
	if err == nil {
		err = io.EOF
	}
	c.closed = err
	pending := c.pending
	c.pending = make(map[uint64]chan qmpReply)
	close(c.done)
	c.mu.Unlock()
	for _, reply := range pending {
		reply <- qmpReply{err: err}
	}
}

func (c *qmpClient) Close() error {
	err := c.channel.Close()
	c.fail(err)
	return err
}

func jsonNumberUint64(value any) (uint64, bool) {
	switch value := value.(type) {
	case float64:
		if value >= 0 && value == float64(uint64(value)) {
			return uint64(value), true
		}
	case json.Number:
		parsed, err := value.Int64()
		return uint64(parsed), err == nil && parsed >= 0
	}
	return 0, false
}

func jsonValueToStarlark(value any) (starlark.Value, error) {
	switch value := value.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(value), nil
	case string:
		return starlark.String(value), nil
	case float64:
		return starlark.Float(value), nil
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			return starlark.MakeInt64(integer), nil
		}
		floating, err := value.Float64()
		if err != nil {
			return nil, err
		}
		return starlark.Float(floating), nil
	case []any:
		items := make([]starlark.Value, len(value))
		for index, item := range value {
			converted, err := jsonValueToStarlark(item)
			if err != nil {
				return nil, err
			}
			items[index] = converted
		}
		return starlark.NewList(items), nil
	case map[string]any:
		dict := starlark.NewDict(len(value))
		for key, item := range value {
			converted, err := jsonValueToStarlark(item)
			if err != nil {
				return nil, err
			}
			if err := dict.SetKey(starlark.String(key), converted); err != nil {
				return nil, err
			}
		}
		return dict, nil
	default:
		return nil, fmt.Errorf("unsupported JSON value %T", value)
	}
}
