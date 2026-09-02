package debug

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	channelpkg "github.com/tinyrange/trex/channel"
	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

const (
	defaultGDBMemoryLimit = 64 << 20
	defaultGDBStopQueue   = 256
)

type gdbCommand struct {
	run   func(*gdbWire) (any, bool, error)
	reply chan gdbCommandResult
}

type gdbCommandResult struct {
	value any
	err   error
}

type gdbActorFailure struct{ err error }

type gdbStop struct {
	raw       string
	kind      string
	signal    int
	thread    string
	watch     *big.Int
	fields    map[string]string
	registers map[string]starlark.Value
	pc        starlark.Value
}

type gdbSessionValue struct {
	channel      *channelstar.Value
	wire         *gdbWire
	architecture string
	features     map[string]string
	registers    []gdbRegister
	registerMap  map[string]gdbRegister
	memoryLimit  int

	commands   chan gdbCommand
	stops      chan gdbStop
	done       chan struct{}
	shutdown   chan struct{}
	ready      chan struct{}
	actorErr   atomic.Value
	running    atomic.Bool
	closed     atomic.Bool
	writeMu    sync.Mutex
	scope      sync.RWMutex
	close      sync.Once
	unregister func()
}

type Session = gdbSessionValue

func (s *gdbSessionValue) Architecture() string { return s.architecture }

func GDBBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var channelValue starlark.Value
	memoryLimit := defaultGDBMemoryLimit
	stopQueue := defaultGDBStopQueue
	timeout := starvalue.Number(15)
	if err := starlark.UnpackArgs("gdb", args, kwargs,
		"channel", &channelValue, "memory_limit?", &memoryLimit, "stop_queue?", &stopQueue, "timeout?", &timeout,
	); err != nil {
		return nil, err
	}
	channel, ok := channelValue.(*channelstar.Value)
	if !ok {
		return nil, fmt.Errorf("gdb: channel is %s, want byte_channel", channelValue.Type())
	}
	if memoryLimit <= 0 || memoryLimit > 1<<30 || stopQueue <= 0 || stopQueue > 65536 || timeout <= 0 {
		return nil, fmt.Errorf("gdb: invalid resource limit or timeout")
	}
	session := &gdbSessionValue{
		channel: channel, wire: newGDBWire(channel), memoryLimit: memoryLimit,
		commands: make(chan gdbCommand), stops: make(chan gdbStop, stopQueue), done: make(chan struct{}), shutdown: make(chan struct{}), ready: make(chan struct{}, 1),
		registerMap: make(map[string]gdbRegister),
	}
	if err := session.negotiate(time.Duration(float64(timeout) * float64(time.Second))); err != nil {
		_ = channel.Close()
		return nil, fmt.Errorf("gdb: negotiate: %w", err)
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		_ = channel.Close()
		return nil, err
	}
	unregister, err := resources.Add(session)
	if err != nil {
		_ = channel.Close()
		return nil, err
	}
	session.unregister = unregister
	go session.actor()
	return session, nil
}

func setByteChannelDeadline(channel channelpkg.ByteChannel, timeout time.Duration) {
	setter, ok := channel.(channelpkg.DeadlineSetter)
	if !ok {
		return
	}
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	_ = setter.SetDeadline(deadline)
}

func (s *gdbSessionValue) negotiate(timeout time.Duration) error {
	setByteChannelDeadline(s.channel, timeout)
	defer setByteChannelDeadline(s.channel, 0)
	reply, err := s.wire.exchange([]byte("qSupported:multiprocess+;xmlRegisters=i386"))
	if err != nil {
		return err
	}
	s.features = parseGDBFeatures(reply)
	if value := s.features["PacketSize"]; value != "" {
		size, err := strconv.ParseInt(value, 16, 32)
		if err != nil || size < 256 || size > maximumGDBPacketSize {
			return fmt.Errorf("invalid target PacketSize %q", value)
		}
		s.wire.packetSize = int(size)
	}
	if s.features["QStartNoAckMode"] == "+" {
		reply, err := s.wire.exchange([]byte("QStartNoAckMode"))
		if err != nil {
			return err
		}
		if string(reply) == "OK" {
			s.wire.noAck = true
		}
	}
	architecture, registers, err := s.wire.targetDescription()
	if err != nil {
		return err
	}
	if len(registers) == 0 {
		return fmt.Errorf("target exposes no registers")
	}
	s.architecture, s.registers = architecture, registers
	for _, register := range registers {
		if _, exists := s.registerMap[register.Name]; exists {
			return fmt.Errorf("duplicate target register %q", register.Name)
		}
		s.registerMap[register.Name] = register
	}
	return nil
}

func (s *gdbSessionValue) actor() {
	defer close(s.done)
	defer close(s.stops)
	for {
		var command gdbCommand
		select {
		case command = <-s.commands:
		case <-s.shutdown:
			return
		}
		value, awaitStop, err := command.run(s.wire)
		if awaitStop && err == nil {
			s.running.Store(true)
		}
		command.reply <- gdbCommandResult{value: value, err: err}
		if err != nil {
			s.setActorError(err)
			return
		}
		if !awaitStop {
			continue
		}
		packet, err := s.wire.read()
		s.running.Store(false)
		if err != nil {
			s.setActorError(err)
			return
		}
		stop := parseGDBStop(packet)
		select {
		case s.stops <- stop:
			select {
			case s.ready <- struct{}{}:
			default:
			}
		default:
			s.setActorError(fmt.Errorf("GDB stop queue overflow"))
			return
		}
	}
}

func (s *gdbSessionValue) setActorError(err error) {
	if err != nil {
		s.actorErr.Store(&gdbActorFailure{err: err})
	}
}

func (s *gdbSessionValue) execute(ctx context.Context, run func(*gdbWire) (any, bool, error)) (any, error) {
	if s.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	command := gdbCommand{run: run, reply: make(chan gdbCommandResult, 1)}
	select {
	case s.commands <- command:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.err()
	case <-s.shutdown:
		return nil, io.ErrClosedPipe
	}
	select {
	case result := <-command.reply:
		return result.value, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.err()
	case <-s.shutdown:
		return nil, io.ErrClosedPipe
	}
}

func (s *gdbSessionValue) err() error {
	if value := s.actorErr.Load(); value != nil {
		return value.(*gdbActorFailure).err
	}
	return io.EOF
}

func (s *gdbSessionValue) Close() error {
	s.close.Do(func() {
		s.closed.Store(true)
		if s.unregister != nil {
			s.unregister()
		}
		_ = s.channel.Close()
		close(s.shutdown)
	})
	return nil
}

func (s *gdbSessionValue) String() string {
	return fmt.Sprintf("<gdb architecture=%q packet_size=%d>", s.architecture, s.wire.packetSize)
}
func (s *gdbSessionValue) DebugReady() <-chan struct{} { return s.ready }
func (s *gdbSessionValue) Type() string                { return "gdb" }
func (s *gdbSessionValue) Freeze()                     {}
func (s *gdbSessionValue) Truth() starlark.Bool        { return starlark.True }
func (s *gdbSessionValue) Hash() (uint32, error)       { return 0, fmt.Errorf("unhashable: %s", s.Type()) }
func (s *gdbSessionValue) Attr(name string) (starlark.Value, error) {
	methods := map[string]func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){
		"breakpoint": s.breakpointBuiltin, "close": s.closeBuiltin, "continue": s.continueBuiltin,
		"interrupt": s.interruptBuiltin, "monitor": s.monitorBuiltin, "packet": s.packetBuiltin,
		"read_memory": s.readMemoryBuiltin, "read_register": s.readRegisterBuiltin,
		"registers": s.registersBuiltin, "search_memory": s.searchMemoryBuiltin,
		"step": s.stepBuiltin, "wait": s.waitBuiltin, "watchpoint": s.watchpointBuiltin,
		"with_register": s.withRegisterBuiltin, "with_state": s.withStateBuiltin, "write_memory": s.writeMemoryBuiltin,
		"write_register": s.writeRegisterBuiltin,
	}
	if method := methods[name]; method != nil {
		return starlark.NewBuiltin(name, method), nil
	}
	switch name {
	case "architecture":
		return starlark.String(s.architecture), nil
	case "features":
		dict := starlark.NewDict(len(s.features))
		for name, value := range s.features {
			_ = dict.SetKey(starlark.String(name), starlark.String(value))
		}
		return dict, nil
	case "running":
		return starlark.Bool(s.running.Load()), nil
	}
	return nil, nil
}
func (s *gdbSessionValue) AttrNames() []string {
	return []string{"architecture", "breakpoint", "close", "continue", "features", "interrupt", "monitor", "packet", "read_memory", "read_register", "registers", "running", "search_memory", "step", "wait", "watchpoint", "with_register", "with_state", "write_memory", "write_register"}
}

func (s *gdbSessionValue) operation(thread *starlark.Thread, timeout float64, run func(context.Context) (starlark.Value, error)) (starlark.Value, error) {
	key := fmt.Sprintf("trex.gdb.scope.%p", s)
	owned := thread != nil && thread.Local(key) == s
	if !owned {
		s.scope.RLock()
		defer s.scope.RUnlock()
	}
	ctx := context.Background()
	cancel := func() {}
	if timeout >= 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout*float64(time.Second)))
	}
	defer cancel()
	return run(ctx)
}

func unpackGDBTimeout(name string, args starlark.Tuple, kwargs []starlark.Tuple, fields ...any) (float64, error) {
	timeout := starvalue.Number(30)
	fields = append(fields, "timeout?", &timeout)
	if err := starlark.UnpackArgs(name, args, kwargs, fields...); err != nil {
		return 0, err
	}
	if timeout < 0 || timeout > 86400 {
		return 0, fmt.Errorf("%s: invalid timeout", name)
	}
	return float64(timeout), nil
}

func (s *gdbSessionValue) packetBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var payload starlark.Value
	timeout, err := unpackGDBTimeout("packet", args, kwargs, "payload", &payload)
	if err != nil {
		return nil, err
	}
	data, err := starfile.BytesForValue(payload, int64(s.wire.packetSize))
	if err != nil {
		return nil, err
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) { reply, err := wire.exchange(data); return reply, false, err })
		if err != nil {
			return nil, err
		}
		return starlark.Bytes(value.([]byte)), nil
	})
}

func (s *gdbSessionValue) continueBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return s.executionBuiltin(thread, "continue", "c", args, kwargs)
}
func (s *gdbSessionValue) stepBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return s.executionBuiltin(thread, "step", "s", args, kwargs)
}
func (s *gdbSessionValue) executionBuiltin(thread *starlark.Thread, name, packet string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout, err := unpackGDBTimeout(name, args, kwargs)
	if err != nil {
		return nil, err
	}
	if s.running.Load() {
		return nil, &vmmapi.Error{Code: vmmapi.ErrorState, Message: "GDB target is already running"}
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		_, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) { return nil, true, wire.send([]byte(packet)) })
		return starlark.None, err
	})
}

func (s *gdbSessionValue) interruptBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout, err := unpackGDBTimeout("interrupt", args, kwargs)
	if err != nil {
		return nil, err
	}
	return s.operation(thread, timeout, func(_ context.Context) (starlark.Value, error) {
		if !s.running.Load() {
			return nil, &vmmapi.Error{Code: vmmapi.ErrorState, Message: "GDB target is not running"}
		}
		s.writeMu.Lock()
		err := writeAll(s.channel, []byte{3})
		s.writeMu.Unlock()
		return starlark.None, err
	})
}

func (s *gdbSessionValue) waitBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout, err := unpackGDBTimeout("wait", args, kwargs)
	if err != nil {
		return nil, err
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		var stop gdbStop
		select {
		case value, ok := <-s.stops:
			if !ok {
				return nil, s.err()
			}
			stop = value
			select {
			case <-s.ready:
			default:
			}
		default:
		}
		if stop.fields != nil {
			if err := s.selectStoppedThread(ctx, stop.thread); err != nil {
				return nil, err
			}
			registers, err := s.readAllRegisters(ctx)
			if err == nil {
				stop.registers = registers
				for _, name := range []string{"pc", "eip", "rip"} {
					if value, ok := registers[name]; ok {
						stop.pc = value
						break
					}
				}
			}
			return gdbStopValue(stop), nil
		}
		select {
		case value, ok := <-s.stops:
			if !ok {
				return nil, s.err()
			}
			stop = value
			select {
			case <-s.ready:
			default:
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if err := s.selectStoppedThread(ctx, stop.thread); err != nil {
			return nil, err
		}
		registers, err := s.readAllRegisters(ctx)
		if err == nil {
			stop.registers = registers
			for _, name := range []string{"pc", "eip", "rip"} {
				if value, ok := registers[name]; ok {
					stop.pc = value
					break
				}
			}
		}
		return gdbStopValue(stop), nil
	})
}

func (s *gdbSessionValue) selectStoppedThread(ctx context.Context, thread string) error {
	if thread == "" {
		return nil
	}
	value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
		reply, err := wire.exchange([]byte("Hg" + thread))
		return reply, false, err
	})
	if err != nil {
		return err
	}
	if reply := string(value.([]byte)); reply != "OK" {
		return fmt.Errorf("select stopped GDB thread %s: target returned %q", thread, reply)
	}
	return nil
}

func parseGDBStop(packet []byte) gdbStop {
	stop := gdbStop{raw: string(packet), fields: make(map[string]string), pc: starlark.None}
	if len(packet) < 3 {
		stop.kind = "unknown"
		return stop
	}
	switch packet[0] {
	case 'S', 'T':
		stop.kind = "signal"
		signal, _ := strconv.ParseUint(string(packet[1:3]), 16, 8)
		stop.signal = int(signal)
		if packet[0] == 'T' {
			for _, field := range strings.Split(string(packet[3:]), ";") {
				name, value, ok := strings.Cut(field, ":")
				if !ok || name == "" {
					continue
				}
				stop.fields[name] = value
				if name == "thread" {
					stop.thread = value
				}
				if name == "watch" || name == "rwatch" || name == "awatch" {
					watch := new(big.Int)
					if _, ok := watch.SetString(value, 16); ok {
						stop.watch = watch
					}
				}
			}
		}
	case 'W':
		stop.kind = "exited"
	case 'X':
		stop.kind = "terminated"
	default:
		stop.kind = "unknown"
	}
	return stop
}

func gdbStopValue(stop gdbStop) starlark.Value {
	registers := starlark.NewDict(len(stop.registers))
	for name, value := range stop.registers {
		_ = registers.SetKey(starlark.String(name), value)
	}
	fields := starlark.NewDict(len(stop.fields))
	for name, value := range stop.fields {
		_ = fields.SetKey(starlark.String(name), starlark.String(value))
	}
	watch := starlark.Value(starlark.None)
	if stop.watch != nil {
		watch = starlark.MakeBigInt(stop.watch)
	}
	return starvalue.NewRecord(starlark.StringDict{
		"fields": fields, "kind": starlark.String(stop.kind), "pc": stop.pc,
		"raw": starlark.Bytes(stop.raw), "registers": registers,
		"signal": starlark.MakeInt(stop.signal), "thread": starlark.String(stop.thread), "watch_address": watch,
	})
}

func (s *gdbSessionValue) readAllRegisters(ctx context.Context) (map[string]starlark.Value, error) {
	value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
		reply, err := wire.exchange([]byte("g"))
		return reply, false, err
	})
	if err != nil {
		return nil, err
	}
	reply := value.([]byte)
	registers := make(map[string]starlark.Value, len(s.registers))
	for _, register := range s.registers {
		start, end := register.Offset*2, (register.Offset+register.Bits/8)*2
		if end > len(reply) {
			return nil, fmt.Errorf("short GDB register reply")
		}
		registers[register.Name] = gdbRegisterValue(reply[start:end])
	}
	return registers, nil
}

func gdbRegisterValue(encoded []byte) starlark.Value {
	if bytes.Contains(encoded, []byte("x")) {
		return starlark.None
	}
	data := make([]byte, len(encoded)/2)
	if _, err := hex.Decode(data, encoded); err != nil {
		return starlark.None
	}
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
	return starlark.MakeBigInt(new(big.Int).SetBytes(data))
}
