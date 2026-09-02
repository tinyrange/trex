package debug

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type gdbAddressSpaceValue struct {
	session    *gdbSessionValue
	pageTable  uint64
	kind       string
	generation uint64
}

func (v *gdbAddressSpaceValue) String() string {
	return fmt.Sprintf("<gdb_address_space kind=%q page_table=%#x>", v.kind, v.pageTable)
}
func (v *gdbAddressSpaceValue) Type() string         { return "gdb_address_space" }
func (v *gdbAddressSpaceValue) Freeze()              {}
func (v *gdbAddressSpaceValue) Truth() starlark.Bool { return starlark.True }
func (v *gdbAddressSpaceValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", v.Type())
}
func (v *gdbAddressSpaceValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "generation":
		return starlark.MakeUint64(v.generation), nil
	case "kind":
		return starlark.String(v.kind), nil
	case "page_table":
		return starlark.MakeUint64(v.pageTable), nil
	case "read_memory":
		return starlark.NewBuiltin("address_space.read_memory", v.readMemoryBuiltin), nil
	}
	return nil, nil
}
func (v *gdbAddressSpaceValue) AttrNames() []string {
	return []string{"generation", "kind", "page_table", "read_memory"}
}

func (s *gdbSessionValue) addressSpaceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pageTable uint64
	kind := "user"
	if err := starlark.UnpackArgs("address_space", args, kwargs, "page_table", &pageTable, "kind?", &kind); err != nil {
		return nil, err
	}
	if pageTable == 0 || kind != "user" && kind != "kernel" {
		return nil, fmt.Errorf("address_space: invalid page table or kind")
	}
	if _, ok := s.registerMap["cr3"]; !ok {
		return nil, fmt.Errorf("address_space: target does not advertise cr3")
	}
	return &gdbAddressSpaceValue{session: s, pageTable: pageTable, kind: kind, generation: s.generation.Load()}, nil
}

func (v *gdbAddressSpaceValue) readMemoryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var size int
	timeout, err := unpackGDBTimeout("address_space.read_memory", args, kwargs, "address", &address, "size", &size)
	if err != nil {
		return nil, err
	}
	if size < 0 || size > v.session.memoryLimit || address > ^uint64(0)-uint64(size) {
		return nil, fmt.Errorf("address_space.read_memory: invalid or oversized range")
	}
	if v.session.closed.Load() {
		return nil, fmt.Errorf("address_space.read_memory: owning GDB session is closed")
	}
	if generation := v.session.generation.Load(); generation != v.generation {
		return nil, fmt.Errorf("address_space.read_memory: stale generation %d (session is %d)", v.generation, generation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*float64(time.Second)))
	defer cancel()
	register := v.session.registerMap["cr3"]
	encoded, err := encodeGDBRegister(new(big.Int).SetUint64(v.pageTable), register.Bits)
	if err != nil {
		return nil, err
	}
	v.session.scope.Lock()
	defer v.session.scope.Unlock()
	old, err := v.session.readRegisterInternal(ctx, register)
	if err != nil {
		return nil, err
	}
	if err := v.session.writeRegisterInternal(ctx, register, encoded); err != nil {
		return nil, err
	}
	data, readErr := v.session.readMemory(ctx, address, size)
	restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
	restoreErr := v.session.writeRegisterInternal(restoreCtx, register, old)
	restoreCancel()
	if readErr != nil {
		return nil, readErr
	}
	if restoreErr != nil {
		return nil, fmt.Errorf("address_space.read_memory: restore cr3: %w", restoreErr)
	}
	return starlark.Bytes(data), nil
}

func (s *gdbSessionValue) registersBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout, err := unpackGDBTimeout("registers", args, kwargs)
	if err != nil {
		return nil, err
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		registers, err := s.readAllRegisters(ctx)
		if err != nil {
			return nil, err
		}
		dict := starlark.NewDict(len(registers))
		for name, value := range registers {
			_ = dict.SetKey(starlark.String(name), value)
		}
		return dict, nil
	})
}

func (s *gdbSessionValue) readRegisterBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	timeout, err := unpackGDBTimeout("read_register", args, kwargs, "name", &name)
	if err != nil {
		return nil, err
	}
	register, ok := s.registerMap[name]
	if !ok {
		return nil, fmt.Errorf("read_register: target does not advertise %q", name)
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, err := wire.exchange([]byte(fmt.Sprintf("p%x", register.Number)))
			return reply, false, err
		})
		if err != nil {
			return nil, err
		}
		reply := value.([]byte)
		if isGDBError(reply) {
			return nil, fmt.Errorf("read_register: target returned %q", reply)
		}
		if len(reply) != register.Bits/4 {
			return nil, fmt.Errorf("read_register: got %d hexadecimal digits, want %d", len(reply), register.Bits/4)
		}
		return gdbRegisterValue(reply), nil
	})
}

func (s *gdbSessionValue) writeRegisterBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Int
	timeout, err := unpackGDBTimeout("write_register", args, kwargs, "name", &name, "value", &value)
	if err != nil {
		return nil, err
	}
	register, ok := s.registerMap[name]
	if !ok {
		return nil, fmt.Errorf("write_register: target does not advertise %q", name)
	}
	encoded, err := encodeGDBRegister(value.BigInt(), register.Bits)
	if err != nil {
		return nil, err
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		result, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, err := wire.exchange([]byte(fmt.Sprintf("P%x=%s", register.Number, encoded)))
			return reply, false, err
		})
		if err != nil {
			return nil, err
		}
		if string(result.([]byte)) != "OK" {
			return nil, fmt.Errorf("write_register: target returned %q", result)
		}
		return starlark.None, nil
	})
}

func encodeGDBRegister(value *big.Int, bits int) (string, error) {
	if value.Sign() < 0 || value.BitLen() > bits {
		return "", fmt.Errorf("register value does not fit in %d bits", bits)
	}
	data := make([]byte, bits/8)
	value.FillBytes(data)
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
	return hex.EncodeToString(data), nil
}

func (s *gdbSessionValue) withRegisterBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (result starlark.Value, err error) {
	var name string
	var value starlark.Int
	var callback starlark.Callable
	if err := starlark.UnpackArgs("with_register", args, kwargs, "name", &name, "value", &value, "callback", &callback); err != nil {
		return nil, err
	}
	register, ok := s.registerMap[name]
	if !ok {
		return nil, fmt.Errorf("with_register: target does not advertise %q", name)
	}
	encoded, err := encodeGDBRegister(value.BigInt(), register.Bits)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("trex.gdb.scope.%p", s)
	s.scope.Lock()
	defer s.scope.Unlock()
	previous := thread.Local(key)
	thread.SetLocal(key, s)
	defer thread.SetLocal(key, previous)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	old, err := s.readRegisterInternal(ctx, register)
	if err != nil {
		return nil, err
	}
	if err := s.writeRegisterInternal(ctx, register, encoded); err != nil {
		return nil, err
	}
	defer func() {
		restoreErr := s.writeRegisterInternal(context.Background(), register, old)
		if err == nil && restoreErr != nil {
			err = fmt.Errorf("with_register: restore %s: %w", name, restoreErr)
		}
	}()
	return starlark.Call(thread, callback, nil, nil)
}

type gdbMemorySnapshot struct {
	address uint64
	data    []byte
}

func (s *gdbSessionValue) withStateBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (result starlark.Value, err error) {
	var registerValues, memoryValues *starlark.List
	var callback starlark.Callable
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("with_state", args, kwargs, "registers", &registerValues, "memory", &memoryValues, "callback", &callback, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if timeout < 0 {
		return nil, fmt.Errorf("with_state: timeout must not be negative")
	}

	registers := make([]gdbRegister, 0, registerValues.Len())
	seenRegisters := make(map[string]bool)
	for index := 0; index < registerValues.Len(); index++ {
		name, ok := starlark.AsString(registerValues.Index(index))
		if !ok {
			return nil, fmt.Errorf("with_state: register %d is not a string", index)
		}
		register, ok := s.registerMap[name]
		if !ok {
			return nil, fmt.Errorf("with_state: target does not advertise %q", name)
		}
		if !seenRegisters[name] {
			seenRegisters[name] = true
			registers = append(registers, register)
		}
	}

	type memoryRange struct {
		address uint64
		size    int
	}
	ranges := make([]memoryRange, 0, memoryValues.Len())
	totalMemory := 0
	for index := 0; index < memoryValues.Len(); index++ {
		rangeValue, ok := memoryValues.Index(index).(starlark.Tuple)
		if !ok || len(rangeValue) != 2 {
			return nil, fmt.Errorf("with_state: memory range %d must be an (address, size) tuple", index)
		}
		var address uint64
		if err := starlark.AsInt(rangeValue[0], &address); err != nil {
			return nil, fmt.Errorf("with_state: memory range %d address: %w", index, err)
		}
		var size int
		if err := starlark.AsInt(rangeValue[1], &size); err != nil || size < 0 || size > s.memoryLimit-totalMemory || address > ^uint64(0)-uint64(size) {
			return nil, fmt.Errorf("with_state: invalid or oversized memory range %d", index)
		}
		totalMemory += size
		ranges = append(ranges, memoryRange{address: address, size: size})
	}

	key := fmt.Sprintf("trex.gdb.scope.%p", s)
	s.scope.Lock()
	defer s.scope.Unlock()
	previous := thread.Local(key)
	thread.SetLocal(key, s)
	defer thread.SetLocal(key, previous)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(float64(timeout)*float64(time.Second)))
	defer cancel()

	savedRegisters := make([]string, len(registers))
	for index, register := range registers {
		savedRegisters[index], err = s.readRegisterInternal(ctx, register)
		if err != nil {
			return nil, fmt.Errorf("with_state: save %s: %w", register.Name, err)
		}
	}
	snapshots := make([]gdbMemorySnapshot, len(ranges))
	for index, memoryRange := range ranges {
		data, readErr := s.readMemory(ctx, memoryRange.address, memoryRange.size)
		if readErr != nil {
			return nil, fmt.Errorf("with_state: save memory %#x: %w", memoryRange.address, readErr)
		}
		snapshots[index] = gdbMemorySnapshot{address: memoryRange.address, data: data}
	}

	defer func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer restoreCancel()
		if s.running.Load() {
			s.writeMu.Lock()
			interruptErr := writeAll(s.channel, []byte{3})
			s.writeMu.Unlock()
			if interruptErr == nil {
				select {
				case <-s.stops:
				case <-s.done:
				case <-restoreCtx.Done():
				}
			}
		}
		var restoreErr error
		for index := len(snapshots) - 1; index >= 0; index-- {
			if writeErr := s.writeMemory(restoreCtx, snapshots[index].address, snapshots[index].data); writeErr != nil && restoreErr == nil {
				restoreErr = fmt.Errorf("restore memory %#x: %w", snapshots[index].address, writeErr)
			}
		}
		for index := len(registers) - 1; index >= 0; index-- {
			if writeErr := s.writeRegisterInternal(restoreCtx, registers[index], savedRegisters[index]); writeErr != nil && restoreErr == nil {
				restoreErr = fmt.Errorf("restore %s: %w", registers[index].Name, writeErr)
			}
		}
		if restoreErr != nil && err == nil {
			err = fmt.Errorf("with_state: %w", restoreErr)
		}
	}()

	return starlark.Call(thread, callback, nil, nil)
}

func (s *gdbSessionValue) readRegisterInternal(ctx context.Context, register gdbRegister) (string, error) {
	value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
		reply, err := wire.exchange([]byte(fmt.Sprintf("p%x", register.Number)))
		return reply, false, err
	})
	if err != nil {
		return "", err
	}
	reply := string(value.([]byte))
	if len(reply) != register.Bits/4 {
		return "", fmt.Errorf("invalid register reply %q", reply)
	}
	return reply, nil
}

func (s *gdbSessionValue) writeRegisterInternal(ctx context.Context, register gdbRegister, encoded string) error {
	value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
		reply, err := wire.exchange([]byte(fmt.Sprintf("P%x=%s", register.Number, encoded)))
		return reply, false, err
	})
	if err != nil {
		return err
	}
	if string(value.([]byte)) != "OK" {
		return fmt.Errorf("target returned %q", value)
	}
	return nil
}

func (s *gdbSessionValue) readMemoryBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var size int
	timeout, err := unpackGDBTimeout("read_memory", args, kwargs, "address", &address, "size", &size)
	if err != nil {
		return nil, err
	}
	if size < 0 || size > s.memoryLimit || address > ^uint64(0)-uint64(size) {
		return nil, fmt.Errorf("read_memory: invalid or oversized range")
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		data, err := s.readMemory(ctx, address, size)
		if err != nil {
			return nil, err
		}
		return starlark.Bytes(data), nil
	})
}

func (s *gdbSessionValue) readMemory(ctx context.Context, address uint64, size int) ([]byte, error) {
	data := make([]byte, 0, size)
	maximum := (s.wire.packetSize - 64) / 2
	if maximum < 1 {
		maximum = 1
	}
	for len(data) < size {
		length := size - len(data)
		if length > maximum {
			length = maximum
		}
		value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, err := wire.exchange([]byte(fmt.Sprintf("m%x,%x", address+uint64(len(data)), length)))
			return reply, false, err
		})
		if err != nil {
			return nil, err
		}
		reply := value.([]byte)
		if isGDBError(reply) {
			return nil, fmt.Errorf("read_memory: target returned %q", reply)
		}
		chunk, err := decodeGDBHex(reply, length)
		if err != nil || len(chunk) != length {
			return nil, fmt.Errorf("read_memory: invalid target reply")
		}
		data = append(data, chunk...)
	}
	return data, nil
}

func (s *gdbSessionValue) writeMemoryBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var input starlark.Value
	timeout, err := unpackGDBTimeout("write_memory", args, kwargs, "address", &address, "data", &input)
	if err != nil {
		return nil, err
	}
	data, err := starfile.BytesForValue(input, int64(s.memoryLimit))
	if err != nil {
		return nil, fmt.Errorf("write_memory: invalid input: %w", err)
	}
	if address > ^uint64(0)-uint64(len(data)) {
		return nil, fmt.Errorf("write_memory: address range overflows")
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		return starlark.None, s.writeMemory(ctx, address, data)
	})
}

func (s *gdbSessionValue) writeMemory(ctx context.Context, address uint64, data []byte) error {
	maximum := (s.wire.packetSize - 128) / 2
	for offset := 0; offset < len(data); {
		length := len(data) - offset
		if length > maximum {
			length = maximum
		}
		packet := fmt.Sprintf("M%x,%x:%s", address+uint64(offset), length, hex.EncodeToString(data[offset:offset+length]))
		value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, err := wire.exchange([]byte(packet))
			return reply, false, err
		})
		if err != nil {
			return err
		}
		if string(value.([]byte)) != "OK" {
			return fmt.Errorf("target returned %q", value)
		}
		offset += length
	}
	return nil
}

func (s *gdbSessionValue) searchMemoryBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var start uint64
	var size int
	var patternValue starlark.Value
	limit := 1024
	timeout, err := unpackGDBTimeout("search_memory", args, kwargs, "start", &start, "size", &size, "pattern", &patternValue, "limit?", &limit)
	if err != nil {
		return nil, err
	}
	pattern, err := starfile.BytesForValue(patternValue, 1<<20)
	if err != nil || len(pattern) == 0 || size < 0 || size > s.memoryLimit || limit < 0 || limit > 1<<20 {
		return nil, fmt.Errorf("search_memory: invalid range, pattern, or limit")
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		const chunkSize = 1 << 20
		var carry []byte
		results := make([]starlark.Value, 0)
		for offset := 0; offset < size && len(results) < limit; {
			length := size - offset
			if length > chunkSize {
				length = chunkSize
			}
			chunk, err := s.readMemory(ctx, start+uint64(offset), length)
			if err != nil {
				return nil, err
			}
			window := append(append([]byte(nil), carry...), chunk...)
			base := start + uint64(offset-len(carry))
			for search := 0; search <= len(window)-len(pattern) && len(results) < limit; {
				found := bytes.Index(window[search:], pattern)
				if found < 0 {
					break
				}
				position := search + found
				if base+uint64(position) >= start {
					results = append(results, starlark.MakeUint64(base+uint64(position)))
				}
				search = position + 1
			}
			keep := len(pattern) - 1
			if keep > len(window) {
				keep = len(window)
			}
			carry = append(carry[:0], window[len(window)-keep:]...)
			offset += length
		}
		return starlark.NewList(results), nil
	})
}

func isGDBError(reply []byte) bool {
	return len(reply) >= 3 && reply[0] == 'E'
}

type gdbPointValue struct {
	session *gdbSessionValue
	kind    int
	address uint64
	size    int
	removed atomic.Bool
}

func (p *gdbPointValue) String() string {
	return fmt.Sprintf("<gdb_point kind=%d address=%#x size=%d>", p.kind, p.address, p.size)
}
func (p *gdbPointValue) Type() string          { return "gdb_point" }
func (p *gdbPointValue) Freeze()               {}
func (p *gdbPointValue) Truth() starlark.Bool  { return starlark.True }
func (p *gdbPointValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", p.Type()) }
func (p *gdbPointValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "address":
		return starlark.MakeUint64(p.address), nil
	case "size":
		return starlark.MakeInt(p.size), nil
	case "removed":
		return starlark.Bool(p.removed.Load()), nil
	case "remove":
		return starlark.NewBuiltin("remove", p.removeBuiltin), nil
	case "with_disabled":
		return starlark.NewBuiltin("with_disabled", p.withDisabledBuiltin), nil
	case "kind":
		return starlark.MakeInt(p.kind), nil
	}
	return nil, nil
}
func (p *gdbPointValue) AttrNames() []string {
	return []string{"address", "kind", "remove", "removed", "size", "with_disabled"}
}

func (p *gdbPointValue) withDisabledBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (result starlark.Value, err error) {
	var callback starlark.Callable
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("with_disabled", args, kwargs, "callback", &callback, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if p.removed.Load() {
		return nil, fmt.Errorf("with_disabled: GDB point is already removed")
	}
	key := fmt.Sprintf("trex.gdb.scope.%p", p.session)
	p.session.scope.Lock()
	defer p.session.scope.Unlock()
	previous := thread.Local(key)
	thread.SetLocal(key, p.session)
	defer thread.SetLocal(key, previous)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(float64(timeout)*float64(time.Second)))
	defer cancel()
	change := func(prefix byte, operation string) error {
		value, exchangeErr := p.session.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, wireErr := wire.exchange([]byte(fmt.Sprintf("%c%d,%x,%x", prefix, p.kind, p.address, p.size)))
			return reply, false, wireErr
		})
		if exchangeErr != nil {
			return exchangeErr
		}
		if string(value.([]byte)) != "OK" {
			return fmt.Errorf("%s GDB point: target returned %q", operation, value)
		}
		return nil
	}
	if err := change('z', "temporarily remove"); err != nil {
		return nil, err
	}
	p.removed.Store(true)
	defer func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer restoreCancel()
		value, restoreErr := p.session.execute(restoreCtx, func(wire *gdbWire) (any, bool, error) {
			reply, wireErr := wire.exchange([]byte(fmt.Sprintf("Z%d,%x,%x", p.kind, p.address, p.size)))
			return reply, false, wireErr
		})
		if restoreErr == nil && string(value.([]byte)) != "OK" {
			restoreErr = fmt.Errorf("target returned %q", value)
		}
		if restoreErr == nil {
			p.removed.Store(false)
		} else if err == nil {
			err = fmt.Errorf("with_disabled: restore GDB point: %w", restoreErr)
		}
	}()
	return starlark.Call(thread, callback, nil, nil)
}

func (s *gdbSessionValue) breakpointBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	kind, size := "hardware", 1
	timeout, err := unpackGDBTimeout("breakpoint", args, kwargs, "address", &address, "kind?", &kind, "size?", &size)
	if err != nil {
		return nil, err
	}
	pointKind := map[string]int{"software": 0, "hardware": 1}[kind]
	if kind != "software" && kind != "hardware" || size <= 0 {
		return nil, fmt.Errorf("breakpoint: invalid kind or size")
	}
	return s.installPoint(thread, timeout, pointKind, address, size)
}

func (s *gdbSessionValue) watchpointBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var size int
	access := "write"
	timeout, err := unpackGDBTimeout("watchpoint", args, kwargs, "address", &address, "size", &size, "access?", &access)
	if err != nil {
		return nil, err
	}
	kind, ok := map[string]int{"write": 2, "read": 3, "access": 4}[access]
	if !ok || size <= 0 {
		return nil, fmt.Errorf("watchpoint: invalid access or size")
	}
	return s.installPoint(thread, timeout, kind, address, size)
}

func (s *gdbSessionValue) installPoint(thread *starlark.Thread, timeout float64, kind int, address uint64, size int) (starlark.Value, error) {
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, err := wire.exchange([]byte(fmt.Sprintf("Z%d,%x,%x", kind, address, size)))
			return reply, false, err
		})
		if err != nil || string(value.([]byte)) != "OK" {
			return nil, fmt.Errorf("install GDB point: response %q: %w", value, err)
		}
		return &gdbPointValue{session: s, kind: kind, address: address, size: size}, nil
	})
}

func (p *gdbPointValue) removeBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout, err := unpackGDBTimeout("remove", args, kwargs)
	if err != nil {
		return nil, err
	}
	if p.removed.Load() {
		return starlark.None, nil
	}
	return p.session.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		value, err := p.session.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, err := wire.exchange([]byte(fmt.Sprintf("z%d,%x,%x", p.kind, p.address, p.size)))
			return reply, false, err
		})
		if err != nil || string(value.([]byte)) != "OK" {
			return nil, fmt.Errorf("remove GDB point: response %q: %w", value, err)
		}
		p.removed.Store(true)
		return starlark.None, nil
	})
}

func (s *gdbSessionValue) monitorBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var command string
	timeout, err := unpackGDBTimeout("monitor", args, kwargs, "command", &command)
	if err != nil {
		return nil, err
	}
	if len(command) > 1<<20 {
		return nil, fmt.Errorf("monitor: command too large")
	}
	return s.operation(thread, timeout, func(ctx context.Context) (starlark.Value, error) {
		value, err := s.execute(ctx, func(wire *gdbWire) (any, bool, error) {
			reply, err := wire.exchange([]byte("qRcmd," + hex.EncodeToString([]byte(command))))
			if err != nil {
				return nil, false, err
			}
			var output []byte
			for len(reply) > 0 && reply[0] == 'O' {
				chunk, err := decodeGDBHex(reply[1:], 8<<20-len(output))
				if err != nil {
					return nil, false, err
				}
				output = append(output, chunk...)
				reply, err = wire.read()
				if err != nil {
					return nil, false, err
				}
			}
			if string(reply) != "OK" {
				return nil, false, fmt.Errorf("monitor target returned %q", reply)
			}
			return output, false, nil
		})
		if err != nil {
			return nil, err
		}
		return starlark.Bytes(value.([]byte)), nil
	})
}

func (s *gdbSessionValue) closeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
		return nil, err
	}
	return starlark.None, s.Close()
}
