package kd

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync/atomic"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func (s *kdSessionValue) requestBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var api uint64
	processor := -1
	var arguments *starlark.Dict
	var dataValue starlark.Value = starlark.Bytes("")
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("request", args, kwargs, "api", &api, "processor?", &processor, "arguments?", &arguments, "data?", &dataValue, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if api > math.MaxUint32 || processor < -1 || processor > math.MaxUint16 {
		return nil, fmt.Errorf("request: API or processor is out of range")
	}
	if processor < 0 {
		s.stateMu.Lock()
		processor = int(s.processor)
		s.stateMu.Unlock()
	}
	union, err := kdArguments(arguments)
	if err != nil {
		return nil, err
	}
	data, err := starfile.BytesForValue(dataValue, int64(s.wire.maximum-kdManipulateSize))
	if err != nil {
		return nil, err
	}
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	packet, err := s.request(ctx, uint32(api), uint16(processor), union, data)
	if err != nil {
		return nil, err
	}
	return kdManipulateValue(packet), nil
}

func kdArguments(arguments *starlark.Dict) ([]byte, error) {
	union := make([]byte, kdManipulateSize-16)
	if arguments == nil {
		return union, nil
	}
	for _, item := range arguments.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("request: argument name is %s, want string", item[0].Type())
		}
		integer, ok := item[1].(starlark.Int)
		if !ok {
			return nil, fmt.Errorf("request: argument %q is %s, want int", name, item[1].Type())
		}
		value := integer.BigInt()
		if value.Sign() < 0 || !value.IsUint64() {
			return nil, fmt.Errorf("request: argument %q is out of range", name)
		}
		number := value.Uint64()
		offset, width := -1, 8
		switch name {
		case "address", "arg0":
			offset = 0
		case "transfer_count", "breakpoint_handle":
			offset, width = 8, 4
		case "actual_bytes":
			offset, width = 12, 4
		case "arg1":
			offset = 8
		case "arg2":
			offset = 16
		case "arg3":
			offset = 24
		case "arg4":
			offset = 32
		default:
			return nil, fmt.Errorf("request: unknown argument %q", name)
		}
		if width == 4 {
			if number > math.MaxUint32 {
				return nil, fmt.Errorf("request: argument %q exceeds 32 bits", name)
			}
			binary.LittleEndian.PutUint32(union[offset:], uint32(number))
		} else {
			binary.LittleEndian.PutUint64(union[offset:], number)
		}
	}
	return union, nil
}

func (s *kdSessionValue) contextBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("context", args, kwargs, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if s.architecture != "" && s.architecture != "i386" {
		return nil, fmt.Errorf("context: architecture %q is not implemented", s.architecture)
	}
	s.stateMu.Lock()
	processor := s.processor
	s.stateMu.Unlock()
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	packet, err := s.request(ctx, kdAPIGetContext, processor, nil, nil)
	if err != nil {
		return nil, err
	}
	if status := kdU32(packet.Payload, 8); status != 0 {
		return nil, fmt.Errorf("context: target status %#x", status)
	}
	_, manipulateSize := s.manipulateLayout()
	if len(packet.Payload) < manipulateSize+204 {
		return nil, fmt.Errorf("context: short x86 context (%d bytes)", len(packet.Payload)-manipulateSize)
	}
	data := packet.Payload[manipulateSize : manipulateSize+204]
	return starvalue.NewRecord(starlark.StringDict{
		"edi": starlark.MakeUint64(uint64(kdU32(data, 156))), "esi": starlark.MakeUint64(uint64(kdU32(data, 160))),
		"ebx": starlark.MakeUint64(uint64(kdU32(data, 164))), "edx": starlark.MakeUint64(uint64(kdU32(data, 168))),
		"ecx": starlark.MakeUint64(uint64(kdU32(data, 172))), "eax": starlark.MakeUint64(uint64(kdU32(data, 176))),
		"ebp": starlark.MakeUint64(uint64(kdU32(data, 180))), "eip": starlark.MakeUint64(uint64(kdU32(data, 184))),
		"eflags": starlark.MakeUint64(uint64(kdU32(data, 192))), "esp": starlark.MakeUint64(uint64(kdU32(data, 196))),
		"raw": starlark.Bytes(data),
	}), nil
}

func (s *kdSessionValue) setContextBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rawValue starlark.Value
	edi, esi, ebx, edx := starlark.Value(starlark.None), starlark.Value(starlark.None), starlark.Value(starlark.None), starlark.Value(starlark.None)
	ecx, eax, ebp, eip := starlark.Value(starlark.None), starlark.Value(starlark.None), starlark.Value(starlark.None), starlark.Value(starlark.None)
	eflags, esp := starlark.Value(starlark.None), starlark.Value(starlark.None)
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("set_context", args, kwargs,
		"raw", &rawValue,
		"edi?", &edi, "esi?", &esi, "ebx?", &ebx, "edx?", &edx,
		"ecx?", &ecx, "eax?", &eax, "ebp?", &ebp, "eip?", &eip,
		"eflags?", &eflags, "esp?", &esp,
		"timeout?", &timeout,
	); err != nil {
		return nil, err
	}
	if s.architecture != "" && s.architecture != "i386" {
		return nil, fmt.Errorf("set_context: architecture %q is not implemented", s.architecture)
	}
	data, err := starfile.BytesForValue(rawValue, 204)
	if err != nil || len(data) != 204 {
		return nil, fmt.Errorf("set_context: raw must be exactly 204 bytes")
	}
	data = append([]byte(nil), data...)
	offsets := map[string]int{
		"edi": 156, "esi": 160, "ebx": 164, "edx": 168, "ecx": 172,
		"eax": 176, "ebp": 180, "eip": 184, "eflags": 192, "esp": 196,
	}
	registerValues := map[string]starlark.Value{
		"edi": edi, "esi": esi, "ebx": ebx, "edx": edx, "ecx": ecx,
		"eax": eax, "ebp": ebp, "eip": eip, "eflags": eflags, "esp": esp,
	}
	for name, value := range registerValues {
		if value == starlark.None {
			continue
		}
		var number uint64
		if err := starlark.AsInt(value, &number); err != nil || number > math.MaxUint32 {
			return nil, fmt.Errorf("set_context: %s must fit in uint32", name)
		}
		binary.LittleEndian.PutUint32(data[offsets[name]:], uint32(number))
	}
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	packet, err := s.request(ctx, kdAPISetContext, s.currentProcessor(), nil, data)
	if err != nil {
		return nil, err
	}
	if status := kdU32(packet.Payload, 8); status != 0 {
		return nil, fmt.Errorf("set_context: target status %#x", status)
	}
	return starlark.None, nil
}

func (s *kdSessionValue) readVirtualBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return s.readMemoryBuiltin("read_virtual", kdAPIReadVirtual, args, kwargs)
}

func (s *kdSessionValue) readPhysicalBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return s.readMemoryBuiltin("read_physical", kdAPIReadPhysical, args, kwargs)
}

func (s *kdSessionValue) readMemoryBuiltin(name string, api uint32, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var size int
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if size < 0 || size > s.memoryLimit || address > math.MaxUint64-uint64(size) {
		return nil, fmt.Errorf("%s: invalid range", name)
	}
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	data := make([]byte, 0, size)
	for len(data) < size {
		unionOffset, manipulateSize := s.manipulateLayout()
		length := min(size-len(data), s.wire.maximum-manipulateSize)
		union := make([]byte, manipulateSize-unionOffset)
		actualOffset := 12
		if s.targetIs64() {
			current := address + uint64(len(data))
			if api == kdAPIReadVirtual {
				current, err = s.virtualAddress(current)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", name, err)
				}
			}
			binary.LittleEndian.PutUint64(union[0:8], current)
			binary.LittleEndian.PutUint32(union[8:12], uint32(length))
		} else {
			if address+uint64(len(data)) > math.MaxUint32 {
				return nil, fmt.Errorf("%s: address exceeds 32-bit target", name)
			}
			binary.LittleEndian.PutUint32(union[0:4], uint32(address)+uint32(len(data)))
			binary.LittleEndian.PutUint32(union[4:8], uint32(length))
			actualOffset = 8
		}
		packet, err := s.request(ctx, api, s.currentProcessor(), union, nil)
		if err != nil {
			return nil, err
		}
		if status := kdU32(packet.Payload, 8); status != 0 {
			return nil, fmt.Errorf("%s: target status %#x", name, status)
		}
		actual := int(kdU32(packet.Payload, unionOffset+actualOffset))
		available := max(0, len(packet.Payload)-manipulateSize)
		if actual <= 0 || actual > length || actual > available {
			return nil, fmt.Errorf("%s: invalid actual byte count %d", name, actual)
		}
		data = append(data, packet.Payload[manipulateSize:manipulateSize+actual]...)
	}
	return starlark.Bytes(data), nil
}

func (s *kdSessionValue) writeVirtualBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return s.writeMemoryBuiltin("write_virtual", kdAPIWriteVirtual, args, kwargs)
}

func (s *kdSessionValue) writePhysicalBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return s.writeMemoryBuiltin("write_physical", kdAPIWritePhysical, args, kwargs)
}

func (s *kdSessionValue) writeMemoryBuiltin(name string, api uint32, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var value starlark.Value
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "data", &value, "timeout?", &timeout); err != nil {
		return nil, err
	}
	data, err := starfile.BytesForValue(value, int64(s.memoryLimit))
	if err != nil {
		return nil, err
	}
	if address > math.MaxUint64-uint64(len(data)) {
		return nil, fmt.Errorf("%s: address range overflows", name)
	}
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	for offset := 0; offset < len(data); {
		unionOffset, manipulateSize := s.manipulateLayout()
		length := min(len(data)-offset, s.wire.maximum-manipulateSize)
		union := make([]byte, manipulateSize-unionOffset)
		actualOffset := 12
		if s.targetIs64() {
			current := address + uint64(offset)
			if api == kdAPIWriteVirtual {
				current, err = s.virtualAddress(current)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", name, err)
				}
			}
			binary.LittleEndian.PutUint64(union[0:8], current)
			binary.LittleEndian.PutUint32(union[8:12], uint32(length))
		} else {
			if address+uint64(offset) > math.MaxUint32 {
				return nil, fmt.Errorf("%s: address exceeds 32-bit target", name)
			}
			binary.LittleEndian.PutUint32(union[0:4], uint32(address)+uint32(offset))
			binary.LittleEndian.PutUint32(union[4:8], uint32(length))
			actualOffset = 8
		}
		packet, err := s.request(ctx, api, s.currentProcessor(), union, data[offset:offset+length])
		if err != nil {
			return nil, err
		}
		if status := kdU32(packet.Payload, 8); status != 0 {
			return nil, fmt.Errorf("%s: target status %#x", name, status)
		}
		actual := int(kdU32(packet.Payload, unionOffset+actualOffset))
		if actual <= 0 || actual > length {
			return nil, fmt.Errorf("%s: invalid actual byte count %d", name, actual)
		}
		offset += actual
	}
	return starlark.None, nil
}

func (s *kdSessionValue) currentProcessor() uint16 {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.processor
}

type kdBreakpointValue struct {
	session *kdSessionValue
	handle  uint32
	address uint64
	removed atomic.Bool
}

func (p *kdBreakpointValue) String() string {
	return fmt.Sprintf("<windows.kd_breakpoint address=%#x handle=%#x>", p.address, p.handle)
}
func (p *kdBreakpointValue) Type() string          { return "windows.kd_breakpoint" }
func (p *kdBreakpointValue) Freeze()               {}
func (p *kdBreakpointValue) Truth() starlark.Bool  { return starlark.True }
func (p *kdBreakpointValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", p.Type()) }
func (p *kdBreakpointValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "address":
		return starlark.MakeUint64(p.address), nil
	case "handle":
		return starlark.MakeUint64(uint64(p.handle)), nil
	case "removed":
		return starlark.Bool(p.removed.Load()), nil
	case "remove":
		return starlark.NewBuiltin("remove", p.removeBuiltin), nil
	}
	return nil, nil
}
func (p *kdBreakpointValue) AttrNames() []string {
	return []string{"address", "handle", "remove", "removed"}
}

func (s *kdSessionValue) breakpointBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("breakpoint", args, kwargs, "address", &address, "timeout?", &timeout); err != nil {
		return nil, err
	}
	unionOffset, manipulateSize := s.manipulateLayout()
	union := make([]byte, manipulateSize-unionOffset)
	handleOffset := 8
	if s.targetIs64() {
		wireAddress, err := s.virtualAddress(address)
		if err != nil {
			return nil, fmt.Errorf("breakpoint: %w", err)
		}
		binary.LittleEndian.PutUint64(union, wireAddress)
	} else {
		if address > math.MaxUint32 {
			return nil, fmt.Errorf("breakpoint: address exceeds 32-bit target")
		}
		binary.LittleEndian.PutUint32(union, uint32(address))
		handleOffset = 4
	}
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	packet, err := s.request(ctx, kdAPIWriteBreakpoint, s.currentProcessor(), union, nil)
	if err != nil {
		return nil, err
	}
	if status := kdU32(packet.Payload, 8); status != 0 {
		return nil, fmt.Errorf("breakpoint: target status %#x", status)
	}
	return &kdBreakpointValue{session: s, handle: kdU32(packet.Payload, unionOffset+handleOffset), address: address}, nil
}

// virtualAddress converts a caller-facing address to the active KD manipulate
// packet layout. An i386 target can use KD64 packets while still requiring its
// kernel half to be represented as a sign-extended 32-bit virtual address.
func (s *kdSessionValue) virtualAddress(address uint64) (uint64, error) {
	if s.architecture == "" || s.architecture == "i386" {
		if address <= math.MaxUint32 {
			if address&0x80000000 != 0 && s.targetIs64() {
				return address | 0xffffffff00000000, nil
			}
			return address, nil
		}
		if address>>32 == math.MaxUint32 {
			return address, nil
		}
		return 0, fmt.Errorf("address exceeds i386 virtual space")
	}
	return address, nil
}

func (p *kdBreakpointValue) removeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("remove", args, kwargs, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if p.removed.Load() {
		return starlark.None, nil
	}
	unionOffset, manipulateSize := p.session.manipulateLayout()
	union := make([]byte, manipulateSize-unionOffset)
	binary.LittleEndian.PutUint32(union, p.handle)
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	packet, err := p.session.request(ctx, kdAPIRestoreBreakpoint, p.session.currentProcessor(), union, nil)
	if err != nil {
		return nil, err
	}
	if status := kdU32(packet.Payload, 8); status != 0 {
		return nil, fmt.Errorf("remove breakpoint: target status %#x", status)
	}
	p.removed.Store(true)
	return starlark.None, nil
}

func (s *kdSessionValue) packetBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind int
	var value starlark.Value
	var packetID starlark.Value = starlark.None
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("packet", args, kwargs, "kind", &kind, "payload", &value, "packet_id?", &packetID, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if kind < 1 || kind > math.MaxUint16 || kind == int(kdPacketStateChange32) || kind == int(kdPacketAcknowledge) || kind == int(kdPacketResend) || kind == int(kdPacketReset) || kind == int(kdPacketStateChange64) {
		return nil, fmt.Errorf("packet: unsafe or invalid packet kind")
	}
	payload, err := starfile.BytesForValue(value, int64(s.wire.maximum))
	if err != nil {
		return nil, err
	}
	s.wire.stateMu.Lock()
	currentID := s.wire.remoteID
	s.wire.stateMu.Unlock()
	if packetID != starlark.None {
		var requested uint64
		if err := starlark.AsInt(packetID, &requested); err != nil || requested != uint64(currentID) {
			return nil, fmt.Errorf("packet: packet_id must equal the current protocol ID %#x", currentID)
		}
	}
	ctx, cancel, err := kdOperationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	id, _, err := s.sendData(ctx, uint16(kind), payload)
	if err != nil {
		return nil, err
	}
	return starlark.MakeUint64(uint64(id)), nil
}

func (s *kdSessionValue) fileIOBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handler starlark.Value = starlark.None
	if err := starlark.UnpackArgs("file_io", args, kwargs, "handler?", &handler); err != nil {
		return nil, err
	}
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	if handler == starlark.None {
		s.fileHandler = nil
		return starlark.None, nil
	}
	callable, ok := handler.(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("file_io: handler is %s, want callable or None", handler.Type())
	}
	s.fileHandler = callable
	return starlark.None, nil
}

func (s *kdSessionValue) rejectFileIO(packet kdPacket) error {
	if len(packet.Payload) < kdFileIOSize {
		return fmt.Errorf("KD file I/O packet is too short")
	}
	response := append([]byte(nil), packet.Payload[:kdFileIOSize]...)
	status := kdStatusInvalidHandle
	if kdU32(packet.Payload, 0) == kdAPICreateFile {
		status = kdStatusObjectNameNotFound
	}
	binary.LittleEndian.PutUint32(response[4:8], status)
	return s.queueData(kdPacketFileIO, response)
}

func (s *kdSessionValue) handleFileCallback(thread *starlark.Thread, packet kdPacket, event starlark.Value) error {
	s.handlerMu.RLock()
	handler := s.fileHandler
	s.handlerMu.RUnlock()
	if handler == nil {
		return s.rejectFileIO(packet)
	}
	result, callbackErr := starlark.Call(thread, handler, starlark.Tuple{event}, nil)
	status := uint64(kdStatusInvalidHandle)
	var output []byte
	if callbackErr == nil {
		dict, ok := result.(*starlark.Dict)
		if !ok {
			callbackErr = fmt.Errorf("KD file handler returned %s, want dict", result.Type())
		} else {
			if value, found, _ := dict.Get(starlark.String("status")); found {
				if err := starlark.AsInt(value, &status); err != nil || status > math.MaxUint32 {
					callbackErr = fmt.Errorf("KD file handler returned invalid status")
				}
			}
			if value, found, _ := dict.Get(starlark.String("data")); found {
				output, callbackErr = starfile.BytesForValue(value, int64(s.wire.maximum-kdFileIOSize))
			}
		}
	}
	response := append([]byte(nil), packet.Payload[:kdFileIOSize]...)
	binary.LittleEndian.PutUint32(response[4:8], uint32(status))
	response = append(response, output...)
	ctx, cancel, contextErr := kdOperationContext(30)
	if contextErr != nil {
		return contextErr
	}
	defer cancel()
	_, _, sendErr := s.sendData(ctx, kdPacketFileIO, response)
	if callbackErr != nil {
		return callbackErr
	}
	return sendErr
}

func (s *kdSessionValue) closeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
		return nil, err
	}
	return starlark.None, s.Close()
}
