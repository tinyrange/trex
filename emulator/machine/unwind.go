package machine

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/tinyrange/trex/emulator/cpu"
	"go.starlark.net/starlark"
)

// localUnwindHandlers validates a same-frame MSVC C-scope unwind before any
// funclet is run. Cross-frame, frame-pointer and chained unwinds require the
// general virtual-unwind engine and are explicitly rejected, never skipped.
func (m *Machine) localUnwindHandlers(frame, target uint64) ([]uint64, error) {
	sp, _ := m.processor.Register("rsp")
	if sp > math.MaxUint64-8 || frame != sp+8 {
		return nil, fmt.Errorf("local_unwind: cross-frame unwind is not supported")
	}
	var raw [8]byte
	if err := m.memory.ReadMemory(sp, raw[:], cpu.Read); err != nil {
		return nil, err
	}
	returnPC := binary.LittleEndian.Uint64(raw[:])
	if returnPC == 0 {
		return nil, fmt.Errorf("local_unwind: no native caller")
	}
	pc := returnPC - 1
	for _, loaded := range m.modules {
		image := loaded.image
		if pc < image.Base || pc-image.Base >= uint64(len(image.Data)) {
			continue
		}
		info, err := image.AMD64UnwindInfo(uint32(pc - image.Base))
		if err != nil {
			return nil, err
		}
		if info == nil || info.FrameRegister != 0 || info.Chained != nil {
			return nil, fmt.Errorf("local_unwind: caller requires unsupported frame unwinding")
		}
		begin, end := image.Base+uint64(info.Function.Begin), image.Base+uint64(info.Function.End)
		if target < begin+uint64(info.PrologSize) || target >= end || pc < begin+uint64(info.PrologSize) {
			return nil, fmt.Errorf("local_unwind: target is not in the caller function body")
		}
		if info.Flags&2 == 0 {
			return nil, nil
		}
		// A C-specific scope table is meaningful only for its corresponding
		// language handler. Resolve the media-owned import jump, not a name
		// guessed from the contents of an arbitrary handler's private data.
		var jump [6]byte
		if err := m.memory.ReadMemory(image.Base+uint64(info.Handler), jump[:], cpu.Execute); err != nil {
			return nil, err
		}
		if jump[0] != 0xff || jump[1] != 0x25 {
			return nil, fmt.Errorf("local_unwind: unsupported language-handler entry")
		}
		iat := image.Base + uint64(info.Handler) + 6 + uint64(int64(int32(binary.LittleEndian.Uint32(jump[2:]))))
		known := false
		for _, entry := range m.imports {
			if entry.iat == iat && strings.EqualFold(entry.name, "__C_specific_handler") {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("local_unwind: unsupported language handler")
		}
		scopes, err := image.CScopes(info.HandlerData)
		if err != nil {
			return nil, err
		}
		var handlers []uint64
		for _, scope := range scopes {
			start, finish := image.Base+uint64(scope.Begin), image.Base+uint64(scope.End)
			if scope.Jump == 0 && pc >= start && pc < finish && !(target >= start && target < finish) {
				handlers = append(handlers, image.Base+uint64(scope.Handler))
			}
		}
		if len(handlers) > 64 {
			return nil, fmt.Errorf("local_unwind: termination-handler budget exceeded")
		}
		return handlers, nil
	}
	return nil, fmt.Errorf("local_unwind: caller is not in a loaded PE image")
}

func (m *Machine) validateTransfer(address, stack uint64) error {
	if stack < m.stackLow || stack > m.stackHigh || stack%8 != 0 {
		return fmt.Errorf("transfer: invalid stack pointer")
	}
	if address != 0 {
		var code [1]byte
		if err := m.memory.ReadMemory(address, code[:], cpu.Execute); err != nil {
			return err
		}
	}
	return nil
}

func (m *Machine) transfer(address, stack uint64) error {
	if err := m.validateTransfer(address, stack); err != nil {
		return err
	}
	if err := m.processor.SetRegister("rsp", stack); err != nil {
		return err
	}
	m.processor.SetPC(address)
	m.transferSerial++
	return nil
}

func (m *Machine) controlMethod(thread *starlark.Thread, name string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if name == "transfer" {
		var address uint64
		stack, _ := m.processor.Register("rsp")
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "stack_pointer?", &stack); err != nil {
			return nil, err
		}
		return starlark.None, m.transfer(address, stack)
	}
	var frame, target uint64
	if err := starlark.UnpackArgs(name, args, kwargs, "frame", &frame, "target", &target); err != nil {
		return nil, err
	}
	handlers, err := m.localUnwindHandlers(frame, target)
	if err != nil {
		return nil, err
	}
	if err := m.validateTransfer(target, frame); err != nil {
		return nil, err
	}
	for _, handler := range handlers {
		result, err := m.method(thread, starlark.NewBuiltin("machine.invoke", m.method), starlark.Tuple{starlark.MakeUint64(handler)}, []starlark.Tuple{{starlark.String("args"), starlark.NewList([]starlark.Value{starlark.MakeInt(1), starlark.MakeUint64(frame)})}})
		if err != nil {
			return nil, err
		}
		reason, err := result.(starlark.HasAttrs).Attr("reason")
		if err != nil {
			return nil, err
		}
		if reason != starlark.String("return") {
			detail, _ := result.(starlark.HasAttrs).Attr("detail")
			pc, _ := result.(starlark.HasAttrs).Attr("pc")
			return nil, fmt.Errorf("local_unwind: termination handler %#x stopped with %s at %s: %s", handler, reason, pc, detail)
		}
	}
	if err := m.transfer(target, frame); err != nil {
		return nil, err
	}
	if err := m.processor.SetRegister("rax", 0); err != nil {
		return nil, err
	}
	return starlark.None, nil
}
