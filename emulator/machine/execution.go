package machine

import (
	"fmt"
	"math"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/emulator/windowsabi"
	"go.starlark.net/starlark"
)

// Execution is an independently resumable processor context sharing a
// machine's portable address space, imports, and semantic API providers.
type Execution struct {
	machine        *Machine
	processor      cpu.Processor
	stackBase      uint64
	stackSize      uint64
	transferSerial uint64
	limit          uint64
	done           bool
	closed         bool
	frozen         bool
	result         starlark.Value
}

func (m *Machine) spawn(address uint64, arguments []uint64, registers map[string]uint64) (*Execution, error) {
	if m.frozen {
		return nil, fmt.Errorf("spawn: machine is frozen")
	}
	if m.processor.Architecture().Name != "amd64" {
		return nil, fmt.Errorf("spawn: unsupported architecture %s", m.processor.Architecture().Name)
	}
	stackSize := m.stackHigh - m.stackLow
	if stackSize == 0 || stackSize > m.memoryLimit {
		return nil, fmt.Errorf("spawn: invalid stack size")
	}
	if m.nextAllocation > math.MaxUint64-0xfff {
		return nil, fmt.Errorf("spawn: stack address overflows")
	}
	stackBase := (m.nextAllocation + 0xfff) &^ 0xfff
	if stackBase > math.MaxUint64-stackSize {
		return nil, fmt.Errorf("spawn: stack address overflows")
	}
	if err := m.memory.Map(stackBase, make([]byte, int(stackSize)), cpu.Read|cpu.Write); err != nil {
		return nil, fmt.Errorf("spawn: map stack: %w", err)
	}
	m.nextAllocation = stackBase + stackSize
	if m.allocationNames == nil {
		m.allocationNames = make(map[uint64]string)
	}
	m.allocationNames[stackBase] = "execution stack"

	processor := cpu.Processor(&amd64.CPU{})
	for _, segment := range []string{"gs_base", "fs_base"} {
		value, err := m.processor.Register(segment)
		if err == nil && value != 0 {
			if err := processor.SetRegister(segment, value); err != nil {
				_ = m.memory.Unmap(stackBase)
				delete(m.allocationNames, stackBase)
				return nil, fmt.Errorf("spawn: copy %s: %w", segment, err)
			}
		}
	}
	for register, value := range registers {
		if err := processor.SetRegister(register, value); err != nil {
			_ = m.memory.Unmap(stackBase)
			delete(m.allocationNames, stackBase)
			return nil, fmt.Errorf("spawn: set %s: %w", register, err)
		}
	}
	if _, supplied := registers["rbp"]; !supplied {
		if err := processor.SetRegister("rbp", stackBase+stackSize); err != nil {
			_ = m.memory.Unmap(stackBase)
			delete(m.allocationNames, stackBase)
			return nil, fmt.Errorf("spawn: set rbp: %w", err)
		}
	}
	if err := windowsabi.PrepareAMD64IntegerCall(processor, m.memory, address, stackBase+stackSize, 0, arguments); err != nil {
		_ = m.memory.Unmap(stackBase)
		delete(m.allocationNames, stackBase)
		return nil, fmt.Errorf("spawn: prepare call: %w", err)
	}
	return &Execution{
		machine: m, processor: processor, stackBase: stackBase, stackSize: stackSize,
		transferSerial: m.transferSerial, limit: m.limit,
	}, nil
}

func (e *Execution) releaseStack() error {
	if e.stackSize == 0 {
		return nil
	}
	err := e.machine.memory.Unmap(e.stackBase)
	delete(e.machine.allocationNames, e.stackBase)
	e.stackBase, e.stackSize = 0, 0
	return err
}

func (e *Execution) runBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	limit := e.limit
	if err := starlark.UnpackArgs("execution.run", args, kwargs, "instruction_limit?", &limit); err != nil {
		return nil, err
	}
	if limit == 0 || limit > e.limit {
		return nil, fmt.Errorf("execution.run: instruction limit must be within the machine budget")
	}
	if e.frozen || e.machine.frozen {
		return nil, fmt.Errorf("execution.run: execution is frozen")
	}
	if e.closed {
		return nil, fmt.Errorf("execution.run: execution is closed")
	}
	if e.done {
		return e.result, nil
	}

	parentProcessor, parentSerial, parentLimit := e.machine.processor, e.machine.transferSerial, e.machine.limit
	e.machine.processor, e.machine.transferSerial, e.machine.limit = e.processor, e.transferSerial, limit
	result, err := e.machine.run(thread)
	e.processor, e.transferSerial = e.machine.processor, e.machine.transferSerial
	e.machine.processor, e.machine.transferSerial, e.machine.limit = parentProcessor, parentSerial, parentLimit
	if err != nil {
		return nil, err
	}
	e.result = result
	if attributed, ok := result.(starlark.HasAttrs); ok {
		reason, attrErr := attributed.Attr("reason")
		if attrErr == nil && reason == starlark.String("return") {
			e.done = true
			if err := e.releaseStack(); err != nil {
				return nil, fmt.Errorf("execution.run: release stack: %w", err)
			}
		}
	}
	return result, nil
}

func (e *Execution) closeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("execution.close", args, kwargs); err != nil {
		return nil, err
	}
	if e.frozen || e.machine.frozen {
		return nil, fmt.Errorf("execution.close: execution is frozen")
	}
	if !e.closed {
		if err := e.releaseStack(); err != nil {
			return nil, fmt.Errorf("execution.close: release stack: %w", err)
		}
		e.closed = true
	}
	return starlark.None, nil
}

func (e *Execution) String() string {
	return fmt.Sprintf("<emulator.execution architecture=amd64 pc=%#x done=%t>", e.processor.PC(), e.done)
}
func (*Execution) Type() string            { return "emulator.execution" }
func (e *Execution) Freeze()               { e.frozen = true }
func (*Execution) Truth() starlark.Bool    { return starlark.True }
func (e *Execution) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: emulator.execution") }
func (*Execution) AttrNames() []string {
	return []string{"close", "closed", "done", "instruction_limit", "run"}
}
func (e *Execution) Attr(name string) (starlark.Value, error) {
	switch name {
	case "close":
		return starlark.NewBuiltin("execution.close", e.closeBuiltin), nil
	case "closed":
		return starlark.Bool(e.closed), nil
	case "done":
		return starlark.Bool(e.done), nil
	case "instruction_limit":
		return starlark.MakeUint64(e.limit), nil
	case "run":
		return starlark.NewBuiltin("execution.run", e.runBuiltin), nil
	default:
		return nil, nil
	}
}
