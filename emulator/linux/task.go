package linux

import (
	"fmt"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
)

// Task supplies the Linux/amd64 user ABI to caller-constructed registers and
// virtual memory. The caller supplies the memory and initializes the task's
// CPU registers before execution. Calls must be serialized.
type Task struct{ p *process }

func NewTask(memory *cpu.AddressSpace, programBreak uint64, cfg Config) (*Task, error) {
	if memory == nil || programBreak < pageSize || programBreak >= userLimit || programBreak&(pageSize-1) != 0 {
		return nil, fmt.Errorf("linux: invalid constructed memory or program break")
	}
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	p, err := newProcess(cfg, memory)
	if err != nil {
		return nil, err
	}
	p.brk, p.initialBrk = programBreak, programBreak
	return &Task{p}, nil
}

func (t *Task) CPU() *amd64.CPU { return &t.p.cpu }

// HandleSyscall executes an actual SYSCALL opcode at the current RIP. Other
// instructions are left to the caller's normal execution loop.
func (t *Task) HandleSyscall() (handled, exited bool, status int, err error) {
	return t.p.handleSyscall()
}

func (t *Task) Close() { t.p.closeFiles() }

func (p *process) handleSyscall() (handled, exited bool, status int, err error) {
	pc := p.cpu.PC()
	var opcode [2]byte
	if err := p.memory.ReadMemory(pc, opcode[:1], cpu.Execute); err != nil {
		return false, false, 0, err
	}
	if opcode[0] != 0x0f {
		return false, false, 0, nil
	}
	if err := p.memory.ReadMemory(pc+1, opcode[1:], cpu.Execute); err != nil {
		return false, false, 0, err
	}
	if opcode[1] != 0x05 {
		return false, false, 0, nil
	}
	p.cpu.SetRegister("rcx", pc+2)
	flags, _ := p.cpu.Register("rflags")
	p.cpu.SetRegister("r11", flags)
	p.cpu.SetPC(pc + 2)
	status, exited, err = p.syscall()
	return true, exited, status, err
}
