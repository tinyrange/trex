// Package linux executes static Linux/amd64 ELF programs in process using the
// existing amd64 interpreter. It does not boot a kernel or execute host code.
package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/storage"
)

// Config supplies process inputs and hard execution budgets. Environment and
// argv are explicit; nothing is inherited from the host. ELF interpreters and
// unsupported syscalls produce emulator errors, not synthetic errno results.
type Config struct {
	Files FileSystem
	// Umask defaults to 0022; a non-nil pointer permits an explicit zero mask.
	Umask           *fs.FileMode
	Dir             string
	Args, Env       []string
	Stdin           io.Reader
	Stdout, Stderr  io.Writer
	MaxInstructions uint64
	MaxMemory       uint64
	// Random supplies the 16 AT_RANDOM bytes. Zero is useful for deterministic
	// tests but is not entropy and must not be used for security-sensitive guests.
	Random [16]byte
}
type Result struct {
	Status       int
	Instructions uint64
	PC           uint64
}
type SyscallError struct{ Number, PC uint64 }

func (e *SyscallError) Error() string {
	return fmt.Sprintf("linux/amd64: unsupported syscall %d at %#x", e.Number, e.PC)
}

type process struct {
	files                    map[uint64]*descriptor
	closeOnExec              map[uint64]bool
	umask                    fs.FileMode
	cfg                      Config
	cpu                      amd64.CPU
	memory                   *cpu.AddressSpace
	used                     uint64
	nextMap, brk, initialBrk uint64
	closed                   [3]bool
}

const pageSize = uint64(4096)
const userLimit = uint64(1) << 47

func align(value uint64) uint64 { return (value + pageSize - 1) &^ (pageSize - 1) }
func (p *process) mapMemory(address, size uint64, data []byte, access cpu.Access) error {
	if size == 0 || address >= userLimit || size > userLimit-address || size > p.cfg.MaxMemory-p.used {
		return fmt.Errorf("linux: invalid mapping or memory budget exceeded")
	}
	if len(data) != 0 && uint64(len(data)) != size {
		return fmt.Errorf("linux: inconsistent mapping data")
	}
	if len(data) == 0 {
		data = make([]byte, int(size))
	}
	if err := p.memory.Map(address, data, access); err != nil {
		return err
	}
	p.used += size
	return nil
}

func Run(ctx context.Context, image storage.Reader, cfg Config) (Result, error) {
	if cfg.MaxInstructions == 0 {
		cfg.MaxInstructions = 10000000
	}
	if cfg.MaxMemory == 0 {
		cfg.MaxMemory = 128 << 20
	}
	if cfg.MaxMemory > 1<<30 {
		return Result{}, fmt.Errorf("linux: memory budget exceeds 1 GiB")
	}
	if cfg.Stdin == nil {
		cfg.Stdin = strings.NewReader("")
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Dir == "" {
		cfg.Dir = "/"
	}
	if !path.IsAbs(cfg.Dir) {
		return Result{}, fmt.Errorf("linux: working directory must be absolute")
	}
	p := &process{files: make(map[uint64]*descriptor), cfg: cfg, memory: cpu.NewAddressSpace(cfg.MaxMemory), nextMap: 0x100000000}
	p.umask = 0022
	if cfg.Umask != nil {
		if *cfg.Umask&^0777 != 0 {
			return Result{}, fmt.Errorf("linux: invalid creation mask")
		}
		p.umask = *cfg.Umask
	}
	defer p.closeFiles()
	if err := p.load(image); err != nil {
		return Result{}, err
	}
	result := Result{}
	for result.Instructions < cfg.MaxInstructions {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		result.PC = p.cpu.PC()
		result.Instructions++
		var opcode [2]byte
		if err := p.memory.ReadMemory(result.PC, opcode[:1], cpu.Execute); err != nil {
			return result, err
		}
		syscall := false
		if opcode[0] == 0x0f {
			if err := p.memory.ReadMemory(result.PC+1, opcode[1:], cpu.Execute); err != nil {
				return result, err
			}
			syscall = opcode[1] == 0x05
		}
		if syscall {
			// SYSCALL clobbers RCX/R11; the Linux return path resumes at the next PC.
			p.cpu.SetRegister("rcx", result.PC+2)
			flags, _ := p.cpu.Register("rflags")
			p.cpu.SetRegister("r11", flags)
			p.cpu.SetPC(result.PC + 2)
			status, exited, err := p.syscall()
			if err != nil {
				return result, err
			}
			if exited {
				result.Status = status
				return result, nil
			}
			continue
		}
		effect, err := p.cpu.Step(p.memory)
		if err != nil {
			return result, fmt.Errorf("linux: instruction at %#x: %w", result.PC, err)
		}
		if effect == cpu.Halt {
			return result, fmt.Errorf("linux: guest halted without exit at %#x", result.PC)
		}
	}
	return result, fmt.Errorf("linux: instruction budget exceeded at %#x", p.cpu.PC())
}
func (p *process) reg(name string) uint64 { v, _ := p.cpu.Register(name); return v }
func (p *process) ret(value uint64)       { p.cpu.SetRegister("rax", value) }
func (p *process) errno(n int)            { p.ret(uint64(-int64(n))) }
func (p *process) syscall() (int, bool, error) {
	number := p.reg("rax")
	a, b, c, d, e, f := p.reg("rdi"), p.reg("rsi"), p.reg("rdx"), p.reg("r10"), p.reg("r8"), p.reg("r9")
	switch number {
	case 95: // umask is process-local and never changes compiler-host state.
		old := p.umask
		p.umask = fs.FileMode(a & 0777)
		p.ret(uint64(old))
	case 60, 231:
		return int(a & 255), true, nil
	case 0, 1:
		if err := p.fileIO(number, a, b, c); err != nil {
			return 0, false, err
		}
	case 2:
		if err := p.openFile(a, b, c); err != nil {
			return 0, false, err
		}
	case 257:
		// Relative directory descriptors need directory-open support. AT_FDCWD only.
		if int32(a) != -100 {
			return 0, false, &SyscallError{number, p.cpu.PC() - 2}
		}
		if err := p.openFile(b, c, d); err != nil {
			return 0, false, err
		}
	case 97:
		if a != 7 {
			return 0, false, &SyscallError{number, p.cpu.PC() - 2}
		}
		var limits [16]byte
		binary.LittleEndian.PutUint64(limits[:8], 1024)
		binary.LittleEndian.PutUint64(limits[8:], 1024)
		if err := p.memory.WriteMemory(b, limits[:]); err != nil {
			p.errno(14)
		} else {
			p.ret(0)
		}
	case 72:
		if err := p.fileControl(a, b, c); err != nil {
			return 0, false, err
		}
	case 33:
		if err := p.duplicateDescriptor(a, b); err != nil {
			return 0, false, err
		}
	case 3:
		if err := p.closeDescriptor(a); err != nil {
			if eno := fileErrno(err); eno != 0 {
				p.errno(eno)
			} else {
				return 0, false, err
			}
		} else {
			p.ret(0)
		}
	case 9: // anonymous private mmap; other kinds need filesystem semantics.
		if b == 0 || b > p.cfg.MaxMemory || c&^uint64(7) != 0 {
			p.errno(22)
			break
		}
		if d != 0x22 || e != ^uint64(0) || f != 0 {
			return 0, false, &SyscallError{number, p.cpu.PC() - 2}
		}
		if a != 0 {
			return 0, false, fmt.Errorf("linux: mmap address hints not implemented")
		}
		size := align(b)
		address := p.nextMap
		access := cpu.Access(c)
		if access == 0 {
			return 0, false, fmt.Errorf("linux: PROT_NONE mmap not implemented")
		}
		if err := p.mapMemory(address, size, nil, access); err != nil {
			p.errno(12)
			break
		}
		p.nextMap += size + pageSize
		p.ret(address)
	case 10:
		if a&(pageSize-1) != 0 || b == 0 || b > p.cfg.MaxMemory || c&^uint64(7) != 0 {
			p.errno(22)
			break
		}
		if _, err := p.memory.Protect(a, int(align(b)), cpu.Access(c)); err != nil {
			p.errno(12)
		} else {
			p.ret(0)
		}
	case 12:
		if a == 0 {
			p.ret(p.brk)
			break
		}
		if a < p.initialBrk {
			p.ret(p.brk)
			break
		}
		if a < p.brk {
			return 0, false, fmt.Errorf("linux: brk shrink not implemented")
		}
		old, new := align(p.brk), align(a)
		if new > old {
			if err := p.mapMemory(old, new-old, nil, cpu.Read|cpu.Write); err != nil {
				p.ret(p.brk)
				break
			}
		}
		p.brk = a
		p.ret(a)
	case 39:
		p.ret(1)
	case 158:
		switch a {
		case 0x1002:
			if b >= userLimit {
				p.errno(1)
			} else {
				p.cpu.SetRegister("fs_base", b)
				p.ret(0)
			}
		case 0x1003:
			var data [8]byte
			binary.LittleEndian.PutUint64(data[:], p.reg("fs_base"))
			if err := p.memory.WriteMemory(b, data[:]); err != nil {
				p.errno(14)
			} else {
				p.ret(0)
			}
		default:
			return 0, false, &SyscallError{number, p.cpu.PC() - 2}
		}
	default:
		return 0, false, &SyscallError{number, p.cpu.PC() - 2}
	}
	return 0, false, nil
}
