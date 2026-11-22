//go:build linux && amd64

package power

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

const jitAvailable = true

// jitArena is an executable mapping filled sequentially with blocks.
type jitArena struct {
	mem  []byte
	used int
}

func newJITArena(size int) (*jitArena, error) {
	b, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, err
	}
	return &jitArena{mem: b}, nil
}

// add copies code into the arena, 16-byte aligned, and returns its entry.
func (a *jitArena) add(code []byte) (uintptr, bool) {
	start := (a.used + 15) &^ 15
	if start+len(code) > len(a.mem) {
		return 0, false
	}
	copy(a.mem[start:], code)
	a.used = start + len(code)
	return uintptr(unsafe.Pointer(&a.mem[start])), true
}

func (a *jitArena) reset() { a.used = 0 }

// patch points the rel32 at site (inside the arena) at target.
func (a *jitArena) patch(site, target uintptr) {
	base := uintptr(unsafe.Pointer(&a.mem[0]))
	binary.LittleEndian.PutUint32(a.mem[site-base:], uint32(int32(target-(site+4))))
}

func (a *jitArena) release() {
	if a.mem != nil {
		syscall.Munmap(a.mem)
		a.mem = nil
	}
}

// jitCall runs native code with the block register assignment.
//
//go:noescape
func jitCall(code uintptr, cpu, mem, ctx unsafe.Pointer)

func jitEnter(code uintptr, c *CPU, m *Machine, ctx *jitCtx) {
	jitCall(code, unsafe.Pointer(c), unsafe.Pointer(&m.Mem[0]), unsafe.Pointer(ctx))
}

func jitPointer[T any](s []T) uintptr {
	if len(s) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&s[0]))
}
