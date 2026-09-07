// Package cpu defines the portable boundary between instruction execution and
// the environment providing guest memory, loaders, and system API semantics.
package cpu

type Access uint8

const (
	Read Access = 1 << iota
	Write
	Execute
)

// Memory addresses are guest virtual addresses, never host pointers. Reads and
// writes must either complete in full or return an error without changing the
// destination. Implementations may observe accesses for bounded debugging.
type Memory interface {
	// CheckMemory validates an access without reading or writing guest data.
	CheckMemory(address uint64, size int, access Access) error
	ReadMemory(address uint64, destination []byte, access Access) error
	WriteMemory(address uint64, source []byte) error
}

type Architecture struct {
	Name        string
	PointerSize int
}

type Effect uint8

const (
	Continue Effect = iota
	Call
	Return
	Halt
)

// Processor executes one instruction, with no host process or OS policy. The
// caller owns budgets, cancellation, import dispatch, and event delivery.
// Register names and instruction semantics belong to the selected processor.
type Processor interface {
	Architecture() Architecture
	PC() uint64
	SetPC(uint64)
	Register(string) (uint64, error)
	SetRegister(string, uint64) error
	Clone() Processor
	Step(Memory) (Effect, error)
}
