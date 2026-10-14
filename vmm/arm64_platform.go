package vmm

import (
	"context"

	"github.com/tinyrange/trex/channel"
)

// ARM64Runtime supplies guest resources to a platform instance. Calls belong
// to its execution thread; implementations revoke access when that VM closes.
// Addresses are guest addresses. No host path, socket or process is exposed.
type ARM64Runtime interface {
	Context() context.Context
	Machine() Machine
	Memory(address, size uint64, write bool) ([]byte, error)
	Protect(address, size uint64, read, write, execute bool) error
	Counter() (ticks, frequency uint64, err error)
	EpochMicroseconds() uint64
	SetSPI(id uint32, level bool) error
	Register(id uint32) (uint64, error)
	SetRegister(id uint32, value uint64) error
	GuestChannel(name string) (channel.ByteChannel, error)
	Emit(kind string, payload any)
}

// ARM64Device is a guest MMIO protocol, independently of its accelerator.
type ARM64Device interface {
	Contains(address uint64, size int) bool
	Read(address uint64, size int) (uint64, error)
	Write(address uint64, size int, value uint64) error
}

// Optional device lifecycle methods are Poll() error, Flush(), Close() error.
// Poll runs before guest entry; Flush publishes final evidence before Close.
type ARM64Platform struct {
	GICDistributor, GICRedistributor uint64
	// New must create fresh mutable device state for each VM.
	New func(ARM64Runtime) (ARM64Device, error)
}

// ARM64HypercallHandler handles a platform's HVC services before architectural
// PSCI dispatch. An unhandled service remains an unsupported guest exit.
type ARM64HypercallHandler interface {
	HVC(immediate uint16, function uint64) (bool, error)
}
