package uefi

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/tinyrange/trex/emulator/cpu"
)

// ErrDecline asks execution to interpret this invocation. A callback returning
// ErrDecline must leave CPU and guest memory unchanged.
var ErrDecline = errors.New("uefi: native rewrite declined")

type Rewrite struct {
	Address uint64
	Name    string
	// Pattern is checked against executable guest memory on every invocation.
	Pattern []byte
	// Apply implements the routine ABI and returns the next guest PC. Keep
	// mutable callback state outside closures so checkpoints can restore it.
	Apply func(*Machine) (uint64, error)
}

// AddRewrite installs a verified, caller-supplied native implementation. It is
// disabled whenever tracing, watches or an interior PC stop need guest execution.
func (m *Machine) AddRewrite(r Rewrite) error {
	if r.Address&3 != 0 || len(r.Pattern) == 0 || len(r.Pattern) > 1<<20 || len(r.Pattern)%4 != 0 || r.Address > ^uint64(0)-uint64(len(r.Pattern)) || r.Name == "" || r.Apply == nil {
		return fmt.Errorf("uefi: invalid rewrite")
	}
	code := make([]byte, len(r.Pattern))
	if err := m.processor.VirtualMemory(m.memory).ReadMemory(r.Address, code, cpu.Execute); err != nil {
		return err
	}
	if !bytes.Equal(code, r.Pattern) {
		return fmt.Errorf("uefi: rewrite pattern mismatch at %#x", r.Address)
	}
	for address, existing := range m.rewrites {
		if r.Address < address+uint64(len(existing.Pattern)) && address < r.Address+uint64(len(r.Pattern)) {
			return fmt.Errorf("uefi: overlapping rewrite")
		}
	}
	if m.rewrites == nil {
		m.rewrites = map[uint64]Rewrite{}
	}
	r.Pattern = slices.Clone(r.Pattern)
	m.rewrites[r.Address] = r
	m.rewriteFilter[(r.Address>>2)&4095] = true
	return nil
}

func (m *Machine) AddDigestRewrite(address uint64, size int, digest []byte, name string, apply func(*Machine) (uint64, error)) error {
	if size <= 0 || size > 1<<20 || len(digest) != sha256.Size {
		return fmt.Errorf("uefi: invalid rewrite digest or size")
	}
	code := make([]byte, size)
	if err := m.processor.VirtualMemory(m.memory).ReadMemory(address, code, cpu.Execute); err != nil {
		return err
	}
	actual := sha256.Sum256(code)
	if !bytes.Equal(actual[:], digest) {
		return fmt.Errorf("uefi: rewrite digest mismatch at %#x", address)
	}
	return m.AddRewrite(Rewrite{address, name, code, apply})
}

func (m *Machine) accelerate(pc uint64, opts RunOptions) (bool, error) {
	if opts.DisableAcceleration || opts.TraceLimit != 0 || len(opts.Watches) != 0 {
		return false, nil
	}
	r, ok := m.rewrites[pc]
	if !ok {
		return false, nil
	}
	for _, stop := range opts.StopPCs {
		if stop >= pc && stop < pc+uint64(len(r.Pattern)) {
			return false, nil
		}
	}
	code := m.rewriteCode[:min(len(r.Pattern), len(m.rewriteCode))]
	if len(r.Pattern) > len(code) {
		code = make([]byte, len(r.Pattern))
	}
	if err := m.processor.VirtualMemory(m.memory).ReadMemory(pc, code, cpu.Execute); err != nil {
		return false, err
	}
	if !bytes.Equal(code, r.Pattern) {
		return false, nil
	}
	var args [8]uint64
	if m.observes("accelerator") {
		args = m.args()
	}
	next, err := r.Apply(m)
	if errors.Is(err, ErrDecline) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if next&3 != 0 {
		return false, fmt.Errorf("uefi: rewrite returned unaligned PC %#x", next)
	}
	m.processor.SetPC(next)
	m.processor.AdvanceInstructions(1)
	m.emit(Event{Kind: "accelerator", Name: r.Name, PC: pc, Args: args})
	return true, nil
}
