// Package device defines portable, owner-serialized experimental PCI attachments.
// It has no dependency on a CPU engine, hypervisor, Starlark, or host resources.
package device

import (
	"errors"
	"fmt"
	"io"
	"time"
)

type Space uint8

const (
	IO Space = iota
	Memory
)

// Region is a currently decoded BAR. Models omit disabled decoders and probes
// outside the parent bus address space. Bases may change after configuration writes; never cache them.
type Region struct {
	BAR        uint8
	Space      Space
	Base, Size uint64
}

// Access transfers one little-endian bus element (not an entire REP string).
// Position is an optional, lazy diagnostic; models must work when it is nil.
type Access struct {
	BAR      uint8
	Offset   uint64
	Data     []byte
	Write    bool
	Position func() (string, error)
}

// PCI owns configuration and BAR semantics. Access never retains Data. Every
// method runs on the machine's device owner, with all guest CPUs stopped.
type PCI interface {
	ReadConfig(offset uint16) byte
	WriteConfig(offset uint16, value byte)
	Regions() []Region
	Access(Access) error
}

// Optional capabilities keep simple register-only models small.
type Poller interface {
	Poll(time.Time) error
	Deadline() time.Time
}
type Interrupt interface {
	Interrupt() (line uint32, asserted bool)
}
type Inspector interface{ State() any }

// BARReader observes an aperture without executing guest register reads.
type BARReader interface {
	ReadBAR(bar uint8, offset uint64, data []byte) error
}

// MemoryReader reads a named model space without guest register writes.
// Unknown spaces and out-of-range reads must fail.
type MemoryReader interface {
	ReadMemory(space string, address uint64, data []byte) error
}

type Profile struct {
	Architecture string
	CPUs         int
	UEFI         bool
}

// Spec is immutable construction policy, not a live device. New must return a
// fresh independent model for every VM. Check must not allocate a live model.
type Spec struct {
	Name  string
	BDF   uint16
	New   func() (PCI, error)
	Check func(Profile) error
}

func Validate(specs []Spec, profile Profile, reserved map[uint16]bool) error {
	names, slots := map[string]bool{}, map[uint16]bool{}
	for _, s := range specs {
		if s.Name == "" || s.New == nil {
			return fmt.Errorf("device: name and factory required")
		}
		if names[s.Name] {
			return fmt.Errorf("device: duplicate name %q", s.Name)
		}
		if s.BDF > 255 || reserved[s.BDF] || slots[s.BDF] {
			return fmt.Errorf("device %s: unavailable bus-0 BDF %#x", s.Name, s.BDF)
		}
		if s.Check != nil && profile.Architecture != "" {
			if err := s.Check(profile); err != nil {
				return fmt.Errorf("device %s: %w", s.Name, err)
			}
		}
		names[s.Name], slots[s.BDF] = true, true
	}
	return nil
}

type entry struct {
	spec  Spec
	model PCI
}

// Bus is zero-value usable and owned by one machine. Reserved is evaluated at
// decode time so built-in BAR relocation is respected. No hotplug or DMA API is
// implied. SetIRQ must serialize with the platform's other interrupt sources.
type Bus struct {
	entries  []entry
	irq      map[uint32]bool
	Reserved func() []Region
	SetIRQ   func(uint32, bool) error
}

// Attach takes ownership only on success. Failed construction rolls back all
// models created by this call; an already attached bus is left unchanged.
func (b *Bus) Attach(specs []Spec, profile Profile, reserved map[uint16]bool) error {
	all := make([]Spec, 0, len(b.entries)+len(specs))
	for _, e := range b.entries {
		all = append(all, e.spec)
	}
	all = append(all, specs...)
	if err := Validate(all, profile, reserved); err != nil {
		return err
	}
	pending := &Bus{}
	for _, s := range specs {
		model, err := s.New()
		if err != nil || model == nil {
			if model != nil {
				pending.entries = append(pending.entries, entry{s, model})
			}
			if err == nil {
				err = fmt.Errorf("factory returned nil")
			}
			return errors.Join(fmt.Errorf("device %s: %w", s.Name, err), pending.Close())
		}
		pending.entries = append(pending.entries, entry{s, model})
	}
	b.entries = append(b.entries, pending.entries...)
	return nil
}
func (b *Bus) Len() int { return len(b.entries) }
func (b *Bus) Config(bdf uint16, offset uint16, write bool, value byte) (byte, bool) {
	for _, e := range b.entries {
		if e.spec.BDF == bdf && offset < 256 {
			if write {
				e.model.WriteConfig(offset, value)
			}
			return e.model.ReadConfig(offset), true
		}
	}
	return 0xff, false
}
func valid(r Region) bool {
	limit := ^uint64(0)
	if r.Space == IO {
		limit = 1 << 16
	} else if r.Space != Memory {
		return false
	}
	return r.Size != 0 && r.Base < limit && r.Size <= limit-r.Base
}
func overlaps(a, c Region) bool {
	return a.Space == c.Space && a.Base < c.Base+c.Size && c.Base < a.Base+a.Size
}

// Decode rejects ambiguous ownership and straddling accesses before invoking a
// model. Overlapping whole BARs are rejected even outside their shared bytes.
func (b *Bus) Decode(space Space, address, size uint64) (PCI, Region, error) {
	query := Region{Space: space, Base: address, Size: size}
	if !valid(query) {
		return nil, Region{}, fmt.Errorf("device: invalid bus range %#x+%d", address, size)
	}
	var model PCI
	var found Region
	owner, barIndex := -1, -1
	for ei, e := range b.entries {
		for ri, r := range e.model.Regions() {
			if !valid(r) {
				return nil, Region{}, fmt.Errorf("device %s: invalid BAR %d", e.spec.Name, r.BAR)
			}
			if !overlaps(r, query) {
				continue
			}
			if model != nil || address < r.Base || size > r.Size-(address-r.Base) {
				return nil, Region{}, fmt.Errorf("device: ambiguous or straddling bus range %#x+%d", address, size)
			}
			model, found = e.model, r
			owner, barIndex = ei, ri
		}
	}
	if model == nil {
		return nil, Region{}, nil
	}
	for ei, e := range b.entries {
		for ri, r := range e.model.Regions() {
			if !valid(r) {
				return nil, Region{}, fmt.Errorf("device %s: invalid BAR", e.spec.Name)
			}
			if ei == owner && ri == barIndex {
				continue
			}
			if overlaps(found, r) {
				return nil, Region{}, fmt.Errorf("device: overlapping BAR at %#x", found.Base)
			}
		}
	}
	if b.Reserved != nil {
		for _, r := range b.Reserved() {
			if valid(r) && overlaps(found, r) {
				return nil, Region{}, fmt.Errorf("device: BAR at %#x conflicts with platform resources", found.Base)
			}
		}
	}
	return model, found, nil
}

// Transfer validates the whole REP shape before any side effects. Each element
// accesses the same port/address, matching x86 string-I/O semantics.
func (b *Bus) Transfer(space Space, address uint64, width, count int, write bool, data []byte, position func() (string, error)) (bool, error) {
	if (width != 1 && width != 2 && width != 4 && (space != Memory || width != 8)) || count < 1 || len(data)/width != count || len(data)%width != 0 || space == Memory && count != 1 {
		return false, fmt.Errorf("device: invalid transfer shape")
	}
	model, r, err := b.Decode(space, address, uint64(width))
	if err != nil || model == nil {
		return model != nil, err
	}
	for i := 0; i < count; i++ {
		if err := model.Access(Access{BAR: r.BAR, Offset: address - r.Base, Data: data[i*width : (i+1)*width], Write: write, Position: position}); err != nil {
			return true, err
		}
	}
	return true, nil
}

// ReadPhysical is an observational read; it does not execute guest MMIO.
func (b *Bus) ReadPhysical(address uint64, data []byte) (bool, error) {
	model, r, err := b.Decode(Memory, address, uint64(max(1, len(data))))
	if err != nil || model == nil {
		return model != nil, err
	}
	reader, ok := model.(BARReader)
	if !ok {
		return true, fmt.Errorf("device: BAR has no observational reader")
	}
	return true, reader.ReadBAR(r.BAR, address-r.Base, data)
}
func (b *Bus) Poll(now time.Time) error {
	for _, e := range b.entries {
		if p, ok := e.model.(Poller); ok {
			if err := p.Poll(now); err != nil {
				return fmt.Errorf("device %s: %w", e.spec.Name, err)
			}
		}
	}
	return b.SyncIRQ()
}
func (b *Bus) SyncIRQ() error {
	if len(b.entries) == 0 && len(b.irq) == 0 {
		return nil
	}
	desired := map[uint32]bool{}
	for _, e := range b.entries {
		if d, ok := e.model.(Interrupt); ok {
			if line, on := d.Interrupt(); on {
				desired[line] = true
			}
		}
	}
	if b.irq == nil {
		b.irq = map[uint32]bool{}
	}
	// Deassert moved/cleared lines before asserting new ones. Shared lines are ORed.
	for line := range b.irq {
		if !desired[line] {
			if b.SetIRQ == nil {
				return fmt.Errorf("device: no IRQ sink")
			}
			if err := b.SetIRQ(line, false); err != nil {
				return err
			}
			delete(b.irq, line)
		}
	}
	for line := range desired {
		if !b.irq[line] {
			if b.SetIRQ == nil {
				return fmt.Errorf("device: no IRQ sink")
			}
			if err := b.SetIRQ(line, true); err != nil {
				return err
			}
			b.irq[line] = true
		}
	}
	return nil
}
func (b *Bus) Deadline() time.Time {
	var next time.Time
	for _, e := range b.entries {
		if p, ok := e.model.(Poller); ok {
			if t := p.Deadline(); !t.IsZero() && (next.IsZero() || t.Before(next)) {
				next = t
			}
		}
	}
	return next
}
func (b *Bus) State(name string) any {
	for _, e := range b.entries {
		if e.spec.Name == name {
			if d, ok := e.model.(Inspector); ok {
				return d.State()
			}
		}
	}
	return nil
}
func (b *Bus) States() map[string]any {
	out := map[string]any{}
	for _, e := range b.entries {
		out[e.spec.Name] = b.State(e.spec.Name)
	}
	return out
}
func (b *Bus) ReadMemory(name, space string, address uint64, data []byte) error {
	for _, e := range b.entries {
		if e.spec.Name == name {
			if d, ok := e.model.(MemoryReader); ok {
				return d.ReadMemory(space, address, data)
			}
			return fmt.Errorf("device %s: no inspection memory", name)
		}
	}
	return fmt.Errorf("device %s: not attached", name)
}
func (b *Bus) Close() error {
	var err error
	for line := range b.irq {
		if b.SetIRQ != nil {
			err = errors.Join(err, b.SetIRQ(line, false))
		}
	}
	clear(b.irq)
	for i := len(b.entries) - 1; i >= 0; i-- {
		if c, ok := b.entries[i].model.(io.Closer); ok {
			err = errors.Join(err, c.Close())
		}
	}
	b.entries = nil
	return err
}
