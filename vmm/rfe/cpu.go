package rfe

import (
	"context"
	"errors"
	"fmt"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
	"renvo.dev/rfe/x86"
	"sync/atomic"
	"time"
)

// cpu serializes architectural state on the VMM driver thread. Only IRQ lines
// and cancellation cross that boundary. PCJIT owns bounded executable memory.
type cpu struct {
	nativeStop     uint32
	nativeTimer    *time.Timer
	trackedRAM     bool
	jit            *x86.PCJIT
	a20            bool
	core           x86.CPU
	system         *x86.System
	ram            []byte
	regions        []hypervisor.RAMRegion
	pending        *hypervisor.X86Exit
	operations     []mmioOperation
	operationIndex int
	mmio           bool
	canceled       atomic.Bool
	lines          atomic.Uint32
	edges          atomic.Uint32
	pics           [2]pic
	pitControls    [256]uint64
	pit            timer
	closed         bool
	breakpoint     *uint64
	ioTrace        [8]hypervisor.X86Exit
	ioSequence     uint64
}

func newCPU(ctx context.Context) (hypervisor.X86, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &cpu{a20: true}
	c.pics[0].base = 8
	c.pics[1].base = 0x70
	c.system = x86.NewPCSystem(&c.core, c, c)
	return c, nil
}

var _ hypervisor.X86 = (*cpu)(nil)

func (c *cpu) SupportedCPUID() ([]x86state.CPUIDEntry, error) {
	// Do not advertise vector/x87 features merely because a decoder accepts a
	// subset. The CPU remains incomplete and reports unknown opcodes.
	return []x86state.CPUIDEntry{{Function: 0, Eax: 1, Ebx: 0x756e6547, Edx: 0x49656e69, Ecx: 0x6c65746e}, {Function: 1, Eax: 0x663, Edx: 1 << 4}, {Function: 0x80000000, Eax: 0x80000001}, {Function: 0x80000001, Edx: 1 << 29}}, nil
}
func (c *cpu) SetCPUID(entries []x86state.CPUIDEntry) error {
	policy := append([]x86state.CPUIDEntry(nil), entries...)
	c.system.CPUID = func(leaf, sub uint32) (uint32, uint32, uint32, uint32) {
		for _, e := range policy {
			if e.Function == leaf && (e.Flags&1 == 0 || e.Index == sub) {
				return e.Eax, e.Ebx, e.Ecx, e.Edx
			}
		}
		return 0, 0, 0, 0
	}
	return nil
}
func (c *cpu) MapRAM(base, size uint64) ([]byte, error) {
	return c.MapRAMRegions(size, []hypervisor.RAMRegion{{Address: base, Size: size}})
}
func (c *cpu) MapRAMRegions(size uint64, regions []hypervisor.RAMRegion) ([]byte, error) {
	if c.ram != nil || size > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid RAM allocation")
	}
	for j, r := range regions {
		if r.Address+r.Size < r.Address || r.Offset > size || r.Size > size-r.Offset {
			return nil, fmt.Errorf("invalid RAM region")
		}
		for _, old := range regions[:j] {
			if r.Address < old.Address+old.Size && old.Address < r.Address+r.Size {
				return nil, fmt.Errorf("overlapping RAM region")
			}
		}
	}
	c.ram = make([]byte, int(size))
	c.regions = append([]hypervisor.RAMRegion(nil), regions...)
	var err error
	c.jit, err = x86.NewPCJIT(&c.core, c.ram, c.nativeOffset)
	if err != nil {
		c.ram = nil
		c.regions = nil
		return nil, err
	}
	return c.ram, nil
}
func (c *cpu) Registers() (x86state.Registers, error) {
	r := c.core.R
	return x86state.Registers{Rax: r[0], Rcx: r[1], Rdx: r[2], Rbx: r[3], Rsp: r[4], Rbp: r[5], Rsi: r[6], Rdi: r[7], R8: r[8], R9: r[9], R10: r[10], R11: r[11], R12: r[12], R13: r[13], R14: r[14], R15: r[15], Rip: c.core.PC, Rflags: c.core.Flags}, nil
}
func (c *cpu) SetRegisters(r x86state.Registers) error {
	c.core.R = [16]uint64{r.Rax, r.Rcx, r.Rdx, r.Rbx, r.Rsp, r.Rbp, r.Rsi, r.Rdi, r.R8, r.R9, r.R10, r.R11, r.R12, r.R13, r.R14, r.R15}
	c.core.PC, c.core.Flags = r.Rip, r.Rflags
	c.updateCPL()
	return nil
}
func fromSegment(s x86state.Segment) x86.Segment {
	return x86.Segment{Selector: s.Selector, Base: s.Base, Limit: s.Limit, Flags: uint16(s.Type) | uint16(s.S)<<4 | uint16(s.Dpl)<<5 | uint16(s.Present)<<7 | uint16(s.Avl)<<12 | uint16(s.L)<<13 | uint16(s.Db)<<14 | uint16(s.G)<<15}
}
func toSegment(s x86.Segment) x86state.Segment {
	return x86state.Segment{Selector: s.Selector, Base: s.Base, Limit: s.Limit, Type: uint8(s.Flags) & 15, S: uint8(s.Flags>>4) & 1, Dpl: uint8(s.Flags>>5) & 3, Present: uint8(s.Flags>>7) & 1, Avl: uint8(s.Flags>>12) & 1, L: uint8(s.Flags>>13) & 1, Db: uint8(s.Flags>>14) & 1, G: uint8(s.Flags>>15) & 1}
}
func (c *cpu) SystemRegisters() (x86state.SystemRegisters, error) {
	s := c.system
	g := s.Segments
	return x86state.SystemRegisters{Es: toSegment(g[0]), Cs: toSegment(g[1]), Ss: toSegment(g[2]), Ds: toSegment(g[3]), Fs: toSegment(g[4]), Gs: toSegment(g[5]), Tr: toSegment(s.TR), Ldt: toSegment(s.LDTR), Gdt: x86state.DescriptorTable{Base: s.GDTR.Base, Limit: s.GDTR.Limit}, Idt: x86state.DescriptorTable{Base: s.IDTR.Base, Limit: s.IDTR.Limit}, Cr0: s.CR[0], Cr2: s.CR[2], Cr3: s.CR[3], Cr4: s.CR[4], Cr8: s.CR[8], Efer: s.EFER}, nil
}
func (c *cpu) SetSystemRegisters(r x86state.SystemRegisters) error {
	s := c.system
	// Firmware often writes back unchanged control registers while updating
	// an ordinary segment cache. That is not an architectural TLB flush.
	flush := !c.trackedRAM || s.CR[0] != r.Cr0 || s.CR[3] != r.Cr3 || s.CR[4] != r.Cr4 || s.EFER != r.Efer
	s.Segments = [6]x86.Segment{fromSegment(r.Es), fromSegment(r.Cs), fromSegment(r.Ss), fromSegment(r.Ds), fromSegment(r.Fs), fromSegment(r.Gs)}
	s.TR, s.LDTR = fromSegment(r.Tr), fromSegment(r.Ldt)
	s.GDTR = x86.Table{Base: r.Gdt.Base, Limit: r.Gdt.Limit}
	s.IDTR = x86.Table{Base: r.Idt.Base, Limit: r.Idt.Limit}
	s.CR[0], s.CR[2], s.CR[3], s.CR[4], s.CR[8], s.EFER = r.Cr0, r.Cr2, r.Cr3, r.Cr4, r.Cr8, r.Efer
	c.updateCPL()
	if flush {
		s.Flush()
	}
	return nil
}

// VM86 always executes at CPL3; CS is a real-mode segment value, not a
// protected selector. Firmware synchronization must not derive privilege from
// its low bits. Real mode always runs at CPL0.
func (c *cpu) updateCPL() {
	s := c.system
	if s.CR[0]&1 == 0 {
		s.CPL = 0
	} else if c.core.Flags&(1<<17) != 0 {
		s.CPL = 3
	} else {
		s.CPL = uint8(s.Segments[1].Selector & 3)
	}
}
func (c *cpu) In(port uint16, n int) uint32 {
	atomic.StoreUint32(&c.nativeStop, 1)
	if v, ok := c.deviceIn(port); ok {
		return uint32(v)
	}
	c.pending = &hypervisor.X86Exit{Reason: hypervisor.X86ExitIO, Port: port, Size: uint8(n), Count: 1, Data: make([]byte, n)}
	return 0
}
func (c *cpu) Out(port uint16, n int, v uint32) {
	atomic.StoreUint32(&c.nativeStop, 1)
	if c.deviceOut(port, byte(v)) {
		return
	}
	data := make([]byte, n)
	for j := range data {
		data[j] = byte(v >> uint(j*8))
	}
	c.pending = &hypervisor.X86Exit{Reason: hypervisor.X86ExitIO, Port: port, Size: uint8(n), Count: 1, Write: true, Data: data}
}
func (c *cpu) CompleteIO() error {
	if c.pending != nil && c.pending.Reason == hypervisor.X86ExitIO {
		ex := *c.pending
		ex.Data = append([]byte(nil), ex.Data...)
		c.ioTrace[c.ioSequence%8] = ex
		c.ioSequence++
	}
	if c.pending != nil && !c.mmio && !c.pending.Write {
		var v uint64
		for j, b := range c.pending.Data {
			v |= uint64(b) << uint(j*8)
		}
		mask := uint64(1)<<uint(c.pending.Size*8) - 1
		if c.pending.Size == 4 {
			c.core.R[0] = v
		} else {
			c.core.R[0] = c.core.R[0]&^mask | v
		}
	}
	if c.mmio && len(c.operations) != 0 {
		c.operations[len(c.operations)-1].ready = true
	}
	c.pending = nil
	c.mmio = false
	return nil
}
func (c *cpu) CompleteMMIORead(v uint64, n uint32) {
	if len(c.operations) == 0 {
		return
	}
	op := &c.operations[len(c.operations)-1]
	for j := range op.ex.Data {
		op.ex.Data[j] = byte(v >> uint(j*8))
	}
	op.ready = true
}

type mmioOperation struct {
	ex    hypervisor.X86Exit
	ready bool
}

// Journal device accesses until the entire instruction retires. Read/modify/
// write instructions may exit more than once and must not replay a completed
// device read or write. No interrupts may interleave an unfinished instruction.
func (c *cpu) accessMMIO(a uint64, n int, write bool, v uint64) (uint64, error) {
	index := c.operationIndex
	c.operationIndex++
	if index < len(c.operations) {
		op := c.operations[index]
		if !op.ready || op.ex.Reason != hypervisor.X86ExitMMIO || op.ex.Address != a || int(op.ex.Size) != n || op.ex.Write != write {
			return 0, fmt.Errorf("inconsistent MMIO instruction replay")
		}
		var value uint64
		for j, b := range op.ex.Data {
			value |= uint64(b) << uint(j*8)
		}
		if write && value != v {
			return 0, fmt.Errorf("MMIO write changed during replay")
		}
		return value, nil
	}
	data := make([]byte, n)
	for j := range data {
		data[j] = byte(v >> uint(j*8))
	}
	ex := hypervisor.X86Exit{Reason: hypervisor.X86ExitMMIO, Address: a, Size: uint8(n), Count: 1, Write: write, Data: data}
	c.operations = append(c.operations, mmioOperation{ex: ex})
	return 0, &memoryExit{ex}
}

type memoryExit struct{ ex hypervisor.X86Exit }

func (e *memoryExit) Error() string { return fmt.Sprintf("MMIO at %#x", e.ex.Address) }
func (c *cpu) SetA20(enabled bool) error {
	if c.a20 != enabled && c.jit != nil {
		c.jit.Invalidate()
	}
	c.a20 = enabled
	return nil
}
func (c *cpu) mapped(a uint64, n int) ([]byte, bool) {
	if !c.a20 {
		a &^= 1 << 20
	}
	if n < 1 || n > 8 {
		return nil, false
	}
	for _, r := range c.regions {
		if a >= r.Address && a-r.Address <= r.Size && uint64(n) <= r.Size-(a-r.Address) {
			off := r.Offset + a - r.Address
			return c.ram[off : off+uint64(n)], true
		}
	}
	return nil, false
}
func (c *cpu) Read(a uint64, n int, execute bool) (uint64, error) {
	if n < 1 || n > 8 {
		return 0, fmt.Errorf("invalid physical read width %d", n)
	}
	if !c.a20 && (a^(a+uint64(n)-1))&(1<<20) != 0 {
		var v uint64
		for j := 0; j < n; j++ {
			b, err := c.Read(a+uint64(j), 1, execute)
			if err != nil {
				return 0, err
			}
			v |= b << uint(j*8)
		}
		return v, nil
	}
	if b, ok := c.mapped(a, n); ok {
		var v uint64
		for j, x := range b {
			v |= uint64(x) << uint(j*8)
		}
		return v, nil
	}
	if execute {
		return 0, fmt.Errorf("instruction fetch from unmapped physical address %#x", a)
	}
	return c.accessMMIO(a, n, false, 0)
}
func (c *cpu) Write(a uint64, n int, v uint64) error {
	if n < 1 || n > 8 {
		return fmt.Errorf("invalid physical write width %d", n)
	}
	if !c.a20 && (a^(a+uint64(n)-1))&(1<<20) != 0 {
		for j := 0; j < n; j++ {
			if err := c.Write(a+uint64(j), 1, v>>uint(j*8)); err != nil {
				return err
			}
		}
		return nil
	}
	if b, ok := c.mapped(a, n); ok {
		if c.jit != nil {
			if off, ok := c.nativeOffset(a, n); ok {
				c.jit.BeforeWrite(off, n)
			}
		}
		for j := range b {
			b[j] = byte(v >> uint(j*8))
		}
		return nil
	}
	_, err := c.accessMMIO(a, n, true, v)
	return err
}
func (c *cpu) Peek(a uint64, n int) (uint64, bool) {
	if _, ok := c.mapped(a, n); !ok {
		return 0, false
	}
	v, e := c.Read(a, n, true)
	return v, e == nil
}
func (c *cpu) Run(ctx context.Context) (hypervisor.X86Exit, error) { return c.RunUntil(ctx, nil) }
func (c *cpu) RunUntil(ctx context.Context, handle func(hypervisor.X86Exit) (bool, error)) (hypervisor.X86Exit, error) {
	if c.closed {
		return hypervisor.X86Exit{}, fmt.Errorf("RFE CPU closed")
	}
	if c.jit != nil && !c.trackedRAM {
		c.jit.ExternalWrite()
	}
	if err := c.CompleteIO(); err != nil {
		return hypervisor.X86Exit{}, err
	}
	stopContext := context.AfterFunc(ctx, func() { atomic.StoreUint32(&c.nativeStop, 1) })
	defer stopContext()
	if c.jit != nil {
		c.jit.SetStopFlag(&c.nativeStop)
		defer c.jit.SetStopFlag(nil)
	}
	defer func() {
		if c.nativeTimer != nil {
			c.nativeTimer.Stop()
		}
	}()
	for {
		atomic.StoreUint32(&c.nativeStop, 0)
		if err := ctx.Err(); err != nil {
			return hypervisor.X86Exit{}, err
		}
		if c.canceled.Swap(false) {
			return hypervisor.X86Exit{}, context.Canceled
		}
		if len(c.operations) == 0 {
			if err := c.interrupts(); err != nil {
				return hypervisor.X86Exit{}, err
			}
		}
		if c.system.Halted {
			select {
			case <-ctx.Done():
				return hypervisor.X86Exit{}, ctx.Err()
			case <-time.After(100 * time.Microsecond):
			}
			continue
		}
		if len(c.operations) == 0 && c.breakpoint != nil && c.system.Segments[1].Base+c.core.PC == *c.breakpoint {
			c.breakpoint = nil
			return hypervisor.X86Exit{Reason: hypervisor.X86ExitDebug}, nil
		}
		c.operationIndex = 0
		var err error
		if c.jit != nil && len(c.operations) == 0 && c.breakpoint == nil {
			// Poll cancellation and IRQs between bounded native slices, not
			// between every tiny translated block. Slow/device instructions
			// return early; IF/shadow changes are architectural boundaries.
			c.armNativeDeadline()
			err = c.jit.Run(^uint64(0))
		} else {
			err = c.core.Step()
		}
		if err != nil {
			var mem *memoryExit
			if !errors.As(err, &mem) {
				return hypervisor.X86Exit{}, err
			}
			ex := mem.ex
			c.pending, c.mmio = &ex, true
		}
		if err == nil {
			c.operations = nil
		}
		if c.pending == nil {
			continue
		}
		ex := *c.pending
		if handle == nil {
			return ex, nil
		}
		handled, err := handle(ex)
		if c.jit != nil && !c.trackedRAM {
			c.jit.ExternalWrite()
		}
		if err != nil || !handled {
			return ex, err
		}
		if err = c.CompleteIO(); err != nil {
			return hypervisor.X86Exit{}, err
		}
	}
}
func (c *cpu) SetIRQ(line uint32, level bool) error {
	if line > 15 {
		return fmt.Errorf("invalid IRQ %d", line)
	}
	if level {
		if old := c.lines.Or(1 << line); old&(1<<line) == 0 {
			c.edges.Or(1 << line)
		}
		atomic.StoreUint32(&c.nativeStop, 1) // publish the edge before waking native execution
	} else {
		c.lines.And(^(uint32(1) << line))
	}
	return nil
}
func (c *cpu) InterruptState() (map[string]uint64, error) {
	state := map[string]uint64{"retired": c.core.Retired, "code_bits": uint64(c.system.CodeBits()), "irq_lines": uint64(c.lines.Load())}
	if c.jit != nil {
		for k, v := range c.jit.Stats() {
			state["jit."+k] = v
		}
	}
	if c.system.Halted {
		state["halted"] = 1
	}
	for j, p := range c.pics {
		prefix := fmt.Sprintf("pic%d.", j)
		state[prefix+"mask"] = uint64(p.mask)
		state[prefix+"base"] = uint64(p.base)
		if p.readISR {
			state[prefix+"read_isr"] = 1
		}
		if p.specialMask {
			state[prefix+"special_mask"] = 1
		}
		state[prefix+"irr"] = uint64(p.irr)
		state[prefix+"isr"] = uint64(p.isr)
	}
	for command, count := range c.pitControls {
		if count != 0 {
			state[fmt.Sprintf("pit.command%02x", command)] = count
		}
	}
	state["pit.mode"], state["pit.reload"], state["pit.periods"] = uint64(c.pit.mode), uint64(c.pit.reload), c.pit.elapsed
	for vector, count := range c.system.InterruptCounts {
		if count != 0 {
			state[fmt.Sprintf("interrupt.%02x", vector)] = count
		}
	}
	for j := uint64(0); j < 8 && j < c.system.InterruptSequence; j++ {
		e := c.system.InterruptTrace[(c.system.InterruptSequence-1-j)%8]
		p := fmt.Sprintf("trap%d.", j)
		state[p+"pc"], state[p+"vector"], state[p+"code"], state[p+"cr0"] = e[0], e[1], e[2], e[3]
	}
	state["fault_count"] = c.system.FaultCount
	for j := uint64(0); j < 4 && j < c.system.FaultCount; j++ {
		entry := c.system.FaultTrace[(c.system.FaultCount-1-j)%8]
		prefix := fmt.Sprintf("fault%d.", j)
		state[prefix+"pc"], state[prefix+"address"], state[prefix+"code"] = entry[0], entry[1], entry[2]
	}
	for j := uint64(0); j < 8 && j < c.ioSequence; j++ {
		ex := c.ioTrace[(c.ioSequence-1-j)%8]
		prefix := fmt.Sprintf("io%d.", j)
		state[prefix+"port"] = uint64(ex.Port)
		state[prefix+"size"] = uint64(ex.Size)
		if ex.Write {
			state[prefix+"write"] = 1
		}
		var value uint64
		for k, b := range ex.Data {
			if k < 8 {
				value |= uint64(b) << uint(k*8)
			}
		}
		state[prefix+"value"] = value
	}
	return state, nil
}
func (c *cpu) Cancel() error {
	c.canceled.Store(true)
	atomic.StoreUint32(&c.nativeStop, 1)
	return nil
}
func (c *cpu) Close() error {
	if c.nativeTimer != nil {
		c.nativeTimer.Stop()
	}
	c.closed = true
	var err error
	if c.jit != nil {
		err = c.jit.Close()
		c.jit = nil
	}
	c.ram = nil
	return err
}

// Native descriptors must never expose an unassigned/device byte through an
// apparently mapped RAM page, including unaligned/split physical regions.
func (c *cpu) nativeOffset(a uint64, n int) (uint64, bool) {
	if !c.a20 {
		a &^= 1 << 20
	}
	for _, r := range c.regions {
		first, last := a&^uint64(4095), (a+uint64(n)-1)|4095
		if first >= r.Address && last >= first && last-r.Address < r.Size {
			off := r.Offset + a - r.Address
			if off&4095 != a&4095 {
				return 0, false
			}
			return off, true
		}
	}
	return 0, false
}
func (c *cpu) SwitchAddressSpace() {
	if c.jit != nil {
		c.jit.SwitchAddressSpace()
	}
}
func (c *cpu) InvalidateNativeRange(base, size uint64) {
	if c.jit != nil {
		c.jit.InvalidateNativeRange(base, size)
	}
}
func (c *cpu) InvalidateMappings() {
	if c.jit != nil {
		c.jit.Invalidate()
	}
}

// TrackLegacyPageTable opts into architectural translation reuse only when
// all borrowed RAM writes participate in the physical write barrier.
func (c *cpu) TrackLegacyPageTable(a uint64) bool {
	c.MarkPageTable(a)
	if c.jit == nil || !c.trackedRAM {
		return false
	}
	_, ok := c.nativeOffset(a, 4)
	return ok
}
func (c *cpu) PageTableOffset(a uint64) (uint64, bool) { return c.nativeOffset(a, 1) }
func (c *cpu) MarkPageTable(a uint64) {
	if c.jit != nil {
		if off, ok := c.nativeOffset(a, 1); ok {
			n := 4
			if c.system.EFER&(1<<10) != 0 {
				n = 8
			}
			c.jit.MarkPageTableEntry(off, n)
		}
	}
}
func (c *cpu) setPageBits(a uint64, n int, bits uint64) error {
	value, err := c.Read(a, n, false)
	if err != nil {
		return err
	}
	if value|bits == value {
		return nil
	}
	if b, ok := c.mapped(a, n); ok {
		if c.jit != nil {
			if off, ok := c.nativeOffset(a, n); ok {
				c.jit.BeforePageTableMetadata(off, n)
			}
		}
		value |= bits
		for j := range b {
			b[j] = byte(value >> uint(8*j))
		}
		return nil
	}
	return c.Write(a, n, value|bits)
}
func (c *cpu) SetLegacyPageBits(a, bits uint64) error { return c.setPageBits(a, 4, bits) }
func (c *cpu) SetPageTableBits(a, bits uint64) error  { return c.setPageBits(a, 8, bits) }

// SetRAMWriteTracking is an owner contract: after enabling it, every host
// mutation of borrowed RAM must call BeforeRAMWrite before changing bytes.
// Untracked owners retain conservative full revocation at each Run boundary.
func (c *cpu) SetRAMWriteTracking(enabled bool) {
	c.trackedRAM = enabled
	if c.jit != nil {
		c.jit.ExternalWrite()
	}
}
func (c *cpu) BeforeRAMWrite(address, size uint64) {
	if c.jit == nil || size == 0 || address+size < address {
		return
	}
	for size != 0 {
		n := min(size, 4096-(address&4095))
		if off, ok := c.nativeOffset(address, int(n)); ok {
			c.jit.BeforeWrite(off, int(n))
		}
		address += n
		size -= n
	}
}
