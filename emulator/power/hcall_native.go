package power

import "fmt"

// NativeHypercall is a declarative hypervisor-call response executed in Go,
// for frequent calls whose effect is fixed: optionally zero a guest buffer,
// then set result registers. Calls outside the declared contract fall back
// to the machine's scripted Hypercall handler, which keeps the policy for
// unusual arguments in one place.
type NativeHypercall struct {
	Name string
	// GPRs are the result registers, applied in order.
	GPRs []RegisterValue
	// ZeroFill, if set, zeroes a guest buffer before setting results.
	ZeroFill *ZeroFill
	// Yield ends the CPU's scheduling quantum after the call.
	Yield bool
	// MSRSet ORs bits into the MSR (for example EE before a cede) and
	// Wait then suspends the CPU until an interrupt or wake.
	MSRSet uint64
	Wait   bool
	// Wake, if set, wakes another CPU (CPU.Wake).
	Wake *WakeCPU
	// ScriptEvery, when nonzero, passes every Nth call to the scripted
	// handler instead, for calls that also give the host a chance to
	// service devices (such as an idle-loop yield polling a console).
	ScriptEvery uint64
	calls       uint64
}

// WakeCPU names the CPU to wake by the index in GPR[Index]; indexes at or
// above Limit are outside the native contract.
type WakeCPU struct {
	Index int
	Limit uint64
}

// RegisterValue is one general-register assignment.
type RegisterValue struct {
	Register int
	Value    uint64
}

// ZeroFill describes a guest buffer to clear: GPR[Length] bytes rounded
// down to Align (or Size bytes when Length is negative) at real address
// GPR[Address] & AddressMask. Lengths over Limit, addresses not aligned to
// AddressAlign and buffers ending beyond End (when nonzero) are outside the
// native contract.
type ZeroFill struct {
	Address, Length int
	AddressMask     uint64
	Align, Limit    uint64
	Size            uint64
	AddressAlign    uint64
	End             uint64
}

func (n *NativeHypercall) validate() error {
	for _, r := range n.GPRs {
		if r.Register < 0 || r.Register > 31 {
			return fmt.Errorf("power: native hypercall %q register %d", n.Name, r.Register)
		}
	}
	if w := n.Wake; w != nil && (w.Index < 0 || w.Index > 31) {
		return fmt.Errorf("power: native hypercall %q wake register %d", n.Name, w.Index)
	}
	if f := n.ZeroFill; f != nil {
		if f.Address < 0 || f.Address > 31 || f.Length > 31 || f.Align == 0 || f.Align&(f.Align-1) != 0 ||
			f.AddressAlign&(f.AddressAlign-1) != 0 {
			return fmt.Errorf("power: native hypercall %q zero fill registers or alignment", n.Name)
		}
	}
	return nil
}

// apply performs the call and reports whether it was within the contract.
func (n *NativeHypercall) apply(c *CPU) bool {
	if n.ScriptEvery != 0 {
		n.calls++
		if n.calls%n.ScriptEvery == 0 {
			return false
		}
	}
	var wake *CPU
	if w := n.Wake; w != nil {
		target := c.GPR[w.Index]
		if target >= w.Limit || target >= uint64(len(c.m.CPUs)) {
			return false
		}
		wake = c.m.CPUs[target]
	}
	if f := n.ZeroFill; f != nil {
		length := f.Size
		if f.Length >= 0 {
			length = c.GPR[f.Length]
		}
		if length > f.Limit {
			return false
		}
		length &^= f.Align - 1
		address := c.GPR[f.Address] & f.AddressMask
		m := c.m
		end := uint64(len(m.Mem))
		if f.End != 0 {
			end = min(end, f.End)
		}
		if address > end || length > end-address || f.AddressAlign != 0 && address&(f.AddressAlign-1) != 0 {
			return false
		}
		clear(m.Mem[address : address+length])
		m.stored(c, address, int(length))
	}
	for _, r := range n.GPRs {
		c.GPR[r.Register] = r.Value
	}
	if wake != nil {
		wake.Wake()
	}
	if n.MSRSet != 0 {
		c.setMSR(c.MSR | n.MSRSet)
	}
	if n.Wait {
		c.WaitForInterrupt()
	}
	if n.Yield {
		c.Yield()
	}
	return true
}

// SetNativeHypercall installs (or with nil removes) the native response to
// the call whose r3 token is token.
func (m *Machine) SetNativeHypercall(token uint64, n *NativeHypercall) error {
	if n == nil {
		delete(m.nativeHypercalls, token)
		return nil
	}
	if err := n.validate(); err != nil {
		return err
	}
	if m.nativeHypercalls == nil {
		m.nativeHypercalls = map[uint64]*NativeHypercall{}
	}
	m.nativeHypercalls[token] = n
	return nil
}

// HypercallCounts returns the number of hypervisor calls made with each r3
// token, native and scripted.
func (m *Machine) HypercallCounts() map[uint64]uint64 { return m.hypercallCounts }
