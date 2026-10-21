package cc

import (
	"encoding/binary"
	"fmt"
	"j5.nz/cc/hypervisor"
	"time"
)

// UHCI 1.1 transport: PCI 00:03.0, BAR4 I/O, two low-speed root ports.
// Native descriptor DMA is bounded to ordinary guest RAM. No guest USB driver
// or accelerator is injected. Queue processing stays on the owning CPU loop.
type uhci struct {
	config                            [256]byte
	command, status, interrupt, frame uint16
	base                              uint32
	sof                               byte
	ports                             [2]uint16
	devices                           [2]*usbHID
	last                              time.Time
	memory                            func(uint64, uint64) ([]byte, error)
	irq                               func(uint32, bool) error
	transactions, frames              uint64
	fault                             string
}

func newUHCI(memory func(uint64, uint64) ([]byte, error), irq func(uint32, bool) error) *uhci {
	u := &uhci{memory: memory, irq: irq, status: 0x20, sof: 64}
	binary.LittleEndian.PutUint16(u.config[:], 0x1234)
	binary.LittleEndian.PutUint16(u.config[2:], 0xcc03)
	u.config[4] = 5
	u.config[8] = 1
	u.config[10] = 3
	u.config[11] = 12
	binary.LittleEndian.PutUint32(u.config[0x20:], 0xc101)
	binary.LittleEndian.PutUint16(u.config[0x2c:], 0x1234)
	binary.LittleEndian.PutUint16(u.config[0x2e:], 0xcc03)
	u.config[0x3c], u.config[0x3d] = 17, 1
	u.config[0xc1] = 0x20
	for n := range u.ports {
		u.ports[n] = 0x1a3
		u.devices[n] = newUSBHID(n == 1)
	}
	return u
}
func (u *uhci) writeConfig(offset int, v byte) {
	switch offset {
	case 4:
		u.config[offset] = v & 5
	case 5:
		u.config[offset] = v & 4 // INTx disable.
	case 0x20:
		u.config[offset] = v&0xe0 | 1
	case 0x21, 0x22, 0x23:
		u.config[offset] = v
	case 0xc1:
		u.config[offset] = v & 0x20
	}
}
func (u *uhci) ioBase() uint32 { return binary.LittleEndian.Uint32(u.config[0x20:]) & 0xffffffe0 }
func (u *uhci) updateIRQ() error {
	enabled := u.config[4]&1 != 0 && u.config[5]&4 == 0
	pending := (u.status&1 != 0 && u.interrupt&12 != 0) || (u.status&2 != 0 && u.interrupt&1 != 0) || (u.status&4 != 0 && u.interrupt&2 != 0) || u.status&0x18 != 0
	return u.irq(17, enabled && pending)
}
func (u *uhci) io(ex hypervisor.X86Exit, now time.Time) error {
	for n := uint32(0); n < ex.Count; n++ {
		data := ex.Data[int(n)*int(ex.Size) : int(n+1)*int(ex.Size)]
		off := int(uint32(ex.Port) - u.ioBase())
		if off < 0 || off+len(data) > 32 {
			return fmt.Errorf("UHCI register transfer outside aperture")
		}
		var regs [32]byte
		binary.LittleEndian.PutUint16(regs[:], u.command)
		binary.LittleEndian.PutUint16(regs[2:], u.status)
		binary.LittleEndian.PutUint16(regs[4:], u.interrupt)
		binary.LittleEndian.PutUint16(regs[6:], u.frame)
		binary.LittleEndian.PutUint32(regs[8:], u.base)
		regs[12] = u.sof
		for i, p := range u.ports {
			binary.LittleEndian.PutUint16(regs[16+i*2:], p)
		}
		if !ex.Write {
			copy(data, regs[off:])
			continue
		}
		old := regs
		copy(regs[off:], data)
		touched := func(start, size int) bool { return off < start+size && off+len(data) > start }
		if touched(0, 2) {
			cmd := binary.LittleEndian.Uint16(regs[:]) & 0xff
			if cmd&2 != 0 {
				u.command = 0
				u.status = 0x20
				u.interrupt = 0
				u.frame = 0
				u.base = 0
				u.sof = 64
				u.last = now
			} else {
				if cmd&4 != 0 && u.command&4 == 0 {
					for i := range u.devices {
						u.devices[i] = newUSBHID(i == 1)
						u.ports[i] = 0x1a3
					}
				}
				if (cmd^u.command)&1 != 0 {
					u.last = now
				}
				u.command = cmd
				if cmd&1 != 0 {
					u.status &^= 0x20
				} else {
					u.status |= 0x20
				}
			}
		}
		if touched(2, 2) {
			var mask uint16
			for i := range data {
				if off+i >= 2 && off+i < 4 {
					mask |= uint16(data[i]) << ((off + i - 2) * 8)
				}
			}
			u.status &^= mask & 0x1f
		}
		if touched(4, 2) {
			u.interrupt = binary.LittleEndian.Uint16(regs[4:]) & 15
		}
		if touched(6, 2) {
			u.frame = binary.LittleEndian.Uint16(regs[6:]) & 0x7ff
		}
		if touched(8, 4) {
			u.base = binary.LittleEndian.Uint32(regs[8:]) & 0xfffff000
		}
		if touched(12, 1) {
			u.sof = regs[12] & 0x7f
		}
		for i := range u.ports {
			at := 16 + i*2
			if !touched(at, 2) {
				continue
			}
			v, previous := binary.LittleEndian.Uint16(regs[at:]), binary.LittleEndian.Uint16(old[at:])
			// Connection/line status are read-only; CSC/PEC are W1C.
			changed := previous & 0xa &^ (v & 0xa)
			control := v & 0x1244
			if v&0x200 != 0 && previous&0x200 == 0 {
				u.devices[i] = newUSBHID(i == 1)
				control &^= 4
			}
			if (control^previous)&4 != 0 {
				changed |= 8
			}
			u.ports[i] = 0x1a1 | changed | control
		}
	}
	return u.updateIRQ()
}
func (u *uhci) fail(message string, process bool) error {
	u.fault = message
	if process {
		u.status |= 0x10
	} else {
		u.status |= 8
	}
	u.command &^= 1
	u.status |= 0x20
	return u.updateIRQ()
}
func (u *uhci) poll(now time.Time) error {
	if u.command&1 == 0 || u.command&0xc != 0 || u.config[4]&5 != 5 {
		u.last = now
		return u.updateIRQ()
	}
	if u.last.IsZero() {
		u.last = now
		return nil
	}
	elapsed := int(now.Sub(u.last) / time.Millisecond)
	// Host suspension must not replay an unbounded number of stale schedules.
	if elapsed > 1024 {
		u.frame = (u.frame + uint16((elapsed-1024)&0x7ff)) & 0x7ff
		elapsed = 1024
		u.last = now.Add(-1024 * time.Millisecond)
	}
	for n := 0; n < elapsed; n++ {
		frame, err := u.memory(uint64(u.base)+uint64(u.frame&1023)*4, 4)
		if err != nil {
			return u.fail(err.Error(), false)
		}
		if err := u.schedule(binary.LittleEndian.Uint32(frame)); err != nil {
			return u.fail(err.Error(), true)
		}
		u.frame = (u.frame + 1) & 0x7ff
		u.frames++
		u.last = u.last.Add(time.Millisecond)
	}
	return u.updateIRQ()
}

func (u *uhci) schedule(link uint32) error {
	// Horizontal QH links can legally cycle for bandwidth reclamation. Process
	// each QH once per frame; descriptor cycles and bounds never hang the host.
	seen := map[uint32]bool{}
	stack := []uint32{}
	qh := uint32(0)
	for budget := 0; budget < 2048; budget++ {
		if link&1 != 0 {
			if len(stack) == 0 {
				return nil
			}
			link = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			qh = 0
			continue
		}
		address := link & 0xfffffff0
		if link&2 != 0 {
			if seen[address] {
				link = 1
				continue
			}
			seen[address] = true
			data, err := u.memory(uint64(address), 8)
			if err != nil {
				return err
			}
			if len(stack) >= 128 {
				return fmt.Errorf("UHCI QH nesting exceeds bound")
			}
			stack = append(stack, binary.LittleEndian.Uint32(data))
			qh = address
			link = binary.LittleEndian.Uint32(data[4:])
			continue
		}
		data, err := u.memory(uint64(address), 16)
		if err != nil {
			return err
		}
		next := binary.LittleEndian.Uint32(data)
		// An inactive queue TD is the software tail sentinel. Hardware must
		// leave the QH element on it, not consume its link and lose the
		// controller driver's completion boundary.
		if binary.LittleEndian.Uint32(data[4:])&(1<<23) == 0 {
			if qh != 0 {
				link = 1
			} else {
				link = next
			}
			continue
		}
		done, short, err := u.transfer(data)
		if err != nil {
			return err
		}
		if !done || short {
			link = 1
			continue
		}
		if qh != 0 {
			head, err := u.memory(uint64(qh)+4, 4)
			if err != nil {
				return err
			}
			binary.LittleEndian.PutUint32(head, next)
		}
		link = next
		// Breadth-first TDs return to the horizontal schedule after completion.
		if qh != 0 && next&4 == 0 {
			link = 1
		}
	}
	return fmt.Errorf("UHCI descriptor traversal exceeds bound")
}
func (u *uhci) transfer(td []byte) (bool, bool, error) {
	status := binary.LittleEndian.Uint32(td[4:])
	if status&(1<<23) == 0 {
		return true, false, nil
	}
	token := binary.LittleEndian.Uint32(td[8:])
	pid, address, ep := byte(token), byte(token>>8)&127, byte(token>>15)&15
	maximum := int((token>>21)+1) & 0x7ff
	if maximum > 8 {
		status &^= 1 << 23
		status |= 1 << 22
		binary.LittleEndian.PutUint32(td[4:], status)
		u.status |= 2
		return false, false, nil
	}
	buffer, err := u.memory(uint64(binary.LittleEndian.Uint32(td[12:])), uint64(maximum))
	if err != nil {
		return false, false, err
	}
	var device *usbHID
	for i, d := range u.devices {
		if u.ports[i]&0x204 == 4 && d.address == address {
			device = d
			break
		}
	}
	n, result := 0, 3
	if device != nil {
		n, result = device.transaction(pid, ep, buffer)
	}
	u.transactions++
	status &^= 0x007f0000 // Old transaction errors.
	switch result {
	case 1:
		status |= 1 << 19
		binary.LittleEndian.PutUint32(td[4:], status)
		return false, false, nil
	case 2:
		status |= 1 << 22
		status &^= 1 << 23
		u.status |= 2
	case 3:
		status |= 1 << 18
		retry := (status >> 27) & 3
		if retry > 0 {
			retry--
			status = status&^(3<<27) | retry<<27
		}
		if retry == 0 {
			status &^= 1 << 23
			u.status |= 2
		}
		binary.LittleEndian.PutUint32(td[4:], status)
		return false, false, nil
	default:
		status &^= 1 << 23
	}
	status = status&^0x7ff | uint32(n-1)&0x7ff
	binary.LittleEndian.PutUint32(td[4:], status)
	short := n < maximum && status&(1<<29) != 0
	if status&(1<<24) != 0 || short {
		u.status |= 1
	}
	return result == 0, short, nil
}
