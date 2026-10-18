package cc

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/emulator/cpu"
	"j5.nz/cc/hypervisor/x86state"
)

const (
	efiExceptionPort = 0xf5
	efiExceptionIDT  = 0x3000
	efiExceptionCode = 0x4000
)

// These tables, like the bootstrap GDT/page tables, are below the firmware
// allocation arena. Stop on the first exception instead of losing its state
// to a triple fault (SVM resets the vCPU before exposing that exit).
func installEFIExceptionGates(ram []byte) x86state.DescriptorTable {
	clear(ram[efiExceptionIDT : efiExceptionIDT+32*16])
	for vector := 0; vector < 32; vector++ {
		address := uint64(efiExceptionCode + vector*8)
		gate := ram[efiExceptionIDT+vector*16:][:16]
		binary.LittleEndian.PutUint16(gate, uint16(address))
		binary.LittleEndian.PutUint16(gate[2:], 8) // bootstrap long-mode CS
		gate[5] = 0x8e                             // present, ring0 interrupt gate
		binary.LittleEndian.PutUint16(gate[6:], uint16(address>>16))
		binary.LittleEndian.PutUint32(gate[8:], uint32(address>>32))
		// Preserve RAX, report the vector, then stop. No IRET or recovery.
		copy(ram[address:], []byte{0x50, 0xb0, byte(vector), 0xe6, efiExceptionPort, 0xf4, 0xeb, 0xfd})
	}
	return x86state.DescriptorTable{Base: efiExceptionIDT, Limit: 32*16 - 1}
}

func (p *pc) efiException() error {
	if err := p.cpu.CompleteIO(); err != nil {
		return err
	}
	r, err := p.cpu.Registers()
	if err != nil {
		return err
	}
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return err
	}
	vector := r.Rax & 255
	if vector >= 32 || r.Rip != efiExceptionCode+vector*8+5 {
		return fmt.Errorf("EFI exception trap outside diagnostic gate: rip=%#x", r.Rip)
	}
	m := efiMemory{p: p, system: &s}
	var frame [56]byte
	offset, errorCode := 8, uint64(0)
	switch vector {
	case 8, 10, 11, 12, 13, 14, 17, 21, 29, 30:
		offset += 8
	}
	if err := m.ReadMemory(r.Rsp, frame[:offset+40], cpu.Read); err != nil {
		return fmt.Errorf("EFI exception vector=%d: unreadable frame: %w", vector, err)
	}
	originalRAX := binary.LittleEndian.Uint64(frame[:])
	if offset == 16 {
		errorCode = binary.LittleEndian.Uint64(frame[8:])
	}
	rip := binary.LittleEndian.Uint64(frame[offset:])
	rsp := binary.LittleEndian.Uint64(frame[offset+24:])
	var instruction [16]byte
	codeErr := m.ReadMemory(rip, instruction[:], cpu.Read)
	return fmt.Errorf("EFI exception vector=%d error=%#x rip=%#x rsp=%#x rax=%#x rcx=%#x rdx=%#x cr2=%#x cr3=%#x instruction_bytes=%x instruction_error=%v last_service=%q", vector, errorCode, rip, rsp, originalRAX, r.Rcx, r.Rdx, s.Cr2, s.Cr3, instruction, codeErr, p.lastService)
}
