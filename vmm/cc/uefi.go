package cc

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/emulator/uefi"
	"github.com/tinyrange/trex/filesystem/fat"
	"github.com/tinyrange/trex/filesystem/gpt"
	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/vmm/ramfb"
	"github.com/tinyrange/trex/windows/guid"
	"j5.nz/cc/hypervisor/x86state"
)

const efiPort = 0xf6

// efiMemory translates service arguments through the guest's current page
// tables. The accelerator owns the bytes; firmware never keeps a second RAM.
type efiMemory struct {
	p      *pc
	system *x86state.SystemRegisters
}

func (m efiMemory) physical(a uint64) (uint64, error) {
	if m.system == nil {
		return a, nil
	}
	s := *m.system
	if s.Efer&(1<<10) == 0 {
		return m.p.physical(a, s)
	}
	if a>>48 != 0 && a>>48 != 0xffff || (a>>47&1 == 0) != (a>>48 == 0) {
		return 0, fmt.Errorf("noncanonical EFI address %#x", a)
	}
	table := s.Cr3 & 0x000ffffffffff000
	for shift := uint(39); ; shift -= 9 {
		b, err := m.p.memory(table+(a>>shift&511)*8, 8)
		if err != nil {
			return 0, err
		}
		e := binary.LittleEndian.Uint64(b)
		if e&1 == 0 {
			return 0, fmt.Errorf("unmapped EFI address %#x at level %d", a, shift)
		}
		table = e & 0x000ffffffffff000
		if shift == 12 {
			return table | a&4095, nil
		}
		if e&128 != 0 && (shift == 30 || shift == 21) {
			mask := uint64(1)<<shift - 1
			return table&^mask | a&mask, nil
		}
	}
}
func (m efiMemory) chunk(a uint64, n int) ([]byte, error) {
	p, err := m.physical(a)
	if err != nil {
		return nil, err
	}
	if p >= ramfb.Address && p-ramfb.Address <= uint64(len(m.p.framebuffer)) && uint64(n) <= uint64(len(m.p.framebuffer))-(p-ramfb.Address) {
		return m.p.framebuffer[p-ramfb.Address : p-ramfb.Address+uint64(n)], nil
	}
	if p >= 0xa0000 && p < 0xc0000 {
		return nil, fmt.Errorf("EFI access to VGA hole")
	}
	return m.p.memory(p, uint64(n))
}
func (m efiMemory) CheckMemory(a uint64, n int, _ cpu.Access) error {
	if n < 0 || uint64(n) > ^uint64(0)-a {
		return fmt.Errorf("EFI memory range overflows")
	}
	for n > 0 {
		size := min(n, 4096-int(a&4095))
		if _, err := m.chunk(a, size); err != nil {
			return err
		}
		a += uint64(size)
		n -= size
	}
	return nil
}
func (m efiMemory) ReadMemory(a uint64, b []byte, access cpu.Access) error {
	if err := m.CheckMemory(a, len(b), access); err != nil {
		return err
	}
	for len(b) > 0 {
		n := min(len(b), 4096-int(a&4095))
		src, _ := m.chunk(a, n)
		copy(b[:n], src)
		b = b[n:]
		a += uint64(n)
	}
	return nil
}
func (m efiMemory) WriteMemory(a uint64, b []byte) error {
	if err := m.CheckMemory(a, len(b), cpu.Write); err != nil {
		return err
	}
	for len(b) > 0 {
		n := min(len(b), 4096-int(a&4095))
		dst, _ := m.chunk(a, n)
		copy(dst, b[:n])
		b = b[n:]
		a += uint64(n)
	}
	return nil
}

func (p *pc) installUEFI() error {
	source := io.NewSectionReader(p.disk.Device, 0, p.disk.Device.Geometry().Size)
	partitions, err := gpt.Read(source)
	if err != nil {
		return err
	}
	espGUID, _ := guid.Parse("{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}")
	var image storage.Reader
	var espIndex int
	for i, part := range partitions {
		if part.TypeGUID != espGUID {
			continue
		}
		files, err := fat.Entries(adapter.File(part.File))
		if err != nil {
			return err
		}
		for _, file := range files {
			if strings.EqualFold(file.Name, "/EFI/Boot/bootx64.efi") {
				image = file.File
				espIndex = i
				break
			}
		}
		if image != nil {
			break
		}
	}
	if image == nil {
		return fmt.Errorf("cc: GPT ESP has no EFI/Boot/bootx64.efi")
	}
	diskPath := []byte{2, 1, 12, 0, 0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0, 1, 1, 6, 0, 0, 1, 3, 1, 8, 0, 0, 0, 0, 0}
	end := []byte{0x7f, 0xff, 4, 0}
	partPath := func(part gpt.Partition) []byte {
		b := append([]byte(nil), diskPath...)
		hd := make([]byte, 42)
		hd[0] = 4
		hd[1] = 1
		hd[2] = 42
		binary.LittleEndian.PutUint32(hd[4:], part.Index)
		binary.LittleEndian.PutUint64(hd[8:], uint64(part.StartLBA))
		binary.LittleEndian.PutUint64(hd[16:], uint64(part.EndLBA-part.StartLBA+1))
		copy(hd[24:], part.UniqueGUID[:])
		hd[40] = 2
		hd[41] = 2
		b = append(b, hd...)
		return append(b, end...)
	}
	p.efiMemory = &efiMemory{p: p}
	p.efi, err = uefi.NewFirmware(image, uefi.FirmwareOptions{
		PhysicalMemory: efiMemory{p: p},
		Options: uefi.Options{MemoryBase: 0x10000, Memory: uint64(len(p.ram)) - 0x10000, Reservations: []uefi.MemoryReservation{{Address: 0xa0000, Pages: 0x60, Type: 0}}, TimeUnix: p.started.Unix(), DevicePath: partPath(partitions[espIndex]), Observe: func(e uefi.Event) error {
			if e.Kind == "console" {
				p.console = append(p.console, []byte(e.Text)...)
			}
			return nil
		}},
		Stall: func(d time.Duration) error { time.Sleep(d); return nil }, Memory: p.efiMemory, Architecture: "amd64", Gate: func(uint64) []byte { return []byte{0xe6, efiPort, 0xc3, 0xcc} }, Clock: func() (uint64, uint64) { return uint64(max(0, p.now().Sub(p.started))), uint64(time.Second) },
	})
	if err != nil {
		return err
	}
	if err = p.efi.InstallGraphicsOutput(ramfb.Address+ramfb.Pixels, p.framebuffer[ramfb.Pixels:], 1280, 720, 1280); err != nil {
		return err
	}
	for i, v := range []uint32{ramfb.Magic, 1, 1280, 720, 1280 * 4, 1} {
		binary.LittleEndian.PutUint32(p.framebuffer[i*4:], v)
	}
	entry := p.efi.Entry()
	disk, err := p.efi.AttachBlockDevice(p.disk.Device, uefi.BlockOptions{DevicePath: append(append([]byte(nil), diskPath...), end...), ReadOnly: p.disk.ReadOnly})
	if err != nil {
		return err
	}
	for i, part := range partitions {
		handle := uint64(0)
		if i == espIndex {
			handle = entry.DeviceHandle
		}
		if _, err = p.efi.AttachBlockPartition(disk, part.StartLBA*512, (part.EndLBA-part.StartLBA+1)*512, partPath(part), handle); err != nil {
			return err
		}
	}
	if _, err = p.efi.InstallConfigurationTable("{8868E871-E4F1-11D3-BC22-0080C73C8881}", p.ram[0xe0000:0xe0000+36], 9); err != nil {
		return err
	}
	// Bootstrap tables are outside the firmware allocation arena. Map all PCI
	// MMIO and RAM identity-wise; Windows replaces these tables itself.
	clear(p.ram[0x1000:0x7000])
	binary.LittleEndian.PutUint64(p.ram[0x1000:], 0x2003)
	for i := uint64(0); i < 4; i++ {
		binary.LittleEndian.PutUint64(p.ram[0x2000+i*8:], 0x3003+i*4096)
		for j := uint64(0); j < 512; j++ {
			binary.LittleEndian.PutUint64(p.ram[0x3000+i*4096+j*8:], (i*512+j)*(2<<20)|0x83)
		}
	}
	binary.LittleEndian.PutUint64(p.ram[0x9008:], 0x00af9b000000ffff)
	binary.LittleEndian.PutUint64(p.ram[0x9010:], 0x00cf93000000ffff)
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return err
	}
	seg := x86state.Segment{Limit: 0xffffffff, Selector: 16, Present: 1, S: 1, Type: 3, Db: 1, G: 1}
	s.Cs, s.Ds, s.Es, s.Ss, s.Fs, s.Gs = seg, seg, seg, seg, seg, seg
	s.Cs.Selector = 8
	s.Cs.Type = 11
	s.Cs.Db = 0
	s.Cs.L = 1
	s.Cr0 = 0x80000011
	s.Cr3 = 0x1000
	s.Cr4 = 0x620
	s.Efer = 0x500
	s.Gdt = x86state.DescriptorTable{Base: 0x9000, Limit: 23}
	s.Idt = x86state.DescriptorTable{}
	if err = p.cpu.SetSystemRegisters(s); err != nil {
		return err
	}
	rsp := entry.Stack - 40
	binary.LittleEndian.PutUint64(p.ram[rsp:], entry.ReturnAddress)
	return p.cpu.SetRegisters(x86state.Registers{Rip: entry.PC, Rsp: rsp, Rcx: entry.ImageHandle, Rdx: entry.SystemTable, Rflags: 2})
}
func (p *pc) efiCall() error {
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
	p.efiMemory.system = &s
	address, err := p.efiMemory.physical(r.Rip - 2)
	if err != nil {
		return err
	}
	if address == p.efi.Entry().ReturnAddress {
		return fmt.Errorf("EFI image returned %#x", r.Rax)
	}
	name, ok := p.efi.Service(address)
	if !ok {
		return fmt.Errorf("EFI trap outside firmware: %#x", r.Rip)
	}
	p.lastService = "EFI " + name
	args := [10]uint64{r.Rcx, r.Rdx, r.R8, r.R9}
	var extra [48]byte
	if err = p.efiMemory.ReadMemory(r.Rsp+40, extra[:], cpu.Read); err != nil {
		return err
	}
	for i := 4; i < 10; i++ {
		args[i] = binary.LittleEndian.Uint64(extra[(i-4)*8:])
	}
	status, err := p.efi.Call(address, args)
	record := map[string]any{"service": name, "status": fmt.Sprintf("%#x", status), "args": fmt.Sprintf("%#x", args[:6])}
	if name == "OpenProtocol" || name == "HandleProtocol" {
		var raw [16]byte
		if e := p.efiMemory.ReadMemory(args[1], raw[:], cpu.Read); e == nil {
			record["guid"] = guid.Format(raw)
		}
	}
	p.efiTrace = append(p.efiTrace, record)
	if len(p.efiTrace) > 32 {
		p.efiTrace = p.efiTrace[len(p.efiTrace)-32:]
	}
	if err != nil {
		return err
	}
	r.Rax = status
	return p.cpu.SetRegisters(r)
}
