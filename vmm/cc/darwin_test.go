package cc

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
	"hash/crc32"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

type darwinTestSource struct{ *bytes.Reader }

func (s darwinTestSource) Size() int64 { return s.Reader.Size() }

type darwinTestCPU struct {
	hypervisor.X86
	regs x86state.Registers
	sys  x86state.SystemRegisters
}

func (c *darwinTestCPU) TSCFrequency() (uint64, error)                       { return 2400000000, nil }
func (c *darwinTestCPU) ReadMSR(uint32) (uint64, error)                      { return 12 << 40, nil }
func (c *darwinTestCPU) SystemRegisters() (x86state.SystemRegisters, error)  { return c.sys, nil }
func (c *darwinTestCPU) SetSystemRegisters(s x86state.SystemRegisters) error { c.sys = s; return nil }
func (c *darwinTestCPU) SetRegisters(r x86state.Registers) error             { c.regs = r; return nil }
func darwinKernel(base uint64) storage.Reader {
	b := make([]byte, 4096)
	p := binary.LittleEndian.PutUint32
	q := binary.LittleEndian.PutUint64
	p(b, 0xfeedfacf)
	p(b[4:], 0x01000007)
	p(b[12:], 2)
	p(b[16:], 2)
	p(b[20:], 256)
	c := b[32:]
	p(c, 0x19)
	p(c[4:], 72)
	copy(c[8:], "__TEXT")
	q(c[24:], 0xffffff8000000000+base)
	q(c[32:], 8192)
	q(c[48:], 4096)
	c = b[104:]
	p(c, 5)
	p(c[4:], 184)
	p(c[8:], 4)
	p(c[12:], 42)
	q(c[144:], base+512)
	return darwinTestSource{bytes.NewReader(b)}
}
func TestDarwinFirmwareHandoff(t *testing.T) {
	c := &darwinTestCPU{}
	p := &pc{cpu: c, ram: make([]byte, 160<<20), framebuffer: make([]byte, ramfb.Size)}
	if err := p.installDarwin(&vmm.DarwinBoot{Kernel: darwinKernel(0x200000), CommandLine: "-v -s rd=disk0s3"}); err != nil {
		t.Fatal(err)
	}
	a := p.ram[c.regs.Rax : c.regs.Rax+4096]
	u := binary.LittleEndian.Uint32
	q := binary.LittleEndian.Uint64
	if c.regs.Rip != 0x200200 || c.regs.Rflags != 2 || c.sys.Cr0 != 0x11 || c.sys.Cr3 != 0 || c.sys.Efer != 0 || c.sys.Cs.Db != 1 || c.sys.Cs.Selector != 8 {
		t.Fatal("XNU must enter original protected-mode pstart, not a loader")
	}
	if u(a[1048:]) != (ramfb.Address+ramfb.Pixels)|1 || u(a[1052:]) != 2 {
		t.Fatal("physical text console flags lost")
	}
	mm := p.ram[u(a[1032:]) : u(a[1032:])+u(a[1036:])]
	if u(mm[40:]) != 7 || q(mm[48:]) != 0x1000 || q(mm[64:]) != 0x9f {
		t.Fatal("first usable region must be bounded conventional low memory")
	}
	system := uint64(u(a[1104:]))
	runtime := q(p.ram[system+88:])
	if runtime>>32 != 0xffffff80 || q(a[1096:])<<12 != runtime&^0xfff {
		t.Fatal("EFI runtime pointers must be XNU high virtual addresses")
	}
	for _, addr := range []uint64{system, runtime & 0xffffffff} {
		n := uint64(u(p.ram[addr+12:]))
		header := bytes.Clone(p.ram[addr : addr+n])
		sum := u(header[16:])
		clear(header[16:20])
		if crc32.ChecksumIEEE(header) != sum {
			t.Fatal("EFI header CRC invalid")
		}
	}
	dt := p.ram[u(a[1072:]) : u(a[1072:])+u(a[1076:])]
	if !bytes.Contains(dt, []byte("8868E871-E4F1-11D3-BC22-0080C73C8881")) || bytes.Contains(dt, []byte("ACPI_20")) {
		t.Fatal("original AppleACPIPlatform GUID path absent")
	}
	if q(a[1152:]) != 200000000 {
		t.Fatal("FSB frequency not derived from guest TSC and ratio")
	}
}
func TestDarwinRejectsBootstrapOverflowBeforeWrites(t *testing.T) {
	c := &darwinTestCPU{}
	p := &pc{cpu: c, ram: bytes.Repeat([]byte{0xcc}, 2<<20)}
	before := bytes.Clone(p.ram)
	for _, base := range []uint64{0x200000, 0x3ffff000, 0xfffff000} {
		if p.installDarwin(&vmm.DarwinBoot{Kernel: darwinKernel(base)}) == nil || !bytes.Equal(p.ram, before) {
			t.Fatal("unsafe handoff modified RAM")
		}
	}
}
