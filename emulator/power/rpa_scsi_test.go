package power

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/scsi"
	"testing"
)

func TestSRPReportLunsDescriptorsAndAtomicDMA(t *testing.T) {
	m := NewMachine(Config{Memory: 0x20000})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.CreateTCETable(1, 32))
	for i := uint64(0); i < 32; i++ {
		must(m.WriteTCE(1, i, i<<12|0x801))
	}
	must(m.RegisterCRQ(3, 1, 0x2000, 4096))
	must(m.AttachCRQOptical(3, make(rpaTestOptical, 2048), RPAOpticalConfig{LUN: 0x0001000000000000}))
	m.crqs[3].rpa.ready = true
	m.crqs[3].rpa.loggedIn = true
	cmd := make([]byte, 256)
	cmd[0], cmd[5], cmd[32] = 2, 1, 0xa0
	binary.BigEndian.PutUint32(cmd[38:42], 0xa80)
	descriptor := func(address uint64, n uint32) []byte {
		b := make([]byte, 16)
		binary.BigEndian.PutUint64(b, address)
		binary.BigEndian.PutUint32(b[12:], n)
		return b
	}
	copy(cmd[48:], descriptor(0x6000, 0xa80))
	must(m.WriteReal(0x4000, cmd))
	if ok, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err != nil || !ok {
		t.Fatalf("REPORT LUNS: %v", err)
	}
	if !bytes.Equal(m.Mem[0x6000:0x6010], []byte{0, 0, 0, 8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}) {
		t.Fatal("configured target0/LUN1 inventory")
	}
	if m.Mem[0x4012]&0x20 == 0 || binary.BigEndian.Uint32(m.Mem[0x4018:]) != 0xa80-16 {
		t.Fatal("short transfer residual")
	}
	// An indirect table outside the IU scatters the same16 bytes into two
	// separate pages. Direct descriptor count0 above is a real native input.
	cmd[5], cmd[7] = 2, 0
	copy(cmd[48:], descriptor(0x5000, 32))
	binary.BigEndian.PutUint32(cmd[64:], 16)
	list := append(descriptor(0x7ff9, 7), descriptor(0x9000, 9)...)
	must(m.WriteReal(0x5000, list))
	must(m.WriteReal(0x4000, cmd))
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err != nil {
		t.Fatal(err)
	}
	got := append(bytes.Clone(m.Mem[0x7ff9:0x8000]), m.Mem[0x9000:0x9009]...)
	if !bytes.Equal(got, m.Mem[0x6000:0x6010]) {
		t.Fatal("indirect scatter bytes")
	}
	must(m.WriteReal(0x4000, cmd))
	must(m.WriteTCE(1, 9, 0))
	before := bytes.Clone(m.Mem)
	pos := m.crqs[3].producer
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err == nil || !bytes.Equal(before, m.Mem) || m.crqs[3].producer != pos {
		t.Fatal("second data-page fault partially transferred or replied")
	}
	// Mismatched descriptor total and malformed external table never change
	// either the command IU or destination pages.
	must(m.WriteTCE(1, 9, 0x9801))
	binary.BigEndian.PutUint32(cmd[64:], 15)
	must(m.WriteReal(0x4000, cmd))
	before = bytes.Clone(m.Mem)
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err == nil || !bytes.Equal(before, m.Mem) {
		t.Fatal("malformed indirect descriptor accepted")
	}
	// Discovery's LUN0 query does not make LUN0 an alias of the assigned
	// LUN1 device. Peripheral, flat and PAPR logical encodings agree on1.
	cmd[5], cmd[32], cmd[36] = 1, 0x12, 255
	copy(cmd[48:], descriptor(0x6000, 255))
	for _, wire := range []uint64{0, 0x0001000000000000, 0x4001000000000000, 0x8001000000000000} {
		binary.BigEndian.PutUint64(cmd[20:28], wire)
		must(m.WriteReal(0x4000, cmd))
		if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err != nil {
			t.Fatal(err)
		}
		want := byte(5)
		if wire == 0 {
			want = 0x7f
		}
		if m.Mem[0x6000] != want {
			t.Fatalf("LUN%016x inquiry type=%x, want%x", wire, m.Mem[0x6000], want)
		}
	}
}

func TestSRPDiskDataOutPreflightsCompletion(t *testing.T) {
	m := NewMachine(Config{Memory: 0x20000})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.CreateTCETable(1, 32))
	for i := uint64(0); i < 32; i++ {
		must(m.WriteTCE(1, i, i<<12|0x801))
	}
	must(m.RegisterCRQ(3, 1, 0x2000, 4096))
	base, _ := block.NewZeroDevice(8192, 512)
	disk, _ := blockstar.NewOverlayDevice(base, 8192, 4096)
	must(m.AttachCRQDisk(3, disk, RPAOpticalConfig{LUN: 0x0001000000000000}, scsi.DiskIdentity{}))
	m.crqs[3].rpa.ready = true
	m.crqs[3].rpa.loggedIn = true
	cmd := make([]byte, 256)
	cmd[0] = 2
	cmd[5] = 0x20
	cmd[6] = 2
	cmd[32] = 0x2a
	binary.BigEndian.PutUint64(cmd[20:], 0x0001000000000000)
	binary.BigEndian.PutUint32(cmd[34:], 1)
	binary.BigEndian.PutUint16(cmd[39:], 1)
	desc := func(address uint64, n uint32) []byte {
		b := make([]byte, 16)
		binary.BigEndian.PutUint64(b, address)
		binary.BigEndian.PutUint32(b[12:], n)
		return b
	}
	copy(cmd[48:], desc(0x5000, 32))
	binary.BigEndian.PutUint32(cmd[64:], 512)
	copy(cmd[68:], desc(0x6ff0, 16))
	copy(cmd[84:], desc(0x9000, 496))
	want := bytes.Repeat([]byte{0x96}, 512)
	must(m.WriteReal(0x6ff0, want[:16]))
	must(m.WriteReal(0x9000, want[16:]))
	must(m.WriteReal(0x4000, cmd))
	// A full ring must not commit the already validated SCSI write.
	m.Mem[0x2000] = 0x80
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err == nil {
		t.Fatal("full ring accepted")
	}
	got := make([]byte, 512)
	disk.ReadAt(got, 512)
	if !bytes.Equal(got, make([]byte, 512)) {
		t.Fatal("full ring changed storage")
	}
	m.Mem[0x2000] = 0
	// The command can be read from a read-only DMA page, but its completion
	// cannot be published there. This failure must also leave media unchanged.
	must(m.WriteTCE(1, 4, 0x4800))
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err == nil {
		t.Fatal("read-only completion page accepted")
	}
	disk.ReadAt(got, 512)
	if !bytes.Equal(got, make([]byte, 512)) {
		t.Fatal("reply preflight changed disk")
	}
	must(m.WriteTCE(1, 4, 0x4801))
	// Likewise, a response IU crossing an unmapped page cannot write disk.
	must(m.WriteReal(0x4ff0, cmd))
	must(m.WriteTCE(1, 5, 0))
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4ff0); err == nil {
		t.Fatal("unmapped command accepted")
	}
	disk.ReadAt(got, 512)
	if !bytes.Equal(got, make([]byte, 512)) {
		t.Fatal("bad DMA changed storage")
	}
	must(m.WriteTCE(1, 5, 0x5801))
	must(m.WriteReal(0x4000, cmd))
	if ok, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err != nil || !ok {
		t.Fatal("write failed", err)
	}
	disk.ReadAt(got, 512)
	if !bytes.Equal(got, want) {
		t.Fatal("scatter data-out not written")
	}
	if m.Mem[0x4013] != 0 || m.Mem[0x4012]&8 != 0 {
		t.Fatal("successful write reported residual")
	}
}

func TestRPALUNAddressing(t *testing.T) {
	for _, tc := range []struct {
		wire, address uint64
		valid         bool
	}{
		{0x0001000000000000, 1, true},
		{0x4001000000000000, 1, true},
		{0x8001000000000000, 1, true},
		{0x8325000000000000, 3<<32 | 1<<24 | 5, true},
		{0x8001000000000001, 0, false},
		{0xc001000000000000, 0, false},
		{0x0101000000000000, 0, false},
	} {
		got, ok := rpaLUN(tc.wire)
		if got != tc.address || ok != tc.valid {
			t.Fatalf("%016x = %x/%v, want%x/%v", tc.wire, got, ok, tc.address, tc.valid)
		}
	}
}
