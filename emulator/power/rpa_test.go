package power

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/tinyrange/trex/block"
)

type rpaTestOptical []byte

func (d rpaTestOptical) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(d)) {
		return 0, io.EOF
	}
	n := copy(p, d[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (d rpaTestOptical) Geometry() block.Geometry {
	return block.Geometry{Size: int64(len(d)), LogicalBlockSize: 2048}
}
func (d rpaTestOptical) Capabilities() block.Capabilities { return block.Capabilities{} }

func TestRPAOpticalReplacementPreservesSessionAndCheckpoint(t *testing.T) {
	m := NewMachine(Config{Memory: 0x10000})
	if err := m.CreateTCETable(1, 16); err != nil {
		t.Fatal(err)
	}
	for page := uint64(0); page < 16; page++ {
		if err := m.WriteTCE(1, page, page<<12|0x801); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.RegisterCRQ(3, 1, 0x2000, 4096); err != nil {
		t.Fatal(err)
	}
	first := rpaTestOptical(bytes.Repeat([]byte{1}, 2048))
	second := rpaTestOptical(bytes.Repeat([]byte{2}, 4096))
	if err := m.AttachCRQOptical(3, first, RPAOpticalConfig{LUN: 0x0001000000000000}); err != nil {
		t.Fatal(err)
	}
	q := m.crqs[3]
	q.rpa.ready, q.rpa.loggedIn = true, true
	q.producer = 16
	q.rpa.optical.Execute(make([]byte, 6))
	checkpoint := m.Checkpoint()
	if err := m.ChangeCRQOpticalMedia(3, second); err != nil {
		t.Fatal(err)
	}
	if !q.rpa.ready || !q.rpa.loggedIn || q.rpa.lun != 0x0001000000000000 || q.producer != 16 {
		t.Fatal("media replacement reset CRQ/SRP session")
	}
	cmd := make([]byte, 256)
	cmd[0] = 2 // SRP TEST UNIT READY, without data descriptors.
	binary.BigEndian.PutUint64(cmd[20:], q.rpa.lun)
	if err := m.WriteReal(0x4000, cmd); err != nil {
		t.Fatal(err)
	}
	m.Mem[0x2010] = 0x80
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err == nil {
		t.Fatal("full reply ring accepted medium-change attention")
	}
	// The rejected transport completion must not acknowledge unit attention.
	r, err := q.rpa.optical.Execute(make([]byte, 6))
	if err != nil || r.Status != 2 || r.Sense[12] != 0x28 {
		t.Fatal("live target did not report change", err)
	}
	if err := m.Restore(checkpoint); err != nil {
		t.Fatal(err)
	}
	read := []byte{0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0}
	r, err = m.crqs[3].rpa.optical.Execute(read)
	if err != nil || !bytes.Equal(r.Data, first) {
		t.Fatal("checkpoint did not retain old immutable medium", err)
	}
	if m.ChangeCRQOpticalMedia(4, second) == nil || m.ChangeCRQOpticalMedia(3, nil) == nil {
		t.Fatal("invalid media change accepted")
	}
}

func TestRPAManagementLoginAndAtomicFaults(t *testing.T) {
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
	disc := make(rpaTestOptical, 2048)
	copy(disc, "optical bytes")
	must(m.AttachCRQOptical(3, disc, RPAOpticalConfig{LUN: 0x8000000000000000, UnsupportedMADs: []uint64{3<<32 | 0x8001}}))
	run := func(high, low uint64) {
		t.Helper()
		posted, err := m.ProcessCRQ(3, high, low)
		must(err)
		if !posted {
			t.Fatal("no reply")
		}
	}
	run(0xc001000000000000, 0)
	if !bytes.Equal(m.Mem[0x2000:0x2010], []byte{0xc0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatal("initialization reply")
	}
	mad := func(typ uint32, length uint16, tag uint64) []byte {
		b := make([]byte, 32)
		binary.BigEndian.PutUint32(b, typ)
		binary.BigEndian.PutUint16(b[6:8], length)
		binary.BigEndian.PutUint64(b[8:16], tag)
		binary.BigEndian.PutUint64(b[16:24], 0x5000)
		return b
	}
	checkReply := func(format byte, length uint16, tag uint64) {
		t.Helper()
		a := 0x2000 + (m.crqs[3].producer+4096-16)%4096
		b := m.Mem[a : a+16]
		if b[0] != 0x80 || b[1] != format || binary.BigEndian.Uint16(b[6:8]) != length || binary.BigEndian.Uint64(b[8:16]) != tag {
			t.Fatalf("CRQ reply %x", b)
		}
	}
	must(m.WriteReal(0x4000, mad(8, 16, 0x123)))
	run(0x8002000000000020, 0x4000)
	checkReply(2, 16, 0x123)
	if binary.BigEndian.Uint16(m.Mem[0x4004:0x4006]) != 0xf1 {
		t.Fatal("fast-fail not explicitly declined")
	}
	caps := make([]byte, 100)
	binary.BigEndian.PutUint32(caps, 4)
	for at := 68; at < 100; at += 8 {
		binary.BigEndian.PutUint32(caps[at:], uint32((at-68)/8+4))
		binary.BigEndian.PutUint16(caps[at+4:], 8)
		binary.BigEndian.PutUint16(caps[at+6:], 1)
	}
	must(m.WriteReal(0x5000, caps))
	must(m.WriteReal(0x4000, mad(5, 100, 0x234)))
	run(0x8002000000000020, 0x4000)
	checkReply(2, 24, 0x234)
	for at := 68; at < 100; at += 8 {
		if binary.BigEndian.Uint16(m.Mem[0x5000+at+6:]) != 0 {
			t.Fatal("unsupported optional feature enabled")
		}
	}
	must(m.WriteReal(0x4000, mad(0x8001, 16, 0x345)))
	run(0x8003000000000020, 0x4000)
	checkReply(3, 16, 0x345)
	if binary.BigEndian.Uint16(m.Mem[0x4004:]) != 0xf1 {
		t.Fatal("vendor capability not declined")
	}
	must(m.WriteReal(0x4000, mad(3, 148, 0x456)))
	run(0x8002000000000020, 0x4000)
	checkReply(2, 24, 0x456)
	if string(m.Mem[0x5000:0x5004]) != "16.a" || string(m.Mem[0x5008:0x5012]) != "TinyRangeX" || binary.BigEndian.Uint32(m.Mem[0x5074:]) != 1<<20 {
		t.Fatal("adapter information")
	}
	// Bad external geometry and malformed capability records are rejected
	// before even the MAD status/header or queue producer is changed.
	for _, b := range [][]byte{mad(5, 69, 0x567), mad(9, 16, 0x678)} {
		must(m.WriteReal(0x4000, b))
		before := bytes.Clone(m.Mem)
		pos := m.crqs[3].producer
		if _, err := m.ProcessCRQ(3, 0x8002000000000020, 0x4000); err == nil || !bytes.Equal(before, m.Mem) || m.crqs[3].producer != pos {
			t.Fatal("invalid management request had effects")
		}
	}
	b := mad(3, 148, 0x789)
	binary.BigEndian.PutUint64(b[16:24], 0x1fff0)
	must(m.WriteReal(0x4000, b))
	before := bytes.Clone(m.Mem)
	if _, err := m.ProcessCRQ(3, 0x8002000000000020, 0x4000); err == nil || !bytes.Equal(before, m.Mem) {
		t.Fatal("external DMA fault partially completed")
	}
	login := make([]byte, 256)
	binary.BigEndian.PutUint64(login[8:16], 0x7fffffffffffffff)
	binary.BigEndian.PutUint32(login[16:20], 256)
	binary.BigEndian.PutUint16(login[24:26], 6)
	must(m.WriteReal(0x4000, login))
	cp := m.Checkpoint()
	// An unread reply must not cause the IU to be overwritten either.
	address := uint64(0x2000) + m.crqs[3].producer
	must(m.WriteReal(address, []byte{0x80}))
	before = bytes.Clone(m.Mem)
	if _, err := m.ProcessCRQ(3, 0x8001000000000100, 0x4000); err == nil || !bytes.Equal(before, m.Mem) || m.crqs[3].rpa.loggedIn {
		t.Fatal("full ring partially logged in")
	}
	must(m.Restore(cp))
	run(0x8001000000000100, 0x4000)
	checkReply(1, 52, 0x7fffffffffffffff)
	if m.Mem[0x4000] != 0xc0 || binary.BigEndian.Uint16(m.Mem[0x4018:]) != 6 || !m.crqs[3].rpa.loggedIn {
		t.Fatal("SRP login failed")
	}
	must(m.Restore(cp))
	if m.crqs[3].rpa.loggedIn {
		t.Fatal("endpoint state checkpoint alias")
	}
	actual := make([]byte, 13)
	_, err := m.crqs[3].rpa.media.ReadAt(actual, 0)
	must(err)
	if string(actual) != "optical bytes" {
		t.Fatal("endpoint lost real media")
	}
}
