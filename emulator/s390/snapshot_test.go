package s390

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/tinyrange/trex/filesystem/ckd"
)

// loopMachine counts in GR2 and storage word 0x800 for GR3 iterations,
// with a DASD and a 3270 attached.
func loopMachine(t *testing.T, base TrackSource) (*Machine, *DASD3390, *Console3270) {
	t.Helper()
	code := []byte{
		0x41, 0x22, 0x00, 0x01, // LA 2,1(2)
		0x50, 0x20, 0x08, 0x00, // ST 2,X'800'
		0x46, 0x30, 0x10, 0x00, // BCT 3,X'1000'
	}
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	c.GR[3] = 200000
	d := NewDASD3390(base, 3)
	if _, err := m.CSS.Attach(0x0a80, d); err != nil {
		t.Fatal(err)
	}
	con := NewConsole3270(24, 80)
	if err := m.CSS.AttachConsole(0x0700, con); err != nil {
		t.Fatal(err)
	}
	return m, d, con
}

// A run checkpointed part way and resumed in a fresh machine ends exactly
// as an uninterrupted run does; device state and disk writes survive.
func TestCheckpointResumesExactly(t *testing.T) {
	ref, _, _ := loopMachine(t, volume())
	if r := ref.Run(10_000_000); r.Kind != "disabled-wait" {
		t.Fatalf("reference run: %v", r)
	}

	m, d, con := loopMachine(t, volume())
	m.Run(250_000)
	d.StartChain()
	d.Exec(0x63, extent(0, 0, 2, 14), true)
	d.Exec(0x47, locate(0x01, 1, 1, 3, 1), true)
	d.Exec(0x85, []byte{9, 9, 9}, false)
	con.Exec(0x05, append([]byte{0xc3}, EncodeEBCDIC("SAVED")...), false)
	var buf bytes.Buffer
	if err := m.Save(&buf); err != nil {
		t.Fatal(err)
	}

	n, nd, ncon := loopMachine(t, volume())
	if err := n.Restore(bytes.NewReader(buf.Bytes()), false); err != nil {
		t.Fatal(err)
	}
	if r := n.Run(10_000_000); r.Kind != "disabled-wait" {
		t.Fatalf("resumed run: %v", r)
	}
	rc, nc := ref.CPUs[0], n.CPUs[0]
	if nc.GR != rc.GR || nc.PSW != rc.PSW || n.TOD() != ref.TOD() || nc.Instructions != rc.Instructions {
		t.Fatalf("resumed GR2 %d TOD %X instr %d, reference GR2 %d TOD %X instr %d",
			nc.GR[2], n.TOD(), nc.Instructions, rc.GR[2], ref.TOD(), rc.Instructions)
	}
	if !bytes.Equal(n.S.Mem, ref.S.Mem) {
		t.Fatal("storage differs from the uninterrupted run")
	}
	if r, _ := nd.ReadTrack(18); string(r[1].Data) != "\x09\x09\x09" {
		t.Fatal("disk write lost")
	}
	if !strings.HasPrefix(ncon.Screen().Text, "SAVED") {
		t.Fatal("3270 screen lost")
	}

	// disks_only: a fresh machine keeps only the written tracks.
	f, fd, fcon := loopMachine(t, volume())
	if err := f.Restore(bytes.NewReader(buf.Bytes()), true); err != nil {
		t.Fatal(err)
	}
	if r, _ := fd.ReadTrack(18); string(r[1].Data) != "\x09\x09\x09" {
		t.Fatal("disks-only restore lost the write")
	}
	if f.CPUs[0].GR[2] != 0 || strings.TrimSpace(fcon.Screen().Text) != "" {
		t.Fatal("disks-only restore changed more than disks")
	}
}

func TestCheckpointRejectsDifferentMachines(t *testing.T) {
	m, _, _ := loopMachine(t, volume())
	var buf bytes.Buffer
	if err := m.Save(&buf); err != nil {
		t.Fatal(err)
	}
	other := volume()
	other[0][1] = ckd.Record{Number: 1, Data: []byte("OTHER")}
	n, _, _ := loopMachine(t, other)
	if err := n.Restore(bytes.NewReader(buf.Bytes()), false); err == nil || !strings.Contains(err.Error(), "different volume") {
		t.Fatalf("different media: %v", err)
	}
	p, _, _ := loopMachine(t, volume())
	p.CSS.AttachConsole(0x0701, NewConsole3270(24, 80))
	if err := p.Restore(bytes.NewReader(buf.Bytes()), false); err == nil {
		t.Fatal("restored into a machine with another device")
	}
	if err := p.Restore(strings.NewReader("not a checkpoint"), false); err == nil {
		t.Fatal("accepted garbage")
	}
}

// sieMachine runs a guest counting loop under SIE that ends with an
// intercepted DIAGNOSE.
func sieMachine(t *testing.T) *Machine {
	t.Helper()
	m, c := newTest(t, append([]byte{0xb2, 0x14, 0x40, 0x00}, stop()...)) // SIE 0(4)
	setupStop(m)
	be.PutUint32(m.S.Mem[0x10000:], 0x00011000|0x0f)
	for i := 1; i < 16; i++ {
		be.PutUint32(m.S.Mem[0x10000+4*i:], 0x20)
	}
	for i := 0; i < 256; i++ {
		be.PutUint32(m.S.Mem[0x11000+4*i:], 0x400)
	}
	be.PutUint32(m.S.Mem[0x11000:], 0x00020000)
	be.PutUint32(m.S.Mem[0x11004:], 0x00021000)
	c.CR[0], c.CR[1] = 0x00b00000, 0x00010000
	// Guest: LA 2,1(2); BCTR 3,5; DIAG.
	copy(m.S.Mem[0x21100:], []byte{0x41, 0x22, 0x00, 0x01, 0x06, 0x35, 0x83, 0x00, 0x00, 0x08})
	c.GR[3], c.GR[5] = 50000, 0x1100
	sd := uint32(0x4000)
	c.GR[4] = sd
	m.S.Mem[sd+3] = 0x20
	be.PutUint16(m.S.Mem[sd+10:], 0)
	be.PutUint64(m.S.Mem[sd+0x18:], 0x00080000_80001100)
	be.PutUint32(m.S.Mem[sd+0x80:], 0x000000e0)
	be.PutUint32(m.S.Mem[sd+0x80+14*4:], 0xc2000000)
	return m
}

// A checkpoint taken while a CPU is in interpretive execution resumes the
// guest exactly where it was.
func TestCheckpointDuringInterpretiveExecution(t *testing.T) {
	ref := sieMachine(t)
	if r := ref.Run(10_000_000); r.Kind != "disabled-wait" {
		t.Fatalf("reference run: %v", r)
	}
	m := sieMachine(t)
	m.Run(40_000)
	if m.CPUs[0].sie == nil {
		t.Fatal("the checkpoint is not taken inside SIE")
	}
	var buf bytes.Buffer
	if err := m.Save(&buf); err != nil {
		t.Fatal(err)
	}
	n := sieMachine(t)
	if err := n.Restore(bytes.NewReader(buf.Bytes()), false); err != nil {
		t.Fatal(err)
	}
	if r := n.Run(10_000_000); r.Kind != "disabled-wait" {
		t.Fatalf("resumed run: %v", r)
	}
	if n.CPUs[0].GR != ref.CPUs[0].GR || n.CPUs[0].PSW != ref.CPUs[0].PSW || !bytes.Equal(n.S.Mem, ref.S.Mem) {
		diff := []string{}
		for i := range n.S.Mem {
			if n.S.Mem[i] != ref.S.Mem[i] && len(diff) < 8 {
				diff = append(diff, fmt.Sprintf("%X:%02X/%02X", i, n.S.Mem[i], ref.S.Mem[i]))
			}
		}
		t.Fatalf("TOD %X/%X instr %d/%d timer %X/%X; storage differs %v", n.TOD(), ref.TOD(), n.CPUs[0].Instructions, ref.CPUs[0].Instructions, n.CPUs[0].cpuTimer(), ref.CPUs[0].cpuTimer(), diff)
	}
	if n.S.Mem[0x4000+0x50] != sieCodeInst || n.CPUs[0].GR[2] != 50000 {
		t.Fatalf("interception %d, guest count %d", n.S.Mem[0x4000+0x50], n.CPUs[0].GR[2])
	}
}

// A disks-only restore carries written tracks into a machine that has
// gained a device since the checkpoint, such as a network adapter.
func TestDisksOnlyRestoreToleratesNewDevices(t *testing.T) {
	m, d, _ := loopMachine(t, volume())
	d.StartChain()
	d.Exec(0x63, extent(0, 0, 2, 14), true)
	d.Exec(0x47, locate(0x01, 1, 1, 3, 1), true)
	d.Exec(0x85, []byte{7, 7, 7}, false)
	var buf bytes.Buffer
	if err := m.Save(&buf); err != nil {
		t.Fatal(err)
	}
	n, nd, _ := loopMachine(t, volume())
	if _, err := n.CSS.AttachCTCI(0x0e20); err != nil {
		t.Fatal(err)
	}
	if err := n.Restore(bytes.NewReader(buf.Bytes()), false); err == nil {
		t.Fatal("a full restore accepted a machine with another device")
	}
	if err := n.Restore(bytes.NewReader(buf.Bytes()), true); err != nil {
		t.Fatal(err)
	}
	if r, _ := nd.ReadTrack(18); string(r[1].Data) != "\x07\x07\x07" {
		t.Fatal("disk write lost")
	}
	if n.TOD() <= m.TOD() {
		t.Fatalf("the clock went back to %X from the saved %X", n.TOD(), m.TOD())
	}
}
