package uefi

import (
	"context"
	"crypto/sha256"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestRewriteGuardsAndInterpreterOverride(t *testing.T) {
	m := machine(t, 0x91000400, 0xd65f03c0) // ADD X0,X0,#1; RET
	entry := m.processor.PC()
	code := make([]byte, 8)
	m.ReadVirtualMemory(entry, code)
	digest := sha256.Sum256(code)
	apply := func(m *Machine) (uint64, error) {
		x, _ := m.Register("x0")
		m.SetRegister("x0", x+1)
		return m.Register("lr")
	}
	if err := m.AddDigestRewrite(entry, 8, digest[:], "increment", apply); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := m.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []RunOptions{{Steps: 1}, {Steps: 1, SampleInterval: 1}, {Steps: 1, DisableAcceleration: true}, {Steps: 1, TraceLimit: 1}, {Steps: 1, StopPCs: []uint64{entry + 4}}, {Steps: 1, Watches: []Watch{{entry, 8, cpu.Execute}}}} {
		m.Restore(checkpoint)
		before, _ := m.Register("x0")
		r := m.RunWithOptions(context.Background(), opts)
		x, _ := m.Register("x0")
		if x != before+1 {
			t.Fatal("incorrect result")
		}
		want := entry + 4
		if !opts.DisableAcceleration && opts.TraceLimit == 0 && len(opts.StopPCs) == 0 && len(opts.Watches) == 0 {
			want = m.returnAddress
		}
		if r.PC != want {
			t.Fatalf("opts=%+v result=%+v", opts, r)
		}
	}
	m.Restore(checkpoint)
	// Changing executable bytes invalidates the match immediately.
	m.WriteVirtualMemory(entry, []byte{0x00, 0x08, 0x00, 0x91}) // ADD X0,X0,#2
	before, _ := m.Register("x0")
	r := m.Run(context.Background(), 1)
	after, _ := m.Register("x0")
	if after != before+2 || r.PC != entry+4 {
		t.Fatal("stale rewrite executed")
	}
	if err := m.AddDigestRewrite(entry, 8, digest[:], "stale", apply); err == nil {
		t.Fatal("stale digest accepted")
	}
}

func TestDeclinedRewriteInterpretsInvocation(t *testing.T) {
	m := machine(t, 0x91000400, 0xd65f03c0)
	entry := m.processor.PC()
	code := make([]byte, 8)
	m.ReadVirtualMemory(entry, code)
	if err := m.AddRewrite(Rewrite{entry, "decline", code, func(*Machine) (uint64, error) { return 0, ErrDecline }}); err != nil {
		t.Fatal(err)
	}
	before, _ := m.Register("x0")
	r := m.Run(context.Background(), 1)
	after, _ := m.Register("x0")
	if after != before+1 || r.PC != entry+4 {
		t.Fatalf("decline result=%+v", r)
	}
}
