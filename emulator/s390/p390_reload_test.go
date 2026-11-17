package s390

import (
	"bytes"
	"testing"
)

func TestP390MicrostoreReloadInvalidatesHostCatalogNotArchitecturalStorage(t *testing.T) {
	p := newP390370Test(t)
	c := p.Machine.CPUs[0]
	catalog := p.Aperture[p390Subchannels : p390Subchannels+512*64]
	c.GR[7] = 0x12345678
	c.S.Mem[0x900] = 0x5a
	c.S.Keys[4] = 0xa8
	before := append([]byte(nil), catalog...)
	// The normal CPU-reset ABI must preserve the current managers' pointers.
	p390ServiceTest(t, p, 2)
	if !bytes.Equal(catalog, before) {
		t.Fatal("CPU-only reset changed host catalog")
	}
	// Original AWSMAIN uploads bootstrap/LIC before initializing a replacement
	// monitor. Old OS/2 far pointers cannot be reused by its new processes.
	upload := []byte{0x12, 0x34, 0x56, 0x78}
	if err := p.WriteAperture(0x200000, upload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(catalog, before) {
		t.Fatal("upload destroyed the catalog before monitor initialization")
	}
	loads := p.MonitorLoads
	p390ServiceTest(t, p, 2)
	if p.MonitorLoads != loads+1 || c.GR[7] != 0x12345678 || c.S.Mem[0x900] != 0x5a || c.S.Keys[4] != 0xa8 {
		t.Fatal("new monitor did not preserve architectural data independently of host state")
	}
	want := make([]byte, len(catalog))
	want[0x68] = 0xff // Original SCHIBINI's 64-byte-entry negotiation.
	if !bytes.Equal(catalog, want) || !bytes.Equal(p.Aperture[0x200000:0x200004], upload) {
		t.Fatal("old host catalog survived reload, or original LIC bytes were altered")
	}
	if _, s := p.device370(9); s != nil {
		t.Fatal("device became available before the new original host installed it")
	}
	// Rebinding is owned by the original host; a later CPU reset retains it.
	copy(catalog, before)
	p390ServiceTest(t, p, 2)
	if !bytes.Equal(catalog, before) || p.MonitorLoads != loads+1 {
		t.Fatal("reload leaked into a subsequent CPU-only reset")
	}
}
