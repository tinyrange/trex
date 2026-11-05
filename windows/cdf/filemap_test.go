package cdf

import (
	"encoding/binary"
	"testing"
)

func TestNativeRootFileMap(t *testing.T) {
	d, e := Parse(nativeRoot(t))
	if e != nil {
		t.Fatal(e)
	}
	m, e := d.FileMap()
	if e != nil {
		t.Fatal(e)
	}
	if m.Path != "" || m.RootSelector != 2 || len(m.Entries) != 1 || len(m.Identities) != 1 {
		t.Fatalf("wrong root map %+v", m)
	}
	f := m.Entries[0]
	if f.Name != "." || f.DisplayName != "." || f.Flags != 0 || f.Identity != 0 {
		t.Fatalf("wrong root record %+v", f)
	}
	attrs := m.Identities[0]
	if len(attrs) != 5 || attrs[0] != (IdentityAttribute{"", "Name", "Microsoft-Windows-MinWin-Security"}) || attrs[1].Value != "10.0.26100.1" {
		t.Fatalf("wrong identity %+v", attrs)
	}
}

func TestRejectUnsupportedFileMaps(t *testing.T) {
	cases := map[string]func(*Document){
		"format":          func(d *Document) { d.Format[0] ^= 1 },
		"hash":            func(d *Document) { d.Blobs[1].Data[4] ^= 1 },
		"bad string":      func(d *Document) { binary.LittleEndian.PutUint32(d.Blobs[1].Data[8:], 99) },
		"file flags":      func(d *Document) { d.Blobs[0].Data[0] = 1 },
		"hash data":       func(d *Document) { binary.LittleEndian.PutUint32(d.Blobs[0].Data[20:], 0) },
		"file identity":   func(d *Document) { binary.LittleEndian.PutUint32(d.Blobs[0].Data[24:], 1) },
		"identity count":  func(d *Document) { binary.LittleEndian.PutUint32(d.Blobs[4].Data, 0xffffffff) },
		"identity string": func(d *Document) { binary.LittleEndian.PutUint32(d.Blobs[4].Data[8:], 99) },
		"root selector":   func(d *Document) { binary.LittleEndian.PutUint32(d.Blobs[2].Data[4:], 3) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d, e := Parse(nativeRoot(t))
			if e != nil {
				t.Fatal(e)
			}
			mutate(d)
			if _, e := d.FileMap(); e == nil {
				t.Fatal("accepted invalid or unsupported schema")
			}
		})
	}
}
