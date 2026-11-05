package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSecurityDescriptorParts(t *testing.T) {
	data, err := CompileSDDL("O:SYG:SYD:(A;;FA;;;SY)S:(ML;OIIO;0x1;;;LW)")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseSecurityDescriptorParts(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Owner, p.Group) || p.SACL == nil || p.DACL == nil || p.Control != 0x8014 {
		t.Fatalf("parts: %+v", p)
	}
	_, entries, err := ParseACL(p.SACL)
	if err != nil || len(entries) != 1 || entries[0].Type != 17 {
		t.Fatalf("label lost: %v %v", entries, err)
	}
	for i := 0; i < len(data); i++ {
		if _, err := ParseSecurityDescriptorParts(data[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	for name, change := range map[string]func([]byte){
		"unaligned":        func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 21) },
		"overlap":          func(b []byte) { binary.LittleEndian.PutUint32(b[8:], binary.LittleEndian.Uint32(b[4:])+4) },
		"missing presence": func(b []byte) { binary.LittleEndian.PutUint16(b[2:], 0x8010) },
		"bad ace count": func(b []byte) {
			start := binary.LittleEndian.Uint32(b[16:])
			binary.LittleEndian.PutUint16(b[start+4:], 65535)
		},
		"bad sid revision": func(b []byte) { b[binary.LittleEndian.Uint32(b[4:])] = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(data)
			change(b)
			if _, err := ParseSecurityDescriptorParts(b); err == nil {
				t.Fatal("accepted malformed components")
			}
		})
	}
	alias := bytes.Clone(data)
	binary.LittleEndian.PutUint32(alias[8:], binary.LittleEndian.Uint32(alias[4:]))
	if _, err := ParseSecurityDescriptorParts(alias); err != nil {
		t.Fatalf("exact SID alias: %v", err)
	}
	for _, text := range []string{"O:SYG:SY", "O:SYG:SYD:NO_ACCESS_CONTROL", "O:SYG:SYD:"} {
		raw, err := CompileSDDL(text)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParseSecurityDescriptorParts(raw)
		if err != nil {
			t.Fatal(err)
		}
		switch text {
		case "O:SYG:SY":
			if p.Control&4 != 0 || p.DACL != nil {
				t.Fatal("absent ACL lost")
			}
		case "O:SYG:SYD:NO_ACCESS_CONTROL":
			if p.Control&4 == 0 || p.DACL != nil {
				t.Fatal("NULL ACL lost")
			}
		default:
			if p.Control&4 == 0 || len(p.DACL) != 8 {
				t.Fatal("empty ACL lost")
			}
		}
	}
}
