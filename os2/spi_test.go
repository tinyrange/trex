package os2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func spiResource(class, name, dll string, kind uint16, n int) []byte {
	b := []byte(class + "\x00" + name + "\x00")
	b = binary.LittleEndian.AppendUint16(b, kind)
	b = append(b, []byte(dll+"\x00")...)
	b = binary.LittleEndian.AppendUint16(b, uint16(n))
	for i := 0; i < n; i++ {
		p := make([]byte, 72)
		binary.LittleEndian.PutUint32(p, 72)
		binary.LittleEndian.PutUint32(p[4:], uint32(i+1))
		b = append(b, p...)
	}
	return b
}
func profileValue(b []byte, appName, keyName string) []byte {
	le := binary.LittleEndian
	for app := le.Uint32(b[4:]); app != 0; app = le.Uint32(b[app:]) {
		n := le.Uint16(b[app+12:])
		off := le.Uint32(b[app+16:])
		if string(b[off:off+uint32(n)-1]) != appName {
			continue
		}
		for key := le.Uint32(b[app+4:]); key != 0; key = le.Uint32(b[key:]) {
			n := le.Uint16(b[key+8:])
			off := le.Uint32(b[key+12:])
			if string(b[off:off+uint32(n)-1]) != keyName {
				continue
			}
			n = le.Uint16(b[key+16:])
			off = le.Uint32(b[key+20:])
			return b[off : off+uint32(n)]
		}
	}
	return nil
}
func TestStreamProfileGroupsAndProtocols(t *testing.T) {
	r := map[uint16][]byte{1: {3, 0}, 2: spiResource("FILESYS", "FSSH", "FSSH", 0, 1), 3: spiResource("FILESYS", "CDSH", "CDSH", 0, 2), 4: spiResource("AUDIOSYS", "AUDIOSH$", "AUDIOSH", 1, 2)}
	b, e := streamProfileResources(r)
	if e != nil {
		t.Fatal(e)
	}
	g := profileValue(b, "SHNAME", "GLOBAL")
	if !bytes.Equal(g, []byte("\x02\x00FILESYS\x00\x00AUDIOSYS\x00")) {
		t.Fatalf("global %q", g)
	}
	f := profileValue(b, "SHCLASS", "FILESYS")
	if len(f) != 2+273*2+72*3 || binary.LittleEndian.Uint16(f) != 2 || string(f[2:6]) != "FSSH" || binary.LittleEndian.Uint16(f[273:]) != 1 || string(f[347:351]) != "CDSH" {
		t.Fatalf("bad file handler layout: %x", f)
	}
	a := profileValue(b, "SHCLASS", "AUDIOSYS")
	if binary.LittleEndian.Uint16(a[11:]) != 1 || binary.LittleEndian.Uint16(a[273:]) != 2 || string(a[13:20]) != "AUDIOSH" || binary.LittleEndian.Uint32(a[275:]) != 72 {
		t.Fatal("PDD/protocol layout")
	}
}
func TestStreamProfileRejectsMalformedResources(t *testing.T) {
	good := spiResource("FILESYS", "FSSH", "FSSH", 0, 1)
	for _, bad := range [][]byte{nil, good[:len(good)-1], append(append([]byte{}, good...), 0), spiResource("TOOLONGCLASS", "FSSH", "FSSH", 0, 1), spiResource("FILESYS", "FSSH", "FSSH", 2, 1)} {
		if _, e := streamProfileResources(map[uint16][]byte{1: {1, 0}, 2: bad}); e == nil {
			t.Fatalf("accepted malformed resource %x", bad)
		}
	}
	if _, e := streamProfileResources(map[uint16][]byte{1: {2, 0}, 2: good, 3: good}); e == nil {
		t.Fatal("duplicate handler accepted")
	}
	if _, e := streamProfileResources(map[uint16][]byte{1: {255, 255}}); e == nil {
		t.Fatal("unbounded count accepted")
	}
}
