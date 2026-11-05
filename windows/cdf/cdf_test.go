package cdf

import (
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

// Native _0000000000000000.cdf-ms from Windows 11 26300.9457 image 6.
// Its overlapping zero-length string payload is intentional, not corruption.
const nativeRootHex = "50636d480100000000000000d3baf0b68ff0b50f11000000880000000c0000005400000000000000000000000100000084000000000000000000000003000000ffffffffff1b352825d55541acb06e7c64c725d80e0000000500000009000000070000000f0000000c0000001000000006000000080000000d0000000a0000000b000000040000001c0000014001000010000006c001000008000001d0010000140000095c01000040000004e8010000000000021001000010000002300100002100000280010000150000021001000004000002700100000c0000027401000006000002280100000c000002a401000005000002d8010000010000022802000007000002e00100000e000002b001000050726f636573736f724172636869746563747572650000004e6f6e53785300003331626633383536616433363465333500000000000000000000000000000000ffffffffffffffff0000000000020000000000000100000001000000020000004e616d6556657273696f6e53636f70654d6963726f736f66742d57696e646f77732d4d696e57696e2d536563757269747900000031302e302e32363130302e315075626c69634b6579546f6b656e000001010000027dffff00000000000000000100000002000000616d64363400000056657273696f6e0005000000ffffffff0200000003000000ffffffff0400000005000000ffffffff0600000007000000ffffffff0800000009000000ffffffff0a0000000b0000002e000000"

func nativeRoot(t *testing.T) []byte {
	t.Helper()
	b, e := hex.DecodeString(nativeRootHex)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestNativeRoot(t *testing.T) {
	b := nativeRoot(t)
	if got := Hash(b); got != 0x0fb5f08fb6f0bad3 {
		t.Fatalf("native checksum %#x", got)
	}
	d, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Blobs) != 17 || len(d.Strings) != 12 || !reflect.DeepEqual(d.Identities, []uint32{4}) || d.Root != 3 || d.AuxiliaryRoot != NoBlob {
		t.Fatalf("unexpected indexes: %+v", d)
	}
	if d.Blobs[7].Kind != 2 || string(d.Blobs[7].Data) != "Microsoft-Windows-MinWin-Security" {
		t.Fatalf("identity string bytes %q", d.Blobs[7].Data)
	}
	if len(d.Blobs[5].Data) != 0 || d.Blobs[5].Kind != 2 {
		t.Fatal("empty native string lost")
	}
	want := []uint32{14, 5, 9, 7, 15, 12, 16, 6, 8, 13, 10, 11}
	if !reflect.DeepEqual(d.Strings, want) {
		t.Fatalf("string IDs %v", d.Strings)
	}
	encoded, e := d.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	again, e := Parse(encoded)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(d, again) {
		t.Fatal("serialization changed logical indexes/payloads")
	}
	// Parsing must not retain aliases into the input buffer.
	b[384] = 'X'
	if d.Blobs[7].Data[0] != 'M' {
		t.Fatal("input mutation changed parsed payload")
	}
}

func TestMalformedNativeRoot(t *testing.T) {
	cases := map[string]func([]byte){
		"magic":                   func(b []byte) { b[0] = 'X' },
		"version":                 func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 2) },
		"flags":                   func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 4) },
		"blob count overflow":     func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 0xffffffff) },
		"blob offset overflow":    func(b []byte) { binary.LittleEndian.PutUint32(b[24:], 0xfffffff0) },
		"payload offset overflow": func(b []byte) { binary.LittleEndian.PutUint32(b[140:], 0xffffffff) },
		"payload length overflow": func(b []byte) { binary.LittleEndian.PutUint32(b[136:], 0x01ffffff) },
		"index into header":       func(b []byte) { binary.LittleEndian.PutUint32(b[32:], 4) },
		"missing string blob":     func(b []byte) { binary.LittleEndian.PutUint32(b[84:], 17) },
		"missing root blob":       func(b []byte) { binary.LittleEndian.PutUint32(b[60:], 17) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := nativeRoot(t)
			change(b)
			// Rehash structural corruptions so rejection is not merely checksum failure.
			binary.LittleEndian.PutUint64(b[12:], Hash(b))
			if _, e := Parse(b); e == nil {
				t.Fatal("accepted corrupt container")
			}
		})
	}
	b := nativeRoot(t)
	b[len(b)-1] ^= 1
	if _, e := Parse(b); e == nil {
		t.Fatal("accepted bad checksum")
	}
	// The last payload ends at 553; the native hash also accepts this final
	// single-byte dot without the three zero alignment bytes. Do not invent
	// a padding requirement the container framing does not express.
	for n := 0; n < 553; n++ {
		if _, e := Parse(b[:n]); e == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}

func TestInlineGUIDsAndAppIDs(t *testing.T) {
	// All index families are represented, with an opaque kind to ensure container
	// serialization does not silently discard data it does not semantically parse.
	d := &Document{Flags: 3, Root: NoBlob, AuxiliaryRoot: NoBlob,
		Blobs:   []Blob{{Kind: 0xfe, Data: []byte{7, 8, 9}}},
		Strings: []uint32{0}, Identities: []uint32{0}, AppIDs: []uint32{0},
		GUIDs: [][16]byte{{1, 2, 3}, {4, 5, 6}}}
	b, e := d.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	got, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(d, got) {
		t.Fatalf("lost indexes: %+v", got)
	}
	d.AppIDs[0] = 1
	if _, e = d.Marshal(); e == nil {
		t.Fatal("accepted out-of-range AppID")
	}
}

func FuzzParse(f *testing.F) {
	b, _ := hex.DecodeString(nativeRootHex)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		d, e := Parse(b)
		if e != nil {
			return
		}
		out, e := d.Marshal()
		if e != nil {
			return
		} // Expanded aligned representation may exceed limit.
		got, e := Parse(out)
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(d, got) {
			t.Fatal("changed logical representation")
		}
	})
}
