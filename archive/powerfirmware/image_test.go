package powerfirmware

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func fixture() []byte {
	b := make([]byte, 416)
	be := binary.BigEndian
	copy(b, "UI\x00\x03")
	be.PutUint32(b[4:], uint32(len(b)))
	be.PutUint16(b[12:], 128)
	be.PutUint16(b[14:], 2)
	for i := 0; i < 2; i++ {
		at := 160 + i*128
		r := b[128+i*16:]
		be.PutUint32(r, uint32(0x80a00701+i))
		be.PutUint32(r[4:], 128)
		be.PutUint32(r[8:], uint32(at))
		be.PutUint32(r[12:], uint32(0x12345678+i))
		h := b[at:]
		copy(h, "\x02\x22\x00\x03")
		copy(h[4:8], r[:4])
		copy(h[16:20], r[12:16])
		be.PutUint32(h[20:], uint32(20-i*16))
		be.PutUint32(h[24:], uint32(108+i*16))
		copy(h[108+i*16:], "data")
	}
	return b
}

func TestViewsAndExtendedHeader(t *testing.T) {
	source := &starfile.Bytes{Data: fixture()}
	image, err := Open(source, 2, 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(image.Entries) != 2 || image.Entries[1].Header.Size() != 124 || image.Entries[1].Payload.Size() != 4 {
		t.Fatal(image)
	}
	b, err := starfile.ReadAll(image.Entries[1].Payload)
	if err != nil || string(b) != "data" {
		t.Fatal(b, err)
	}
	// Borrowed readers preserve bytes and do not materialize payloads.
	source.Data[412] = 'D'
	b, _ = starfile.ReadAll(image.Entries[1].Payload)
	if string(b) != "Data" {
		t.Fatal(b)
	}
	r, err := auto.Identify(source, auto.Options{})
	if err != nil || r.Format != "power_firmware" {
		t.Fatal(r, err)
	}
}

func TestMarkerMIKeyword(t *testing.T) {
	payload := make([]byte, 40)
	binary.BigEndian.PutUint32(payload, 1)
	binary.BigEndian.PutUint32(payload[4:], 16)
	binary.BigEndian.PutUint32(payload[16:], 9)
	copy(payload[20:], "FW000_001padding")
	source := &starfile.Bytes{Data: payload}
	field, err := MIKeyword(source)
	if err != nil {
		t.Fatal(err)
	}
	b, err := starfile.ReadAll(field)
	if err != nil || string(b) != "FW000_001" {
		t.Fatal(b, err)
	}
	for _, tc := range []struct{ version, offset, size uint32 }{{2, 16, 9}, {1, 8, 9}, {1, 38, 9}, {1, 16, 0}, {1, 16, 21}} {
		binary.BigEndian.PutUint32(payload, tc.version)
		binary.BigEndian.PutUint32(payload[4:], tc.offset)
		binary.BigEndian.PutUint32(payload[16:], tc.size)
		if _, err := MIKeyword(source); err == nil {
			t.Fatal("accepted invalid marker", tc)
		}
	}
}

func TestMalformedAndBudgets(t *testing.T) {
	be := binary.BigEndian
	for name, mutate := range map[string]func([]byte){
		"size":                  func(b []byte) { b[7]-- },
		"version":               func(b []byte) { b[3] = 4 },
		"directory":             func(b []byte) { be.PutUint16(b[12:], 127) },
		"count":                 func(b []byte) { be.PutUint16(b[14:], 65535) },
		"duplicate":             func(b []byte) { copy(b[144:148], b[128:132]) },
		"overlap":               func(b []byte) { be.PutUint32(b[152:], 160) },
		"outside":               func(b []byte) { be.PutUint32(b[136:], 0xffffffff) },
		"length":                func(b []byte) { be.PutUint32(b[132:], 0xffffffff) },
		"header overlap":        func(b []byte) { be.PutUint32(b[136:], 128) },
		"lid magic":             func(b []byte) { b[160] = 0 },
		"lid id":                func(b []byte) { b[167]++ },
		"lid checksum mismatch": func(b []byte) { b[176]++ },
		"lid header short":      func(b []byte) { be.PutUint32(b[184:], 107) },
		"lid header outside":    func(b []byte) { be.PutUint32(b[184:], 129) },
		"lid payload":           func(b []byte) { b[183]++ },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 2, 256); err == nil {
				t.Fatal("accepted malformed image")
			}
		})
	}
	s := &starfile.Bytes{Data: fixture()}
	for _, v := range [][2]int{{1, 256}, {2, 255}, {0, 0}, {2, -1}} {
		if _, err := Open(s, v[0], int64(v[1])); err == nil {
			t.Fatal("ignored budget", v)
		}
	}
	for _, n := range []int{0, 127, 159, 200, 415} {
		if _, err := Open(&starfile.Bytes{Data: fixture()[:n]}, 2, 256); err == nil {
			t.Fatal("accepted truncation", n)
		}
	}
}

func TestOverlappingIndividuallyValidLIDs(t *testing.T) {
	b := fixture()
	// Extend the first payload into the second LID's intact header. Both
	// records remain independently valid and bounded, but their extents overlap.
	binary.BigEndian.PutUint32(b[132:], 160)
	binary.BigEndian.PutUint32(b[180:], 52)
	s := &starfile.Bytes{Data: b}
	if _, err := OpenLID(io.NewSectionReader(s, 160, 160)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLID(io.NewSectionReader(s, 288, 128)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s, 2, 512); err == nil {
		t.Fatal("accepted overlapping valid records")
	}
}
