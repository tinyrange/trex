package tome

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func packed(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b := make([]byte, (len(s)+7)/8)
	for i, c := range s {
		if c == '1' {
			b[i/8] |= 0x80 >> uint(i%8)
		} else if c != '0' {
			panic("invalid test bits")
		}
	}
	return b
}
func chunk(bits string) []byte { return append([]byte{0, 1, 0, 0}, packed(bits)...) }
func sample() []byte {
	payload := chunk("00 0 01000001 00 0 00 0 01011010") // AAAAZ
	b := make([]byte, 164+len(payload))
	be := binary.BigEndian
	be.PutUint32(b, 0x6b630001)
	be.PutUint16(b[16:], 1)
	be.PutUint32(b[28:], 1)
	be.PutUint16(b[26:], 1)
	e := b[36:164]
	be.PutUint16(e[4:], 7)
	e[6] = 3
	copy(e[7:], "a/b")
	copy(e[38:], "APPLTEST")
	be.PutUint32(e[60:], 5)
	be.PutUint32(e[64:], 164)
	be.PutUint32(e[68:], uint32(len(payload)))
	be.PutUint32(e[72:], checksum([]byte("AAAAZ")))
	copy(b[164:], payload)
	return b
}
func TestCatalogAndForks(t *testing.T) {
	b := sample()
	// Neither name padding nor the final 36 bytes are reserved-zero fields.
	b[36+30] = 0xff
	b[36+120] = 0xff
	a, err := Open(&starfile.Bytes{Data: b}, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	e := a.Entries[0]
	if e.ID != 7 || e.Path != "/7/a%2Fb" || string(e.Name) != "a/b" || string(e.Type[:]) != "APPL" || e.Resource.Size() != 0 {
		t.Fatalf("%+v", e)
	}
	got, err := starfile.ReadAll(e.Data)
	if err != nil || string(got) != "AAAAZ" {
		t.Fatalf("%q %v", got, err)
	}
	stored, err := starfile.ReadAll(e.StoredData)
	if err != nil || !bytes.Equal(stored, b[164:]) {
		t.Fatal("stored view changed")
	}
}

func resourceSample() []byte {
	b := sample()
	binary.BigEndian.PutUint16(b[16:], 2)
	e := b[36:164]
	clear(e)
	binary.BigEndian.PutUint16(e[4:], 7)
	binary.BigEndian.PutUint16(e[6:], 0xfffe)
	copy(e[8:], "TEST")
	// A resource may have no Pascal name; its signed ID still identifies it.
	binary.BigEndian.PutUint32(e[78:], 5)
	binary.BigEndian.PutUint32(e[82:], 164)
	binary.BigEndian.PutUint32(e[86:], uint32(len(b)-164))
	binary.BigEndian.PutUint32(e[90:], checksum([]byte("AAAAZ")))
	return b
}

func TestResourceCatalog(t *testing.T) {
	b := resourceSample()
	e := b[36:164]
	a, err := Open(&starfile.Bytes{Data: b}, 10, 4096)
	if err != nil {
		t.Fatal(err)
	}
	r := a.Entries[0]
	if a.Kind != 2 || r.ResourceID != -2 || string(r.ResourceType[:]) != "TEST" || r.Path != "/7/54455354/-2" || len(r.Name) != 0 || r.Resource.Size() != 0 {
		t.Fatal("lost resource identity or invented a resource fork")
	}
	got, err := starfile.ReadAll(r.Data)
	if err != nil || string(got) != "AAAAZ" {
		t.Fatalf("%q %v", got, err)
	}
	e[90] ^= 1
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 4096); err == nil {
		t.Fatal("ignored resource checksum")
	}
	for _, kind := range []uint16{0, 3, 65535} {
		b := sample()
		binary.BigEndian.PutUint16(b[16:], kind)
		if _, err := Open(&starfile.Bytes{Data: b}, 10, 4096); err == nil {
			t.Fatal("unknown catalog kind")
		}
	}
}
func TestCatalogRejectsMalformed(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:20] },
		func(b []byte) []byte { b[0] = 0; return b },
		func(b []byte) []byte { b[108] ^= 1; return b },
		func(b []byte) []byte { binary.BigEndian.PutUint16(b[26:], 2); return b },
		func(b []byte) []byte { b[42] = 32; return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[100:], 36); return b },
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[104:], 0); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[112:], 1); return b },
		func(b []byte) []byte { copy(b[112:124], b[96:108]); return b }, // overlapping forks
	} {
		if _, err := Open(&starfile.Bytes{Data: mutate(sample())}, 10, 100); err == nil {
			t.Fatal("accepted malformed catalog")
		}
	}
	for _, limit := range []int64{-1, 4, 7} {
		if _, err := Open(&starfile.Bytes{Data: sample()}, 1, limit); err == nil {
			t.Fatalf("accepted limit %d", limit)
		}
	}
}
func TestChunkHistoryAndCommandBoundary(t *testing.T) {
	// 1040 literal runs of 63 bytes, followed by 17 bytes: a complete literal
	// command crosses the nominal 65536-byte block boundary by one byte.
	first := strings.Repeat("00"+"11111"+"11111"+strings.Repeat("01000001", 63), 1040)
	first += "00" + "11110" + "0001" + strings.Repeat("01000001", 17)
	input := append(chunk(first), chunk("01 0 00000000000")...) // length3, distance1 using retained history
	out, err := decodeFork(input, 65540)
	if err != nil || !bytes.Equal(out, bytes.Repeat([]byte{'A'}, 65540)) {
		t.Fatalf("decoded %d: %v", len(out), err)
	}
	// The next full block must compensate for the preceding one-byte
	// overshoot: 65537 + 65535, not 65537 + 65536.
	second := strings.Repeat("00"+"11111"+"11111"+strings.Repeat("01000001", 63), 1040)
	second += "00" + "1110" + "111" + strings.Repeat("01000001", 15)
	three := append(append(chunk(first), chunk(second)...), chunk("01 0 00000000000")...)
	out, err = decodeFork(three, 131075)
	if err != nil || !bytes.Equal(out, bytes.Repeat([]byte{'A'}, 131075)) {
		t.Fatalf("absolute chunk boundaries: decoded %d: %v", len(out), err)
	}
	for _, size := range []int{65536, 65539, 65541} {
		if _, err := decodeFork(input, size); err == nil {
			t.Fatalf("accepted wrong decoded size %d", size)
		}
	}
	for _, bad := range [][]byte{input[:len(input)-1], append(append([]byte{}, input...), 0), {0, 2, 0, 0}} {
		if _, err := decodeFork(bad, 65540); err == nil {
			t.Fatal("accepted invalid chunk stream")
		}
	}
}
func FuzzFork(f *testing.F) {
	f.Add([]byte{1, 8, 2, 0xa6, 'A'}, uint16(1))
	f.Add(append([]byte{0, 0, 0, 0}, packed("000 0 1000001 000 0")...), uint16(4))
	f.Add(chunk("00 0 01000001"), uint16(1))
	f.Add([]byte{0, 1, 0, 0}, uint16(0))
	f.Fuzz(func(t *testing.T, b []byte, size uint16) {
		out, err := decodeFork(b, int(size))
		if err == nil && len(out) != int(size) {
			t.Fatal("escaped size")
		}
	})
}

func TestTextModeAndChecksum(t *testing.T) {
	input := append([]byte{0, 0, 0, 0}, packed("000 0 1000001 000 0 000 0 1011010")...)
	out, err := decodeFork(input, 5)
	if err != nil || string(out) != "AAAAZ" {
		t.Fatalf("%q %v", out, err)
	}
	for _, tc := range []struct {
		data []byte
		want uint32
	}{
		{nil, 0}, {[]byte{0x41}, 0xffffffbe}, {[]byte{0x80}, 0x7f},
		{[]byte{0x80, 0xff}, 0xffff80ff},
	} {
		if got := checksum(tc.data); got != tc.want {
			t.Fatalf("checksum %x: %08x want %08x", tc.data, got, tc.want)
		}
	}
}

func TestStoredChunks(t *testing.T) {
	first := bytes.Repeat([]byte{'A'}, 65536)
	input := append([]byte{1, 8, 2, 0xa6}, first...)
	input = append(input, 1, 1, 0, 0, 'Z')
	out, err := decodeFork(input, 65537)
	if err != nil || !bytes.Equal(out, append(first, 'Z')) {
		t.Fatalf("stored: %d %v", len(out), err)
	}
	if _, err := decodeFork(input[:len(input)-1], 65537); err == nil {
		t.Fatal("accepted truncated stored chunk")
	}
	// A following compressed block references stored history.
	input = append([]byte{1, 0, 0, 0}, first...)
	input = append(input, chunk("01 0 00000000000")...)
	out, err = decodeFork(input, 65539)
	if err != nil || !bytes.Equal(out, bytes.Repeat([]byte{'A'}, 65539)) {
		t.Fatalf("stored history: %d %v", len(out), err)
	}
}

func TestSparseCatalogIDs(t *testing.T) {
	b := sample()
	binary.BigEndian.PutUint32(b[28:], 100)
	a, err := Open(&starfile.Bytes{Data: b}, 1, 100)
	if err != nil || len(a.Entries) != 1 || a.Entries[0].ID != 7 {
		t.Fatalf("sparse catalog: %v", err)
	}
}
func FuzzCatalog(f *testing.F) {
	f.Add(resourceSample())
	f.Add(sample())
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Open(&starfile.Bytes{Data: b}, 64, 1<<16)
		if err != nil {
			return
		}
		n := int64(0)
		for _, e := range a.Entries {
			n += e.Data.Size() + e.Resource.Size()
		}
		if n > 1<<16 {
			t.Fatal("escaped decoded limit")
		}
	})
}
