package ibmiimd

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Fixed bit strings specify tokens independently of any codec encoder.
func testFrame(bits string, want uint32) []byte {
	bits = strings.ReplaceAll(bits, " ", "") + "1000000111111111" // length-255 control, then a stop bit
	data := make([]byte, 12+max(4, ((len(bits)+31)/32)*4))
	binary.BigEndian.PutUint32(data, 0x03000080)
	binary.BigEndian.PutUint32(data[4:], uint32(len(data)))
	binary.BigEndian.PutUint32(data[8:], want)
	for i, b := range bits {
		if b == '1' {
			data[12+i/8] |= 1 << uint(7-i%8)
		}
	}
	return data
}
func testPacked(frames ...[]byte) []byte {
	data := make([]byte, 16)
	var expanded uint32
	for _, f := range frames {
		data = append(data, f...)
		expanded += binary.BigEndian.Uint32(f[8:])
	}
	binary.BigEndian.PutUint32(data, uint32(len(data)))
	binary.BigEndian.PutUint32(data[4:], expanded)
	binary.BigEndian.PutUint32(data[8:], uint32(len(frames)))
	return data
}
func TestRecoveredTokens(t *testing.T) {
	for _, tc := range []struct {
		name, bits string
		want       []byte
	}{
		{"literal", "0 01000001", []byte("A")},
		{"overlap near", "0 01000001 1 11 1 0000001", []byte("AAAA")},
		{"overlap far", "0 01000001 1 11 0 00000000001", []byte("AAAA")},
		{"wide length", "0 01000001 1 000000 10000000 1 0000001", bytes.Repeat([]byte("A"), 129)},
		{"binary literals", "0 00000000 0 11111111", []byte{0, 255}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeFrame(testFrame(tc.bits, uint32(len(tc.want))))
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("%x %v", got, err)
			}
		})
	}
}
func TestMalformedTokens(t *testing.T) {
	for name, f := range map[string][]byte{
		"before history":  testFrame("1 11 1 0000001", 3),
		"zero distance":   testFrame("0 01000001 1 11 1 0000000", 4),
		"overrun":         testFrame("0 01000001 1 11 1 0000001", 2),
		"end marker":      testFrame("1 000000 11111111", 1),
		"truncated bits":  testFrame("", 32768),
		"too much output": testFrame("", 32769),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeFrame(f); err == nil {
				t.Fatal("malformed frame accepted")
			}
		})
	}
}
func TestPackedRandomAccessAndFrameIsolation(t *testing.T) {
	source := &starfile.Bytes{Data: testPacked(testFrame("0 01000001 1 11 1 0000001", 4), testFrame("0 01000010", 1))}
	p, err := OpenPacked(source, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 3)
	if n, err := p.Data.ReadAt(got, 2); n != 3 || err != nil || string(got) != "AAB" {
		t.Fatal(n, got, err)
	}
	if n, err := p.Data.ReadAt(got, 4); n != 1 || err != io.EOF || got[0] != 'B' {
		t.Fatal(n, got, err)
	}
	if n, err := p.Data.ReadAt(got, -1); n != 0 || err == nil {
		t.Fatal(n, err)
	}
	if n, err := p.Data.ReadAt(nil, 5); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	// The second frame must not borrow the first frame's output as history.
	bad := &starfile.Bytes{Data: testPacked(testFrame("0 01000001", 1), testFrame("1 11 1 0000001", 3))}
	p, err = OpenPacked(bad, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Data.ReadAt(got, 1); err == nil {
		t.Fatal("history crossed frame boundary")
	}
	result, err := auto.Identify(source, auto.Options{})
	if err != nil || result.Format != "ibmi_packed" {
		t.Fatal(result, err)
	}
	entries, err := result.View.Entries()
	if err != nil || len(entries) != 3 {
		t.Fatal(entries, err)
	}
}
func TestPackedHeaderBounds(t *testing.T) {
	fixture := testPacked(testFrame("0 01000001", 1))
	for name, mutate := range map[string]func([]byte){
		"reserved":     func(b []byte) { b[15] = 1 },
		"outside":      func(b []byte) { binary.BigEndian.PutUint32(b, 0xffffffff) },
		"count":        func(b []byte) { binary.BigEndian.PutUint32(b[8:], 100000) },
		"aggregate":    func(b []byte) { binary.BigEndian.PutUint32(b[4:], 2) },
		"frame marker": func(b []byte) { b[16] = 0 },
		"frame length": func(b []byte) { binary.BigEndian.PutUint32(b[20:], 15) },
		"frame output": func(b []byte) { binary.BigEndian.PutUint32(b[24:], 32769) },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(fixture)
			mutate(b)
			if _, err := OpenPacked(&starfile.Bytes{Data: b}, 10, 1<<20); err == nil {
				t.Fatal("bad header accepted")
			}
		})
	}
	source := &starfile.Bytes{Data: fixture}
	if _, err := OpenPacked(source, 1, 0); err == nil {
		t.Fatal("budget ignored")
	}
	if _, err := OpenPacked(source, 0, 1); err == nil {
		t.Fatal("frame budget ignored")
	}
}
