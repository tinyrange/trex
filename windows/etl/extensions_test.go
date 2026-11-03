package etl

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Independent serialized EVENT_HEADER fixtures: inline extension data is not
// the SDK's in-memory DataPtr structure. Padding is intentionally nonzero.
func testExtension(kind, link uint16, data []byte) []byte {
	b := bytes.Repeat([]byte{0xcc}, (8+len(data)+7)&^7)
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	binary.LittleEndian.PutUint16(b[2:], kind)
	binary.LittleEndian.PutUint16(b[4:], link)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(data)))
	copy(b[8:], data)
	return b
}
func testManifestRecord(ext, payload []byte) []byte {
	b := make([]byte, 80)
	binary.LittleEndian.PutUint16(b[2:], 0xc013)
	binary.LittleEndian.PutUint16(b[4:], 1)
	binary.LittleEndian.PutUint32(b[8:], 0x1234)
	binary.LittleEndian.PutUint32(b[12:], 3704)
	binary.LittleEndian.PutUint64(b[16:], 987654321)
	b[24] = 0x81
	binary.LittleEndian.PutUint16(b[40:], 1001)
	copy(b[64:], "activity-id-1234")
	b = append(b, ext...)
	b = append(b, payload...)
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	return b
}
func TestEventExtensionsSeparatePayloadAndPreserveStackWidths(t *testing.T) {
	stack := make([]byte, 24)
	binary.LittleEndian.PutUint64(stack, 0x1122334455667788)
	binary.LittleEndian.PutUint64(stack[8:], 0x7ffdc95983e7)
	binary.LittleEndian.PutUint64(stack[16:], 0xfffff80212345678)
	extensions := append(testExtension(6, 1, stack), testExtension(12, 0, []byte{1, 2, 3})...)
	raw := testManifestRecord(extensions, []byte("user-data"))
	e, n, err := record(raw)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(raw) || e.PID != 3704 || e.EventID != 1001 || e.HeaderFlags != 1 || string(e.ActivityID[:]) != "activity-id-1234" {
		t.Fatalf("header: %+v", e)
	}
	if string(e.Payload) != "user-data" || len(e.ExtendedData) != 2 {
		t.Fatalf("payload/extensions: %+v", e)
	}
	s := e.ExtendedData[0]
	if s.PointerSize != 8 || s.MatchID != 0x1122334455667788 || len(s.Stack) != 2 || s.Stack[1] != 0xfffff80212345678 {
		t.Fatalf("stack: %+v", s)
	}
	if !bytes.Equal(e.ExtendedData[1].Data, []byte{1, 2, 3}) {
		t.Fatal("opaque provider data changed")
	}
	short := make([]byte, 12)
	binary.LittleEndian.PutUint64(short, 77)
	binary.LittleEndian.PutUint32(short[8:], 0xfedcba98)
	e, _, err = record(testManifestRecord(testExtension(5, 0, short), nil))
	if err != nil || e.ExtendedData[0].PointerSize != 4 || e.ExtendedData[0].Stack[0] != 0xfedcba98 {
		t.Fatalf("32-bit stack: %+v %v", e, err)
	}
}
func TestEventExtensionsRejectMalformedChains(t *testing.T) {
	stack := make([]byte, 16)
	valid := testManifestRecord(testExtension(6, 0, stack), nil)
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"short_header", func(b []byte) []byte { return b[:84] }},
		{"oversize_data", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[86:], 65535); return b }},
		{"unterminated_chain", func(b []byte) []byte { b[84] = 1; return b }},
		{"missing_alignment", func(b []byte) []byte { b[82] = 12; binary.LittleEndian.PutUint16(b[86:], 9); return b[:97] }},
		{"short_match_id", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[86:], 7); return b }},
		{"partial_address", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[86:], 15); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.mutate(bytes.Clone(valid))
			binary.LittleEndian.PutUint16(b, uint16(len(b)))
			if _, _, err := record(b); err == nil {
				t.Fatal("accepted malformed extension")
			}
		})
	}
	chain := append(bytes.Repeat(testExtension(12, 1, nil), 127), testExtension(12, 0, nil)...)
	if e, _, err := record(testManifestRecord(chain, nil)); err != nil || len(e.ExtendedData) != 128 {
		t.Fatalf("valid bounded chain: count=%d err=%v", len(e.ExtendedData), err)
	}
	chain = append(testExtension(12, 1, nil), chain...)
	if _, _, err := record(testManifestRecord(chain, nil)); err == nil {
		t.Fatal("accepted unbounded chain")
	}
	// With no EXTENDED_INFO flag the same bytes remain opaque user data.
	b := bytes.Clone(valid)
	binary.LittleEndian.PutUint16(b[4:], 0)
	e, _, err := record(b)
	if err != nil || len(e.ExtendedData) != 0 || !bytes.Equal(e.Payload, b[80:]) {
		t.Fatalf("ordinary user data changed: %v", err)
	}
}
