package etl

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
)

func TestWPPTraceMessage(t *testing.T) {
	// Captured Windows 11 repdrvfs WPP header: GUID, QPC, TID/PID,
	// then a four-byte HRESULT. No alignment padding belongs to payload.
	b, err := hex.DecodeString("2c0000901400aa0029ebf52c31dab23c56d577853629d7e246a91a1503000000940e0000840a000005000780")
	if err != nil {
		t.Fatal(err)
	}
	e, n, err := record(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 44 || e.Marker != 0x9000 || e.EventID != 20 || e.MessageFlags != 0xaa || e.Timestamp != 0x3151aa946 || e.PID != 2692 || e.TID != 3732 || e.Group != 255 || !bytes.Equal(e.Payload, []byte{5, 0, 7, 128}) || e.ProviderID[0] != 0x29 || e.ProviderID[15] != 0xe2 {
		t.Fatalf("%+v", e)
	}
	for length := 0; length < len(b); length++ {
		short := bytes.Clone(b[:length])
		if length >= 2 {
			le.PutUint16(short, uint16(length))
		}
		// With a complete header, shorter payloads are legitimate.
		if length >= 40 {
			continue
		}
		if _, _, err := record(short); err == nil {
			t.Fatalf("accepted short header %d", length)
		}
	}
	// Optional sequence field precedes the GUID and shifts all later fields.
	seq := append(bytes.Clone(b[:8]), 1, 2, 3, 4)
	seq = append(seq, b[8:]...)
	le.PutUint16(seq, uint16(len(seq)))
	seq[6] |= 1
	shifted, _, err := record(seq)
	if err != nil || shifted.Timestamp != e.Timestamp || shifted.ProviderID != e.ProviderID || !bytes.Equal(shifted.Payload, e.Payload) {
		t.Fatalf("sequence: %+v %v", shifted, err)
	}
	for _, flags := range []uint16{0x100, 0x6, 0xc0, 0x10} {
		invalid := bytes.Clone(b)
		le.PutUint16(invalid[6:], flags)
		if _, _, err := record(invalid); err == nil {
			t.Fatalf("accepted flags %#x", flags)
		}
	}
	header := testHeader(1)
	le.PutUint32(header[16+32:], 0) // Default sequential mode from logman -f bin.
	b = append(b, 0, 0, 0, 0)
	data := testBuffer(0, header, b)
	count := 0
	_, err = Walk(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{}, func(e Event) error { count++; return nil })
	if err != nil || count != 2 {
		t.Fatalf("walk: %d %v", count, err)
	}
}
