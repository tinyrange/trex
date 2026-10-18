package perf

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

type source []byte

func (s source) Size() int64                             { return int64(len(s)) }
func (s source) ReadAt(b []byte, off int64) (int, error) { return bytes.NewReader(s).ReadAt(b, off) }

func record(kind uint32, payload ...uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, kind)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], uint16(8+len(payload)*8))
	for _, v := range payload {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	return b
}

func capture(mask, flags uint64, records ...[]byte) source {
	// Independent literal wire layout: header104 + one attr128/ids16 + ID8.
	b := make(source, 256)
	copy(b, "PERFILE2")
	put := binary.LittleEndian
	put.PutUint64(b[8:], 104)
	put.PutUint64(b[16:], 144)
	put.PutUint64(b[24:], 104)
	put.PutUint64(b[32:], 144)
	put.PutUint64(b[40:], 256)
	put.PutUint32(b[104:], 1)
	put.PutUint32(b[108:], 128)
	put.PutUint64(b[120:], 499)
	put.PutUint64(b[128:], mask)
	put.PutUint64(b[144:], flags)
	put.PutUint32(b[196:], 1)
	put.PutUint64(b[232:], 248)
	put.PutUint64(b[240:], 8)
	put.PutUint64(b[248:], 42)
	for _, r := range records {
		b = append(b, r...)
	}
	put.PutUint64(b[48:], uint64(len(b)-256))
	return b
}

func TestFixedSampleOrderAndIdentityTrailer(t *testing.T) {
	const all = uint64(0x103cf) // IDENTIFIER|STREAM_ID|PERIOD|CPU|ID|ADDR|TIME|TID|IP
	// IDENTIFIER is first in a SAMPLE, but last in a non-sample trailer.
	s := record(9, 42, 0xfeedface01234567, 0x2222222211111111, 777, 888, 42, 999, 0xdeadbeef00000003, 123)
	l := record(2, 42, 5, 0x4444444433333333, 778, 42, 1000, 7, 42)
	f, err := Open(capture(all, 1<<18|1<<25|1<<10, s, l), Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := f.Attributes[0]
	if a.SampleType != all || a.SamplePeriod != 499 || a.ClockID != 1 || !a.UseClockID || !a.SampleIDAll || len(a.IDs) != 1 || a.IDs[0] != 42 {
		t.Fatalf("attribute: %+v", a)
	}
	want := Fields{Present: all, IP: 0xfeedface01234567, PID: 0x11111111, TID: 0x22222222, Time: 777, Address: 888, ID: 42, StreamID: 999, CPU: 3, Period: 123, Identifier: 42}
	if len(f.Samples) != 1 || f.Samples[0].Fields != want || f.Samples[0].Offset != 256 || f.Samples[0].Misc != 2 {
		t.Fatalf("sample: %+v", f.Samples)
	}
	id := f.Lost[0].SampleID
	if id.Present != 0x102c6 || id.PID != 0x33333333 || id.TID != 0x44444444 || id.Time != 778 || id.ID != 42 || id.Identifier != 42 || id.StreamID != 1000 || id.CPU != 7 || f.TotalLost != 5 {
		t.Fatalf("trailer/loss: %+v", f.Lost)
	}
}

func TestSamplePresenceMasks(t *testing.T) {
	for _, bit := range []uint64{1, 2, 4, 8, 64, 128, 256, 512, 65536} {
		f, err := Open(capture(bit, 0, record(9, 0)), Options{})
		if err != nil {
			t.Fatal(bit, err)
		}
		if f.Samples[0].Fields.Present != bit || f.Records != 1 {
			t.Fatal(bit, f.Samples)
		}
	}
}

func TestFeatureMetadataIsBoundedWithoutReadingPayload(t *testing.T) {
	b := capture(1, 0, record(9, 0x1234))
	put := binary.LittleEndian
	put.PutUint64(b[72:], 1<<6) // HEADER_ARCH
	table := len(b)
	b = append(b, make([]byte, 16)...)
	put.PutUint64(b[table:], uint64(len(b)))
	put.PutUint64(b[table+8:], 8)
	b = append(b, []byte("x86_64\x00\x00")...)
	if _, err := Open(b, Options{}); err != nil {
		t.Fatal(err)
	}
	put.PutUint64(b[table:], 0)
	if _, err := Open(b, Options{}); err == nil || !strings.Contains(err.Error(), "overlapping") {
		t.Fatal("accepted overlapping feature", err)
	}
}

func TestMalformedCaptureRejected(t *testing.T) {
	base := capture(1, 0, record(9, 0x1234))
	for n := 0; n < len(base); n++ {
		if _, err := Open(base[:n], Options{}); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	for _, test := range []struct {
		name   string
		change func(source)
	}{
		{"magic", func(b source) { copy(b, "2ELIFREP") }},
		{"pipe", func(b source) { le.PutUint64(b[8:], 16) }},
		{"small attr", func(b source) { le.PutUint64(b[16:], 72) }},
		{"huge attr", func(b source) { le.PutUint64(b[16:], ^uint64(0)) }},
		{"attribute remainder", func(b source) { le.PutUint64(b[32:], 143) }},
		{"attribute mismatch", func(b source) { le.PutUint32(b[108:], 64) }},
		{"attribute overlap", func(b source) { le.PutUint64(b[24:], 0) }},
		{"ID overlap", func(b source) { le.PutUint64(b[232:], 104) }},
		{"ID truncation", func(b source) { le.PutUint64(b[240:], 16) }},
		{"ID unaligned", func(b source) { le.PutUint64(b[240:], 7) }},
		{"data overflow", func(b source) { le.PutUint64(b[40:], ^uint64(0)-4) }},
		{"data empty", func(b source) { le.PutUint64(b[48:], 0) }},
		{"sample read layout", func(b source) { le.PutUint64(b[128:], 1<<4) }},
		{"sample callchain layout", func(b source) { le.PutUint64(b[128:], 1<<5) }},
		{"unknown sample layout", func(b source) { le.PutUint64(b[128:], 1<<63) }},
		{"sample excess", func(b source) { le.PutUint64(b[128:], 0) }},
		{"sample shortage", func(b source) { le.PutUint64(b[128:], 3) }},
		{"short record", func(b source) { le.PutUint16(b[262:], 7) }},
		{"record outside data", func(b source) { le.PutUint16(b[262:], 17) }},
		{"compressed feature", func(b source) { le.PutUint64(b[72:], 1<<27) }},
		{"compressed record", func(b source) { le.PutUint32(b[256:], 81) }},
		{"aux record", func(b source) { le.PutUint32(b[256:], 71) }},
		{"stream attr", func(b source) { le.PutUint32(b[256:], 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := bytes.Clone(base)
			test.change(b)
			if _, err := Open(source(b), Options{}); err == nil {
				t.Fatal("accepted malformed capture")
			}
		})
	}
}

func TestRecordFaultsAndLimits(t *testing.T) {
	for _, b := range []source{
		capture(1<<16|1<<6, 0, record(9, 1, 2)),              // conflicting copies of event ID
		capture(1<<1|1<<2, 1<<18, record(3, 1)),              // missing sample_id trailer/body
		capture(1, 0, record(3, 1, ^uint64(0))),              // unterminated COMM
		capture(1, 0, record(1, 1, 0, 0, 0)),                 // missing MMAP filename
		capture(1, 0, record(10, 1, 0, 0, 0)),                // short MMAP2
		capture(1, 0, record(2, 1)),                          // missing LOST count
		capture(1, 0, record(13, ^uint64(0)), record(13, 1)), // loss overflow
	} {
		if _, err := Open(b, Options{}); err == nil {
			t.Fatal("accepted malformed record")
		}
	}
	b := capture(1, 0, record(9, 1), record(9, 2))
	for _, o := range []Options{{MaximumRecords: 1}, {MaximumSamples: 1}, {MaximumRecords: -1}, {MaximumSamples: 10000001}, {MaximumStringBytes: 65 << 20}} {
		if _, err := Open(b, o); err == nil {
			t.Fatal("ignored limit", o)
		}
	}
	// A string's terminator/padding do not count toward retained string bytes.
	comm := record(3, 1, uint64('a')|uint64('b')<<8)
	if _, err := Open(capture(1, 0, comm), Options{MaximumStringBytes: 1}); err == nil {
		t.Fatal("ignored string budget")
	}
	if _, err := Open(capture(1, 0, comm), Options{MaximumStringBytes: 2}); err != nil {
		t.Fatal(err)
	}
}

func TestMappingUnionAndOverflow(t *testing.T) {
	// MMAP2 build-ID union uses bytes32..55; its size cannot exceed20.
	m := record(10, 1, 0x1000, 0x2000, 0, 0, 0, 0, 0, 0)
	le.PutUint16(m[4:], 1<<14)
	m[8+32] = 21
	if _, err := Open(capture(1, 0, m), Options{}); err == nil {
		t.Fatal("accepted oversized build ID")
	}
	for _, address := range []bool{false, true} {
		m := record(1, 1, 0, 16, 0, 0)
		off := 8 + 24
		if address {
			off = 8 + 8
		}
		le.PutUint64(m[off:], ^uint64(0)-7)
		if _, err := Open(capture(1, 0, m), Options{}); err == nil {
			t.Fatal("accepted overflowing mmap")
		}
	}
}

type shortReader struct{ source }

func (r shortReader) ReadAt(b []byte, off int64) (int, error) {
	n, _ := r.source.ReadAt(b, off)
	if n > 0 {
		n--
	}
	return n, nil
}
func TestReaderShortReadRejected(t *testing.T) {
	_, err := Open(shortReader{capture(1, 0, record(9, 1))}, Options{})
	if err == nil || !strings.Contains(err.Error(), io.ErrUnexpectedEOF.Error()) {
		t.Fatal(err)
	}
}

func FuzzOpen(f *testing.F) {
	f.Add([]byte(capture(1, 0, record(9, 0x1234))))
	f.Add(starFixture().Data)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Open(source(b), Options{MaximumRecords: 1000, MaximumSamples: 1000, MaximumStringBytes: 4096})
	})
}
