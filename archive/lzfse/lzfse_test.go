package lzfse

import (
	"bytes"
	"io"
	"testing"
)

// Synthetic entropy fixture, independently specified from the wire layout:
// four A literals; each L/M/D token is (1,3,1), producing sixteen As.
func entropyFixture(v2 bool, length, match, distance int) []byte {
	b := make([]byte, 772)
	copy(b, "bvx1")
	le.PutUint32(b[4:], 16)
	le.PutUint32(b[8:], 14)
	le.PutUint32(b[12:], 4)
	le.PutUint32(b[16:], 4)
	le.PutUint32(b[20:], 7)
	le.PutUint32(b[24:], 7)
	freq := make([]uint16, 360)
	freq[length] = 64
	freq[20+match] = 64
	freq[40+distance] = 256
	freq[104+int('A')] = 1024
	for i, f := range freq {
		le.PutUint16(b[50+2*i:], f)
	}
	if v2 {
		var codes []byte
		bit := 0
		put := func(value, n int) {
			for i := 0; i < n; i++ {
				if bit/8 >= len(codes) {
					codes = append(codes, 0)
				}
				codes[bit/8] |= byte((value>>uint(i))&1) << uint(bit%8)
				bit++
			}
		}
		for _, f := range freq {
			if f == 0 {
				put(0, 2)
			} else {
				put(15+(int(f)-24)*16, 14)
			}
		}
		b = make([]byte, 32)
		copy(b, "bvx2")
		le.PutUint32(b[4:], 16)
		le.PutUint64(b[8:], 4|7<<20|4<<40|7<<60)
		le.PutUint64(b[16:], 7<<40|7<<60)
		le.PutUint64(b[24:], uint64(32+len(codes)))
		b = append(b, codes...)
	}
	return append(b, make([]byte, 14)...)
}
func TestEntropyV1V2AndHistory(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		stream := append(entropyFixture(v2, 1, 3, 1), []byte("bvx$")...)
		f, err := Open(bytes.NewReader(stream), 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
		if err != nil || string(got) != "AAAAAAAAAAAAAAAA" {
			t.Fatalf("v2=%v %q %v", v2, got, err)
		}
		// A raw B followed by match-only entropy requires cross-block history.
		raw := append([]byte("bvx-"), 1, 0, 0, 0, 'B')
		raw = append(raw, entropyFixture(v2, 0, 4, 1)...)
		raw = append(raw, []byte("bvx$")...)
		f, err = Open(bytes.NewReader(raw), 0)
		if err != nil {
			t.Fatal(err)
		}
		var p [3]byte
		if _, err := f.ReadAt(p[:], 13); err != nil || string(p[:]) != "BBB" {
			t.Fatalf("history %q %v", p, err)
		}
		if _, err := f.ReadAt(p[:], 0); err != nil || string(p[:]) != "BBB" {
			t.Fatalf("backward %q %v", p, err)
		}
	}
}
func TestLZVNAndMalformedStreams(t *testing.T) {
	// Literal abc + distance3/match3 + reused match3 + eight-byte EOS.
	tokens := []byte{0xe3, 'a', 'b', 'c', 0, 3, 0xf3, 6, 0, 0, 0, 0, 0, 0, 0}
	b := make([]byte, 12)
	copy(b, "bvxn")
	le.PutUint32(b[4:], 9)
	le.PutUint32(b[8:], uint32(len(tokens)))
	b = append(b, tokens...)
	b = append(b, []byte("bvx$")...)
	f, err := Open(bytes.NewReader(b), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err != nil || string(got) != "abcabcabc" {
		t.Fatalf("LZVN %q %v", got, err)
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0), []byte("bvx2"), []byte("xxxx")} {
		if _, err := Open(bytes.NewReader(bad), 0); err == nil {
			t.Fatal("accepted malformed framing")
		}
	}
	if _, err := Open(bytes.NewReader(b), 8); err == nil {
		t.Fatal("maximum not enforced")
	}
	stream := append(entropyFixture(false, 0, 4, 1), []byte("bvx$")...)
	f, err = Open(bytes.NewReader(stream), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("invalid history distance accepted")
	}
	for _, tokens := range [][]byte{{0xf3, 6, 0, 0, 0, 0, 0, 0, 0}, {0x1e}, {0xe3, 'a'}} {
		if _, err := decodeLZVN(tokens, 3, nil); err == nil {
			t.Fatal("invalid LZVN accepted")
		}
	}
}
func TestBoundedCacheReplays(t *testing.T) {
	var stream []byte
	for i := 0; i < 3; i++ {
		b := make([]byte, 8)
		copy(b, "bvx-")
		le.PutUint32(b[4:], 24<<20)
		stream = append(stream, b...)
		stream = append(stream, bytes.Repeat([]byte{byte(i)}, 24<<20)...)
	}
	stream = append(stream, []byte("bvx$")...)
	f, err := Open(bytes.NewReader(stream), 0)
	if err != nil {
		t.Fatal(err)
	}
	var p [1]byte
	for _, off := range []int64{70 << 20, 1, 50 << 20} {
		if _, err := f.ReadAt(p[:], off); err != nil || p[0] != byte(off/(24<<20)) {
			t.Fatalf("replay %d %v", off, err)
		}
		if f.cached > MaxBlock || len(f.history) > historySize {
			t.Fatal("unbounded cache/history")
		}
	}
}
