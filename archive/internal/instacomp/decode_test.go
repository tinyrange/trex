package instacomp

import (
	"strings"
	"testing"
)

func packedBits(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b := make([]byte, (len(s)+7)/8)
	for i, c := range s {
		if c == '1' {
			b[i/8] |= 0x80 >> uint(i%8)
		} else if c != '0' {
			panic("bad test bits")
		}
	}
	return b
}
func TestDcmp3Distance(t *testing.T) {
	for _, tc := range []struct {
		position int
		bits     string
		want     int
	}{
		{1, "0", 1}, {10, "1001", 3}, {10, "11001", 7},
		{21, "001", 2}, {40, "100011", 8}, {40, "1100011", 24},
		{675, "1000000111", 72}, {1000, "110000000001", 322},
		{650, "11000000011", 164},
		{645, "11000000011", 164},
		{1650, "11" + strings.Repeat("0", 11), 641},
	} {
		r := bitReader{data: packedBits(tc.bits)}
		got := r.distance(tc.position)
		if r.err != nil || got != tc.want {
			t.Errorf("position%d bits%s: %d want%d: %v", tc.position, tc.bits, got, tc.want, r.err)
		}
	}
}

func TestTextCodebooks(t *testing.T) {
	for ones := 0; ones <= 10; ones++ {
		prefix := strings.Repeat("1", ones)
		if ones < 10 {
			prefix += "0"
		}
		width, want := ones, (1<<uint(ones))+4
		if ones < 3 {
			width, want = 2, 4*ones
		}
		r := bitReader{data: packedBits(prefix + strings.Repeat("0", width))}
		if got := r.copyLengthText(); r.err != nil || got != want {
			t.Fatalf("text length prefix %d: %d want %d: %v", ones, got, want, r.err)
		}
	}
	for _, tc := range []struct{ position, k int }{{321, 6}, {833, 7}, {1281, 8}, {2561, 9}, {5121, 10}, {10241, 11}, {30001, 11}, {32768, 11}} {
		r := bitReader{data: packedBits("0" + strings.Repeat("0", tc.k))}
		got := r.distanceMode(tc.position, true, 32768)
		if r.err != nil || got != 1 || r.pos != int64(tc.k+1) {
			t.Fatalf("text distance at %d: %d bits %d: %v", tc.position, got, r.pos, r.err)
		}
	}
}
