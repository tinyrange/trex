package rawcd

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func TestSectorViews(t *testing.T) {
	for _, stride := range []int{2352, 2448} {
		for _, mode := range []byte{1, 2} {
			raw := make([]byte, 20*stride)
			logical := make([]byte, 20*2048)
			offset := 16
			if mode == 2 {
				offset = 24
			}
			for i := 0; i < 20; i++ {
				s := raw[i*stride:]
				copy(s, syncBytes)
				s[15] = mode
				data := bytes.Repeat([]byte{byte(i)}, 2048)
				copy(s[offset:], data)
				copy(logical[i*2048:], data)
			}
			copy(raw[16*stride+offset:], []byte{1, 'C', 'D', '0', '0', '1', 1})
			copy(logical[16*2048:], []byte{1, 'C', 'D', '0', '0', '1', 1})
			f, e := Open(&starfile.Bytes{Data: raw})
			if e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(logical))
			if _, e = f.ReadAt(got, 0); e != nil || !bytes.Equal(got, logical) {
				t.Fatal("whole view", e)
			}
			got = make([]byte, 3000)
			if _, e = f.ReadAt(got, 2019); e != nil || !bytes.Equal(got, logical[2019:5019]) {
				t.Fatal("cross-sector", e)
			}
			if n, e := f.ReadAt(got, f.Size()-3); n != 3 || e != io.EOF {
				t.Fatalf("EOF %d %v", n, e)
			}
			if mode == 2 {
				raw[2*stride+18] = 0x20
				raw[2*stride+22] = 0x20
			} else {
				raw[2*stride] = 42
			}
			if _, e = f.ReadAt(got, 4096); e == nil {
				t.Fatal("accepted invalid sector")
			}
		}
	}
}
