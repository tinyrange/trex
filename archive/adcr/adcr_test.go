package adcr

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

type writer struct {
	data []byte
	pos  int
}

func (w *writer) put(v uint32, n int) {
	for i := 0; i < n; i++ {
		if w.pos/8 == len(w.data) {
			w.data = append(w.data, 0)
		}
		w.data[w.pos/8] |= byte(v>>i&1) << uint(w.pos%8)
		w.pos++
	}
}
func (w *writer) align() { w.pos = (w.pos + 7) / 8 * 8 }
func (w *writer) table(l []int) {
	w.put(5, 8) // minimum1, four-bit tokens, zero token14.
	for _, n := range l {
		v := 14
		if n != 0 {
			v = n - 1
		}
		w.put(uint32(v), 4)
	}
	w.align()
}
func fixture(match bool) []byte {
	w := writer{}
	w.put(1, 8)
	l := make([]int, 292)
	symbol := 65
	target := 1
	if match {
		symbol = 256
		target = 3
	}
	l[symbol] = 1
	w.table(l)
	w.table([]int{1})
	w.put(0, 1)
	if match {
		w.put(0, 1)
	}
	return append([]byte{'A', 'D', 'C', 'R', 3, 0, 0, byte(target)}, w.data...)
}
func TestLiteralAndDictionary(t *testing.T) {
	for _, match := range []bool{false, true} {
		input := fixture(match)
		seed := &starfile.Bytes{Data: []byte("Q")}
		file, err := Open(&starfile.Bytes{Data: input}, seed, 4096)
		if err != nil {
			t.Fatal(err)
		}
		got, err := starfile.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		want := "A"
		if match {
			want = "QQQ"
		}
		if string(got) != want {
			t.Fatalf("got %q", got)
		}
	}
	if _, err := Open(&starfile.Bytes{Data: fixture(true)}, nil, 4096); err == nil {
		t.Fatal("invented dictionary")
	}
}
func TestRejectMalformed(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { b[4] = 4; return b },
		func(b []byte) []byte { b[8] = 17; return b },
	} {
		if _, err := Open(&starfile.Bytes{Data: mutate(fixture(false))}, nil, 4096); err == nil {
			t.Fatal("accepted malformed stream")
		}
	}
	if _, err := Open(&starfile.Bytes{Data: fixture(false)}, nil, 0); err == nil {
		t.Fatal("ignored limit")
	}
	input := fixture(true)
	input[7] = 2
	if _, err := Open(&starfile.Bytes{Data: input}, &starfile.Bytes{Data: []byte("Q")}, 4096); err == nil {
		t.Fatal("match overran output")
	}
}
func FuzzDecode(f *testing.F) {
	f.Add(fixture(false))
	f.Add(fixture(true))
	f.Fuzz(func(t *testing.T, b []byte) {
		file, err := Open(&starfile.Bytes{Data: b}, &starfile.Bytes{Data: []byte("Q")}, 4096)
		if err == nil && file.Size() > 4096 {
			t.Fatal("output limit")
		}
	})
}
