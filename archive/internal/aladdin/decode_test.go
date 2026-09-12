package aladdin

import (
	"bytes"
	"reflect"
	"testing"
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
func TestLengthRepetitionAndTieOrder(t *testing.T) {
	b := bits{data: []byte{5, 0xf0, 1}}
	l, err := lengths(&b, 5, 0)
	if err != nil || !reflect.DeepEqual(l, []int{1, 1, 1, 1, 1}) || b.pos != 24 {
		t.Fatalf("%v %v", l, err)
	}
	b = bits{data: []byte{5, 15}}
	if _, err := lengths(&b, 3, 0); err == nil {
		t.Fatal("repeat before any length")
	}
	c, err := makeCodes([]int{3, 3, 3, 3, 3, 3, 3, 3})
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range []int{5, 6, 4, 7, 0, 1, 3, 2} {
		if c[key{3, uint32(i)}] != s {
			t.Fatal("changed equal-length permutation")
		}
	}
	if _, err := makeCodes([]int{1, 1, 1}); err == nil {
		t.Fatal("oversubscribed table")
	}
}
func TestRecursiveLengthTable(t *testing.T) {
	w := writer{}
	w.put(0x45, 8)
	sub := make([]int, 16)
	sub[0], sub[14] = 1, 1
	w.table(sub)
	c, err := makeCodes(sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{0, 14, 0} {
		for k, v := range c {
			if v == want {
				w.put(k.code, k.width)
			}
		}
	}
	b := bits{data: w.data}
	got, err := lengths(&b, 3, 0)
	if err != nil || !reflect.DeepEqual(got, []int{1, 0, 1}) {
		t.Fatalf("%v %v", got, err)
	}
	b = bits{data: bytes.Repeat([]byte{0x45}, 20)}
	if _, err := lengths(&b, 1, 0); err == nil {
		t.Fatal("unbounded recursion")
	}
}
