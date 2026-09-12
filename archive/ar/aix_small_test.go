package ar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func aixSmallFixture() []byte {
	b := make([]byte, 1200)
	copy(b, "<aiaff>\n")
	decimal := func(at int, n int64) { copy(b[at:at+12], fmt.Sprintf("%-12d", n)) }
	for i, v := range []int64{600, 800, 400, 68, 1000} {
		decimal(8+12*i, v)
	}
	member := func(off int, name string, data []byte, next, prev int64) {
		for i, v := range []int64{int64(len(data)), next, prev, 123, 1, 2} {
			decimal(off+i*12, v)
		}
		copy(b[off+72:off+84], fmt.Sprintf("%-12o", 0644))
		copy(b[off+84:off+88], fmt.Sprintf("%-4d", len(name)))
		copy(b[off+88:], name)
		end := off + 88 + (len(name)+1)/2*2
		copy(b[end:], "`\n")
		copy(b[end+2:], data)
	}
	member(400, "one", []byte("abc"), 68, 0)
	member(68, "second", []byte("defg"), 600, 400)
	index := []byte(fmt.Sprintf("%-12d%-12d%-12d", 2, 400, 68))
	index = append(index, []byte("one\x00second\x00")...)
	member(600, "", index, 800, 68)
	symbols := binary.BigEndian.AppendUint32(nil, 1)
	symbols = binary.BigEndian.AppendUint32(symbols, 400)
	symbols = append(symbols, []byte("exported\x00")...)
	member(800, "", symbols, 0, 600)
	member(1000, "deleted", []byte("old bytes"), 0, 0)
	return b
}

func TestAIXSmallLinkedMembers(t *testing.T) {
	data := aixSmallFixture()
	source := &starfile.Bytes{Data: data}
	a, err := Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 2 || a.entries[0].entry.name != "one" || a.entries[1].entry.name != "second" {
		t.Fatal("lost link order")
	}
	for i, want := range []string{"abc", "defg"} {
		got, err := starfile.ReadAll(a.entries[i])
		if err != nil || string(got) != want {
			t.Fatal(i, string(got), err)
		}
	}
	data[a.entries[0].entry.dataOffset] = 'z'
	got, _ := starfile.ReadAll(a.entries[0])
	if string(got) != "zbc" {
		t.Fatal("copied payload")
	}
	node, err := auto.Open(source, "no-extension", auto.Options{}).Resolve("one")
	if err != nil || node.Reader().Size() != 3 {
		t.Fatal(node, err)
	}
	if _, err := openWithLimits(source, 1, 10000); err == nil {
		t.Fatal("entry limit ignored")
	}
	if _, err := openWithLimits(source, 10, 100); err == nil {
		t.Fatal("metadata limit ignored")
	}
}

func TestAIXSmallMalformed(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"cycle":            func(b []byte) { copy(b[412:424], fmt.Sprintf("%-12d", 400)) },
		"backlink":         func(b []byte) { copy(b[92:104], fmt.Sprintf("%-12d", 0)) },
		"out of range":     func(b []byte) { copy(b[400:412], fmt.Sprintf("%-12d", 2000)) },
		"numeric sign":     func(b []byte) { b[400] = '-' },
		"index name":       func(b []byte) { b[726] = 'x' },
		"index offset":     func(b []byte) { copy(b[702:714], fmt.Sprintf("%-12d", 800)) },
		"symbol reference": func(b []byte) { binary.BigEndian.PutUint32(b[894:], 999) },
		"free cycle":       func(b []byte) { copy(b[1012:1024], fmt.Sprintf("%-12d", 1000)) },
		"header overlap":   func(b []byte) { copy(b[400:412], fmt.Sprintf("%-12d", 200)) },
	} {
		t.Run(name, func(t *testing.T) {
			b := aixSmallFixture()
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
				t.Fatal("accepted malformed archive")
			}
		})
	}
	for _, n := range []int{8, 67, 100, 650, 810, 1050} {
		if _, err := Open(&starfile.Bytes{Data: bytes.Clone(aixSmallFixture()[:n])}); err == nil {
			t.Fatal("accepted truncated archive", n)
		}
	}
}
