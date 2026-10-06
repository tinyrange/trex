package gzip

import (
	"bytes"
	stdgzip "compress/gzip"
	"io"
	"math"
	"testing"
)

func member(t *testing.T, data string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := stdgzip.NewWriter(&b)
	w.Name = "member"
	if _, err := io.WriteString(w, data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestExactMemberBoundariesAndIntegrity(t *testing.T) {
	a, b, c := member(t, "control"), member(t, ""), member(t, "data")
	raw := append(append(append([]byte(nil), a...), b...), c...)
	views, err := Members(bytes.NewReader(raw), 11, 3)
	if err != nil {
		t.Fatal(err)
	}
	if wide, err := Members(bytes.NewReader(raw), math.MaxInt64, 3); err != nil || len(wide) != 3 {
		t.Fatal("large limit overflowed", len(wide), err)
	}
	for i, want := range [][]byte{a, b, c} {
		got, err := io.ReadAll(io.NewSectionReader(views[i], 0, views[i].Size()))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal(i, err)
		}
	}
	for _, test := range []struct {
		data  []byte
		limit int64
		count int
	}{{raw, 10, 3}, {raw, 11, 2}, {raw[:len(raw)-1], 11, 3}, {append(append([]byte(nil), raw...), 0), 11, 4}} {
		if _, err := Members(bytes.NewReader(test.data), test.limit, test.count); err == nil {
			t.Fatal("accepted malformed or over-limit stream")
		}
	}
	broken := append([]byte(nil), raw...)
	broken[len(a)-8] ^= 1
	if _, err := Members(bytes.NewReader(broken), 11, 3); err == nil {
		t.Fatal("bad CRC accepted")
	}
}
