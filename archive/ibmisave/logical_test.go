package ibmisave

import (
	"bytes"
	"errors"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func TestLogicalHoleAndSavedAssembly(t *testing.T) {
	s := Section{Address: 0x100000000, LogicalSize: 8, Data: &starfile.Bytes{Data: []byte("abcd")}}
	r, err := s.LogicalReader()
	if err != nil || r.Size() != 8 {
		t.Fatal(r, err)
	}
	p := bytes.Repeat([]byte{'?'}, 6)
	n, err := r.ReadAt(p, 0)
	if n != 4 || !errors.Is(err, ErrUnsaved) || string(p) != "abcd??" {
		t.Fatal(n, string(p), err)
	}
	if n, err := r.ReadAt(p[:1], 7); n != 0 || !errors.Is(err, ErrUnsaved) {
		t.Fatal(n, err)
	}
	if _, err := r.ReadAt(p[:1], 8); err != io.EOF {
		t.Fatal(err)
	}
	o := Object{Sections: []Section{s, {Address: 0x100000008, LogicalSize: 4, Data: &starfile.Bytes{Data: []byte("efgh")}}}}
	if _, err := o.StoredAt(s.Address, 12); !errors.Is(err, ErrUnsaved) {
		t.Fatal("filled a gap", err)
	}
	o.Sections[0].LogicalSize = 4
	o.Sections[1].Address = s.Address + 4
	assembled, err := o.StoredAt(s.Address+2, 5)
	if err != nil {
		t.Fatal(err)
	}
	p = make([]byte, 5)
	if _, err := assembled.ReadAt(p, 0); err != nil || string(p) != "cdefg" {
		t.Fatal(string(p), err)
	}
	o.Sections[1].Address = s.Address + 3
	if _, err := o.StoredAt(s.Address, 2); err == nil {
		t.Fatal("ambiguous spans")
	}
	if _, err := o.StoredAt(^uint64(0), 1); err == nil {
		t.Fatal("overflow")
	}
}
