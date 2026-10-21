package native

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExclusiveOwnershipAndNoOverwrite(t *testing.T) {
	name := filepath.Join(t.TempDir(), "final.scs")
	r, e := CreateOptimized(name)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	w := r.Empty()
	if e = w.WriteFile("f", []byte("kept")); e != nil {
		t.Fatal(e)
	}
	if _, e = w.Publish("main"); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := Open(name); e == nil {
		other.Close()
		t.Fatal("second owner accepted")
	}
	if other, e := Create(name); e == nil {
		other.Close()
		t.Fatal("existing repository overwritten")
	}
	after, e := os.ReadFile(name)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed constructor changed repository", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	next, e := Open(name)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	saved, e := next.Checkout("main")
	if e != nil {
		t.Fatal(e)
	}
	data, e := saved.ReadFile("f")
	if e != nil || string(data) != "kept" {
		t.Fatal(string(data), e)
	}
}
func TestRejectedOpenDoesNotRepairInvalidHeader(t *testing.T) {
	name := filepath.Join(t.TempDir(), "invalid.scs")
	data := []byte("not an SCS repository")
	if e := os.WriteFile(name, data, 0600); e != nil {
		t.Fatal(e)
	}
	if r, e := Open(name); e == nil {
		r.Close()
		t.Fatal("invalid header accepted")
	}
	after, e := os.ReadFile(name)
	if e != nil || !bytes.Equal(after, data) {
		t.Fatal("rejected open modified bytes", e)
	}
	if _, e := GitTransport(name); e == nil {
		t.Fatal("host local Git transport accepted")
	}
}
