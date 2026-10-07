package cpio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func record(sig, name, data string, ino, mode, links uint32) []byte {
	var b bytes.Buffer
	var sum uint32
	if sig == "070702" {
		for _, v := range []byte(data) {
			sum += uint32(v)
		}
	}
	b.WriteString(sig)
	if sig == "070707" {
		fmt.Fprintf(&b, "%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", 1, ino, mode, 0, 0, links, 0, 0, len(name)+1, len(data))
	} else {
		for _, v := range []uint32{ino, mode, 0, 0, links, 0, uint32(len(data)), 1, 0, 0, 0, uint32(len(name) + 1), sum} {
			fmt.Fprintf(&b, "%08x", v)
		}
	}
	b.WriteString(name)
	b.WriteByte(0)
	if sig != "070707" {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	b.WriteString(data)
	if sig != "070707" {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	return b.Bytes()
}
func trailer(sig string) []byte { return record(sig, "TRAILER!!!", "", 0, 0, 1) }
func readPath(t *testing.T, b []byte, name string) string {
	t.Helper()
	root := auto.Open(&starfile.Bytes{Data: b}, "test.cpio", auto.Options{})
	node, err := root.Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(node.Reader(), 0, node.Reader().Size()))
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}
func TestASCIIFormats(t *testing.T) {
	for _, sig := range []string{"070701", "070702", "070707"} {
		t.Run(sig, func(t *testing.T) {
			b := record(sig, "./dir", "", 1, 0040755, 2)
			b = append(b, record(sig, "dir/file", "hello", 2, 0100644, 1)...)
			b = append(b, record(sig, "link", "dir/file", 3, 0120777, 1)...)
			b = append(b, trailer(sig)...)
			if got := readPath(t, b, "dir/file"); got != "hello" {
				t.Fatal(got)
			}
			node, err := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{}).Resolve("link")
			if err != nil {
				t.Fatal(err)
			}
			m := node.Summary()
			if m.Kind != "symlink" || m.Readable || m.Attributes["target"] != "dir/file" {
				t.Fatalf("%+v", m)
			}
		})
	}
}
func TestHardlinksAndConcatenation(t *testing.T) {
	b := record("070701", "a", "", 42, 0100644, 2)
	b = append(b, record("070701", "b", "first", 42, 0100644, 2)...)
	b = append(b, trailer("070701")...)
	b = append(b, make([]byte, 512)...)
	b = append(b, record("070701", "a", "second", 42, 0100644, 2)...)
	b = append(b, record("070701", "c", "", 42, 0100644, 2)...)
	b = append(b, trailer("070701")...)
	for name, want := range map[string]string{"a": "second", "b": "first", "c": "second"} {
		if got := readPath(t, b, name); got != want {
			t.Fatalf("%s = %q", name, got)
		}
	}
	// A later data-carrying hardlink replaces the earlier payload too.
	b = record("070707", "a", "first", 42, 0100644, 2)
	b = append(b, record("070707", "b", "second", 42, 0100644, 2)...)
	b = append(b, trailer("070707")...)
	if got := readPath(t, b, "a"); got != "second" {
		t.Fatal(got)
	}
}
func TestBoundsAndChecksums(t *testing.T) {
	for _, name := range []string{"../escape", "safe/../../escape", "/absolute", ""} {
		b := append(record("070701", name, "hello", 1, 0100644, 1), trailer("070701")...)
		if _, err := Open(b, &starfile.Bytes{Data: b}, auto.Options{}); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	b := append(record("070702", "file", "hello", 1, 0100644, 1), trailer("070702")...)
	at := bytes.Index(b, []byte("hello"))
	b[at] ^= 1
	v, err := Open(b, &starfile.Bytes{Data: b}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	es, err := v.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = es[0].Reader.ReadAt(make([]byte, 1), 0); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("got %v", err)
	}
	b = record("070701", "file", "hello", 1, 0100644, 1)
	if _, err = Open(b, &starfile.Bytes{Data: b[:at+2]}, auto.Options{}); err == nil {
		t.Fatal("accepted truncated payload")
	}
	b = append(record("070701", "a", "", 1, 0100644, 1), record("070701", "b", "", 2, 0100644, 1)...)
	if _, err = Open(b, &starfile.Bytes{Data: b}, auto.Options{MaxEntries: 1}); !errors.Is(err, auto.ErrLimit) {
		t.Fatalf("entry limit: %v", err)
	}
}

// Simulate a decoder that cannot reread its earlier bytes without replaying.
type forwardOnly struct {
	*starfile.Bytes
	end int64
}

func (r *forwardOnly) ReadAt(p []byte, off int64) (int, error) {
	if off < r.end {
		return 0, fmt.Errorf("backward read %d < %d", off, r.end)
	}
	n, err := r.Bytes.ReadAt(p, off)
	r.end = off + int64(n)
	return n, err
}
func TestIndexIsForwardOnly(t *testing.T) {
	b := record("070701", "a", "payload", 1, 0100644, 1)
	b = append(b, record("070701", "link", "a", 2, 0120777, 1)...)
	b = append(b, trailer("070701")...)
	if _, err := Open(b, &forwardOnly{Bytes: &starfile.Bytes{Data: b}}, auto.Options{}); err != nil {
		t.Fatal(err)
	}
}
