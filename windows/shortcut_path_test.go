package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// A shell can prefer the PIDL over LinkInfo. Empty primary names made the
// Edge desktop shortcut resolve to C:\ even though LinkInfo named msedge.exe.
func TestShellLinkDefaultPrimaryNames(t *testing.T) {
	link, err := buildShellLink(shellLinkOptions{
		Target: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(link) < 78 {
		t.Fatal("missing IDList size")
	}
	end := 78 + int(binary.LittleEndian.Uint16(link[76:78]))
	if end > len(link) {
		t.Fatal("IDList exceeds link")
	}
	pos := 78
	var names []string
	for pos < end {
		if end-pos < 2 {
			t.Fatal("truncated item size")
		}
		size := int(binary.LittleEndian.Uint16(link[pos : pos+2]))
		if size == 0 {
			if pos+2 != end {
				t.Fatal("early IDList terminator")
			}
			break
		}
		if size < 3 || size > end-pos {
			t.Fatal("invalid item size")
		}
		item := link[pos : pos+size]
		if item[2] == 0x31 || item[2] == 0x32 {
			if len(item) <= 14 {
				t.Fatal("missing primary name")
			}
			n := bytes.IndexByte(item[14:], 0)
			if n < 0 {
				t.Fatal("unterminated primary name")
			}
			names = append(names, string(item[14:14+n]))
		}
		pos += size
	}
	want := []string{"Program Files (x86)", "Microsoft", "Edge", "Application", "msedge.exe"}
	if len(names) != len(want) {
		t.Fatalf("PIDL names = %q, want %q", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("PIDL component %d = %q, want %q", i, names[i], want[i])
		}
	}
}
