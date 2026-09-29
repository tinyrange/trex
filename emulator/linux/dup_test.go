package linux

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"io"
	"strings"
	"testing"
)

func TestDup2SharesOffsetAndClosesOnce(t *testing.T) {
	f := new(trackedFile)
	d := &descriptor{file: f, flags: Read, reader: strings.NewReader("abc")}
	p := &process{files: map[uint64]*descriptor{3: d}, memory: cpu.NewAddressSpace(4096)}
	if err := p.duplicateDescriptor(3, 4); err != nil || p.reg("rax") != 4 {
		t.Fatalf("dup: %v", err)
	}
	var b [1]byte
	for _, fd := range []uint64{3, 4} {
		if _, err := p.files[fd].reader.Read(b[:]); err != nil {
			t.Fatal(err)
		}
	}
	if b[0] != 'b' {
		t.Fatal("offset not shared")
	}
	if err := p.closeDescriptor(3); err != nil || f.closes != 0 {
		t.Fatalf("early close: %d %v", f.closes, err)
	}
	replacement := new(trackedFile)
	p.files[5] = &descriptor{file: replacement, flags: Write, writer: replacement}
	if err := p.duplicateDescriptor(4, 5); err != nil || replacement.closes != 1 {
		t.Fatalf("replacement: %d %v", replacement.closes, err)
	}
	if err := p.duplicateDescriptor(5, 5); err != nil || f.closes != 0 {
		t.Fatal("self duplication closed file")
	}
	if err := p.duplicateDescriptor(9999, 5); err != nil || p.reg("rax") != ^uint64(8) || p.files[5] != d {
		t.Fatal("invalid source modified destination")
	}
	if err := p.duplicateDescriptor(5, 1024); err != nil || p.reg("rax") != ^uint64(8) {
		t.Fatal("invalid destination accepted")
	}
	p.closeFiles()
	if f.closes != 1 || replacement.closes != 1 {
		t.Fatalf("closes=%d,%d", f.closes, replacement.closes)
	}
	if err := p.closeDescriptor(4); err != Errno(9) {
		t.Fatalf("closed fd: %v", err)
	}
}
func TestDup2StandardStreamSurvivesOriginalClose(t *testing.T) {
	p := &process{files: make(map[uint64]*descriptor), cfg: Config{Stdout: io.Discard}}
	if err := p.duplicateDescriptor(1, 7); err != nil {
		t.Fatal(err)
	}
	if err := p.closeDescriptor(1); err != nil {
		t.Fatal(err)
	}
	if p.files[7].writer != io.Discard {
		t.Fatal("lost stdout")
	}
	if err := p.duplicateDescriptor(7, 1); err != nil {
		t.Fatal(err)
	}
	if err := p.closeDescriptor(7); err != nil {
		t.Fatal(err)
	}
	if p.files[1].writer != io.Discard {
		t.Fatal("lost restored stdout")
	}
	p.closeFiles()
}
