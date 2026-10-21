package linux

import (
	"io"
	"testing"
)

func TestFcntlLimitsAndUnsupportedOperations(t *testing.T) {
	p := &process{files: make(map[uint64]*descriptor), cfg: Config{Stdout: io.Discard}}
	for fd := uint64(3); fd < 1024; fd++ {
		p.files[fd] = &descriptor{}
	}
	if e := p.fileControl(1, 0, 3); e != nil || p.reg("rax") != ^uint64(23) {
		t.Fatalf("full table: %v %#x", e, p.reg("rax"))
	}
	delete(p.files, 500)
	if e := p.fileControl(1, 1030, 3); e != nil || p.reg("rax") != 500 || !p.closeOnExec[500] {
		t.Fatalf("reuse hole: %v", e)
	}
	if e := p.closeDescriptor(500); e != nil || p.closeOnExec[500] {
		t.Fatalf("stale descriptor flag: %v", e)
	}
	if e := p.fileControl(1, 0, 500); e != nil || p.reg("rax") != 500 || p.closeOnExec[500] {
		t.Fatalf("reuse flags: %v", e)
	}
	for _, arg := range []uint64{1024, ^uint64(0)} {
		if e := p.fileControl(1, 0, arg); e != nil || p.reg("rax") != ^uint64(21) {
			t.Fatalf("invalid minimum: %v", e)
		}
	}
	if e := p.fileControl(1024, 1, 0); e != nil || p.reg("rax") != ^uint64(8) {
		t.Fatalf("bad descriptor: %v", e)
	}
	if e := p.fileControl(1, 999, 0); e == nil {
		t.Fatal("unknown operation claimed success")
	}
	if e := p.fileControl(1, 4, 2048); e == nil {
		t.Fatal("unsupported nonblocking claimed success")
	}
	if e := p.fileControl(1, 4, 1024); e == nil {
		t.Fatal("provider without append control claimed success")
	}
}
