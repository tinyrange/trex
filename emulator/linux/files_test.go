package linux

import (
	"errors"
	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/emulator/cpu"
	"io"
	"io/fs"
	"testing"
)

type trackedFile struct{ closes int }

func (f *trackedFile) Read([]byte) (int, error)    { return 0, io.EOF }
func (f *trackedFile) Write(b []byte) (int, error) { return len(b), nil }
func (f *trackedFile) Close() error                { f.closes++; return nil }

type trackedFS struct {
	names   []string
	modes   []fs.FileMode
	handles []*trackedFile
}

func (f *trackedFS) Open(name string, flags OpenFlags, mode fs.FileMode) (channel.ByteChannel, error) {
	h := new(trackedFile)
	f.names = append(f.names, name)
	f.modes = append(f.modes, mode)
	f.handles = append(f.handles, h)
	return h, nil
}
func TestFileDescriptorsAndFaults(t *testing.T) {
	files := new(trackedFS)
	p := &process{cfg: Config{Files: files, Dir: "/work"}, memory: cpu.NewAddressSpace(4096), files: make(map[uint64]*descriptor)}
	data := make([]byte, 4096)
	copy(data, []byte("relative\x00"))
	if err := p.memory.Map(4096, data, cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	if err := p.openFile(4096, 2|64, 0666); err != nil {
		t.Fatal(err)
	}
	if p.reg("rax") != 3 || files.names[0] != "/work/relative" {
		t.Fatalf("fd=%d names=%v", p.reg("rax"), files.names)
	}
	if err := p.fileIO(0, 3, 8192, 1); err != nil {
		t.Fatal(err)
	}
	if p.reg("rax") != ^uint64(13) {
		t.Fatal("invalid pointer did not return EFAULT")
	}
	// Closing standard input releases descriptor zero; a later file open must
	// reuse it, and reading that fd must use the file, not the original stdin.
	p.cpu.SetRegister("rax", 3)
	p.cpu.SetRegister("rdi", 0)
	if _, _, err := p.syscall(); err != nil {
		t.Fatal(err)
	}
	if err := p.openFile(4096, 0, 0); err != nil {
		t.Fatal(err)
	}
	if p.reg("rax") != 0 {
		t.Fatal("did not reuse descriptor zero")
	}
	if err := p.fileIO(1, 0, 4096, 1); err != nil {
		t.Fatal(err)
	}
	if p.reg("rax") != ^uint64(8) {
		t.Fatal("readonly descriptor accepted write")
	}
	p.closeFiles()
	for _, h := range files.handles {
		if h.closes != 1 {
			t.Fatalf("close count %d", h.closes)
		}
	}
	if fileErrno(errors.New("backend failure")) != 0 || fileErrno(Errno(28)) != 28 {
		t.Fatal("incorrect error boundary")
	}
}

func TestUmaskSyscallAffectsOnlyProcessCreation(t *testing.T) {
	files := new(trackedFS)
	p := &process{umask: 0022, cfg: Config{Files: files, Dir: "/"}, memory: cpu.NewAddressSpace(4096), files: make(map[uint64]*descriptor)}
	data := make([]byte, 4096)
	copy(data, []byte("file\x00"))
	if err := p.memory.Map(4096, data, cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	p.cpu.SetRegister("rax", 95)
	p.cpu.SetRegister("rdi", 010077)
	if _, exit, err := p.syscall(); err != nil || exit {
		t.Fatalf("%v %v", exit, err)
	}
	if p.reg("rax") != 0022 {
		t.Fatalf("old mask %o", p.reg("rax"))
	}
	if err := p.openFile(4096, 64|1, 0666); err != nil {
		t.Fatal(err)
	}
	if files.modes[0] != 0600 {
		t.Fatalf("mode %o", files.modes[0])
	}
	p.closeFiles()
}
