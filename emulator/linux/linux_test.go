package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"renvo.dev/driver"
)

type sourceFS struct{ fstest.MapFS }

func (s sourceFS) PathExists(name string) bool {
	_, err := s.MapFS.Stat(strings.TrimPrefix(name, "./"))
	return err == nil
}
func (s sourceFS) ReadFile(name string) ([]byte, bool) {
	data, err := s.MapFS.ReadFile(strings.TrimPrefix(name, "./"))
	return data, err == nil
}
func (s sourceFS) ReadDir(name string) ([]driver.DirEntry, bool) {
	entries, err := s.MapFS.ReadDir(name)
	if err != nil {
		return nil, false
	}
	result := make([]driver.DirEntry, len(entries))
	for i, e := range entries {
		result[i] = driver.DirEntry{Name: e.Name(), IsDir: e.IsDir()}
	}
	return result, true
}
func TestRenvoCPrograms(t *testing.T) {
	for _, tc := range []struct {
		name, source, output string
		status               int
	}{
		{"return", `int main(void) { int x=0; for (int i=0; i<7; ++i) x+=i; return x; }`, "", 21},
		{"arguments", `int main(int argc, char **argv) { return argc == 2 && argv[1][0] == 'x' ? 0 : 42; }`, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := driver.CompileCommand(&driver.CommandRequest{Filesystem: sourceFS{fstest.MapFS{"main.c": {Data: []byte(tc.source)}}}, Args: []string{"cc", "main.c"}, Target: "linux/amd64", ArenaSize: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Ok {
				t.Fatalf("compile: %+v", result.Diagnostic)
			}
			var out bytes.Buffer
			run, err := Run(context.Background(), bytes.NewReader(result.Binary), Config{Args: []string{"probe", "x"}, Stdout: &out, Stderr: &out, MaxInstructions: 1000000})
			if err != nil {
				t.Fatalf("%+v: %v; output=%q", run, err, out.String())
			}
			if run.Status != tc.status || out.String() != tc.output {
				t.Fatalf("status=%d output=%q", run.Status, out.String())
			}
		})
	}
}

// ELF fixture assembled directly from instructions, independent of Renvo's
// loader conventions. The code and headers share one RX load segment.
func tinyELF(code []byte) []byte {
	b := make([]byte, 128+len(code))
	copy(b, "\x7fELF\x02\x01\x01")
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)
	le.PutUint16(b[18:], 62)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], 0x400080)
	le.PutUint64(b[32:], 64)
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[54:], 56)
	le.PutUint16(b[56:], 1)
	le.PutUint32(b[64:], 1)
	le.PutUint32(b[68:], 5)
	le.PutUint64(b[80:], 0x400000)
	le.PutUint64(b[96:], uint64(len(b)))
	le.PutUint64(b[104:], uint64(len(b)))
	le.PutUint64(b[112:], 4096)
	copy(b[128:], code)
	return b
}
func TestExitAndUnsupportedSyscall(t *testing.T) {
	// mov eax,60; mov edi,37; syscall
	image := tinyELF([]byte{0xb8, 60, 0, 0, 0, 0xbf, 37, 0, 0, 0, 0x0f, 0x05})
	result, err := Run(context.Background(), bytes.NewReader(image), Config{})
	if err != nil || result.Status != 37 || result.Instructions != 3 {
		t.Fatalf("%+v %v", result, err)
	}
	image[129] = 255
	_, err = Run(context.Background(), bytes.NewReader(image), Config{})
	var syscall *SyscallError
	if !errors.As(err, &syscall) || syscall.Number != 255 {
		t.Fatalf("want unsupported syscall, got %v", err)
	}
}
func TestELFValidationAndBudgets(t *testing.T) {
	valid := tinyELF([]byte{0xeb, 0xfe})
	for _, change := range []func([]byte){
		func(b []byte) { b[4] = 1 },
		func(b []byte) { binary.LittleEndian.PutUint64(b[32:], ^uint64(0)) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[104:], 1<<40) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 3) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[68:], 4) },
	} {
		image := bytes.Clone(valid)
		change(image)
		if _, err := Run(context.Background(), bytes.NewReader(image), Config{MaxInstructions: 10}); err == nil {
			t.Fatal("accepted invalid ELF")
		}
	}
	result, err := Run(context.Background(), bytes.NewReader(valid), Config{MaxInstructions: 10})
	if err == nil || !strings.Contains(err.Error(), "instruction budget") || result.Instructions != 10 {
		t.Fatalf("%+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Run(ctx, bytes.NewReader(valid), Config{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
