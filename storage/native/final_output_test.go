package native

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

func TestFinalOutputSurvivesExecutionWithBoundedDurableBlockWrites(t *testing.T) {
	name := filepath.Join(t.TempDir(), "control.raw")
	thread := &starlark.Thread{}
	resources := lifecycle.Install(thread)
	t.Cleanup(func() { _ = resources.Close() })
	const size = 8 << 20
	value, err := createOutputBuiltin(thread, nil, starlark.Tuple{starlark.String(name), starlark.MakeInt(size)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	output := value.(*finalOutput)
	disk, err := block.NewFileDevice(output, block.FileDeviceOptions{Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	if !disk.Capabilities().Flush || !disk.Capabilities().Durable {
		t.Fatal("durability not propagated")
	}
	if _, err := disk.WriteAt([]byte("MBR"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := disk.WriteAt([]byte("END"), size-3); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{-1, size - 1, size + 1} {
		if _, err := output.WriteAt([]byte("BAD"), off); err == nil {
			t.Fatalf("accepted out-of-range %d", off)
		}
	}
	if err := disk.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal("final artifact removed:", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != size {
		t.Fatalf("fixed logical size: %v %v", info, err)
	}
	for _, sample := range []struct {
		off  int64
		want []byte
	}{{0, []byte("MBR")}, {4096, make([]byte, 512)}, {size - 3, []byte("END")}} {
		got := make([]byte, len(sample.want))
		if _, err := file.ReadAt(got, sample.off); err != nil || !bytes.Equal(got, sample.want) {
			t.Fatalf("reopened data at %d: %q %v", sample.off, got, err)
		}
	}
}

func TestFinalOutputNeverOverwritesInputsOrOpensAfterCancellation(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "original")
	if err := os.WriteFile(name, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	thread := &starlark.Thread{}
	resources := lifecycle.Install(thread)
	if _, err := createOutputBuiltin(thread, nil, starlark.Tuple{starlark.String(name), starlark.MakeInt(4096)}, nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing input: %v", err)
	}
	got, err := os.ReadFile(name)
	if err != nil || string(got) != "preserve" {
		t.Fatalf("input changed: %q %v", got, err)
	}
	input, err := openBuiltin(thread, nil, starlark.Tuple{starlark.String(name)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.(File).WriteAt([]byte("BAD"), 0); err == nil {
		t.Fatal("ordinary open became writable")
	}
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	canceled := filepath.Join(dir, "must-not-exist")
	if _, err := createOutputBuiltin(thread, nil, starlark.Tuple{starlark.String(canceled), starlark.MakeInt(4096)}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled output creation: %v", err)
	}
	if _, err := os.Stat(canceled); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled execution created output: %v", err)
	}
	for _, size := range []int64{0, -1, defaultFinalOutputLimit + 1} {
		if _, err := createOutputBuiltin(&starlark.Thread{}, nil, starlark.Tuple{starlark.String(canceled), starlark.MakeInt64(size)}, nil); err == nil {
			t.Fatalf("invalid size %d", size)
		}
	}
}
