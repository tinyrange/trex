package qemu

import (
	"context"
	blockpkg "github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type mediaReadCounter struct {
	blockpkg.Device
	bytes atomic.Int64
}

func (d *mediaReadCounter) ReadAt(p []byte, off int64) (int, error) {
	n, err := d.Device.ReadAt(p, off)
	d.bytes.Add(int64(n))
	return n, err
}
func bootMedia(t *testing.T, tag byte) *mediaReadCounter {
	t.Helper()
	data := make([]byte, 1440<<10)
	// In-memory 16-bit boot sector: write a distinguishing byte to COM1, halt.
	copy(data, []byte{0xba, 0xf8, 0x03, 0xb0, tag, 0xee, 0xfa, 0xf4, 0xeb, 0xfd})
	data[510], data[511] = 0x55, 0xaa
	disk, err := blockpkg.NewFileDevice(&starfile.Bytes{Name: "opaque-profiled-media", Data: data}, blockpkg.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return &mediaReadCounter{Device: disk}
}
func TestMediaReplacementUsesSuppliedSourceAndClosesExports(t *testing.T) {
	qemuAvailable(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first := bootMedia(t, 'A')
	backend := &qemuBackend{machine: "pc", accelerator: "tcg", displayFrontend: "none", blockTransport: "nbd", overlayLimit: 4 << 20, stderrLimit: 1 << 20, capabilities: qemuCapabilities()}
	machine := vmmapi.Machine{Architecture: "i386", Memory: 16 << 20, CPUs: 1, Disks: []vmmapi.Disk{{Device: first, Name: "distribution", Bus: "floppy", Media: "floppy", Unit: 0, ReadOnly: true}}, Channels: []vmmapi.Channel{{Kind: "serial", Name: "proof"}}, Display: vmmapi.Display{Mode: "capturable"}}
	raw, err := startQEMU(ctx, backend, machine)
	if err != nil {
		t.Fatal(err)
	}
	d := raw.(*qemuDriver)
	defer d.Close(context.Background())
	serial, err := d.Channel(ctx, "proof")
	if err != nil {
		t.Fatal(err)
	}
	for i, tag := range []byte{'A', 'B', 'C'} {
		source := first
		if i > 0 {
			if err := d.Pause(ctx); err != nil {
				t.Fatal(err)
			}
			source = bootMedia(t, tag)
			if source.bytes.Load() != 0 {
				t.Fatal("source read before replacement")
			}
			if err := d.ReplaceMedia(ctx, "distribution", source); err != nil {
				t.Fatal(err)
			}
			if err := d.Reset(ctx); err != nil {
				t.Fatal(err)
			}
			if err := d.Resume(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var got [1]byte
		if _, err := io.ReadFull(serial, got[:]); err != nil {
			t.Fatal(err)
		}
		if got[0] != tag {
			t.Fatalf("guest read %q, want %q", got[0], tag)
		}
		if n := source.bytes.Load(); n <= 0 || n >= source.Geometry().Size {
			t.Fatalf("source logical reads=%d, want nonzero partial reads", n)
		}
	}
	exports := d.exportSnapshot(false)
	if len(exports) != 3 {
		t.Fatalf("owned exports=%d, want 3", len(exports))
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, e := range exports {
		select {
		case <-e.done:
		default:
			t.Fatal("export survived VM close")
		}
	}
	if err := d.ReplaceMedia(ctx, "distribution", bootMedia(t, 'D')); err == nil {
		t.Fatal("closed VM accepted replacement")
	}
}

func TestMediaRejectsUnsafeTargetsBeforeOpeningExport(t *testing.T) {
	source := testBlockDevice(t, 1440<<10)
	for _, disk := range []vmmapi.Disk{
		{Name: "source", Device: source, Bus: "ide", Media: "disk", ReadOnly: true},
		{Name: "source", Device: source, Bus: "floppy", Media: "floppy"},
		{Name: "source", Device: source, Bus: "floppy", Media: "floppy", ReadOnly: true, Snapshot: true},
	} {
		if _, err := mediaTarget(vmmapi.Machine{Disks: []vmmapi.Disk{disk}}, "source", source); err == nil {
			t.Fatalf("unsafe target accepted: %+v", disk)
		}
	}
	machine := vmmapi.Machine{Disks: []vmmapi.Disk{{Name: "source", Device: source, Bus: "auto", Media: "floppy", ReadOnly: true}}}
	if _, err := mediaTarget(machine, "missing", source); err == nil {
		t.Fatal("unknown target accepted")
	}
	if _, err := mediaTarget(machine, "source", testBlockDevice(t, 720<<10)); err == nil {
		t.Fatal("changed floppy geometry accepted")
	}
	if _, err := mediaTarget(machine, "source", nil); err == nil {
		t.Fatal("nil source accepted")
	}
}
