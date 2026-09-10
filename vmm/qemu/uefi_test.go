package qemu

import (
	"context"
	"os/exec"
	"testing"
	"time"

	vmmapi "github.com/tinyrange/trex/vmm"
)

func TestQEMUUEFIFirmwareStarts(t *testing.T) {
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Skip("QEMU x86_64 is unavailable")
	}
	firmware, err := qemuUEFIFirmware("x86_64", "")
	if err != nil {
		t.Skipf("UEFI firmware is unavailable: %v", err)
	}
	info, err := firmware.Stat()
	firmware.Close()
	if err != nil {
		t.Fatal(err)
	}
	if size := info.Size(); size < 1<<20 || size&(size-1) != 0 {
		t.Fatalf("firmware flash size = %d", size)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backend := &qemuBackend{
		machine: "pc", accelerator: "tcg", firmware: "uefi", displayFrontend: "none",
		blockTransport: "nbd", overlayLimit: 4 << 20, stderrLimit: 1 << 20,
		capabilities: qemuCapabilities(),
	}
	driver, err := startQEMU(ctx, backend, vmmapi.Machine{
		Architecture: "x86_64", Memory: 256 << 20, CPUs: 1, StartPaused: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close(context.Background())
	if err := driver.(*qemuDriver).Resume(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := driver.Status(ctx)
	if err != nil || !status.Running {
		t.Fatalf("UEFI emulator state = %+v, error = %v", status, err)
	}
}
