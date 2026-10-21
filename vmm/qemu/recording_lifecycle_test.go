package qemu

import (
	"context"
	vmmapi "github.com/tinyrange/trex/vmm"
	"strings"
	"testing"
	"time"
)

// Exercise the real paused QEMU/FFmpeg ownership boundary, including capture
// contention. No copyrighted guest media is needed to record a BIOS surface.
func TestRecordingQEMUOwnership(t *testing.T) {
	qemuAvailable(t)
	requireFFmpeg(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backend := &qemuBackend{machine: "pc", accelerator: "tcg", displayFrontend: "none", blockTransport: "nbd", overlayLimit: 4 << 20, stderrLimit: 1 << 20, capabilities: qemuCapabilities()}
	dv, err := startQEMU(ctx, backend, vmmapi.Machine{Architecture: "i386", Memory: 16 << 20, CPUs: 1, Display: vmmapi.Display{Mode: "capturable", Required: true}, StartPaused: true})
	if err != nil {
		t.Fatal(err)
	}
	d := dv.(*qemuDriver)
	defer d.Close(ctx)
	options := recordingTestOptions()
	options.Duration = 10 * time.Second
	r, err := d.Record(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	state, err := d.Status(ctx)
	if err != nil || state.Running {
		t.Fatal("recording resumed guest", state, err)
	}
	if _, err = d.Record(ctx, options); err == nil {
		t.Fatal("concurrent recorder accepted")
	}
	if err = d.Detach(ctx); err == nil {
		t.Fatal("active recording detached")
	}
	if err = d.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Screenshot(ctx, "png"); err != nil {
		t.Fatal("concurrent screenshot", err)
	}
	f, err := r.Stop(ctx)
	if err != nil || f.Size() == 0 {
		t.Fatal("finalization", err)
	}
	second, err := d.Record(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !second.Stats().Done {
		t.Fatal("VM close did not join recorder")
	}
	if _, err = second.Stop(ctx); err == nil || !strings.Contains(err.Error(), "discarded") {
		t.Fatal("VM teardown did not discard recording", err)
	}
	// The previously returned portable file survives VM teardown.
	if f.Size() == 0 {
		t.Fatal("returned artifact invalidated")
	}
}
