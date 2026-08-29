package qemu

import (
	"context"
	"io"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	blockpkg "github.com/tinyrange/trex/block"
	nbdapi "github.com/tinyrange/trex/block/nbd"
	blockstar "github.com/tinyrange/trex/block/star"
	channelstar "github.com/tinyrange/trex/channel/star"
	debugapi "github.com/tinyrange/trex/debug"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func newStarlarkRuntime(string) (*starlark.Thread, starlark.StringDict, error) {
	thread := &starlark.Thread{Name: "qemu test"}
	lifecycle.Install(thread)
	return thread, nil, nil
}

func testBlockDevice(t *testing.T, size int) *blockpkg.FileDevice {
	t.Helper()
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(index * 31)
	}
	device, err := blockpkg.NewFileDevice(&starfile.Bytes{Name: "block-test", Data: data}, blockpkg.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

type sparseCountingBlock struct {
	size      int64
	reads     atomic.Uint64
	readBytes atomic.Uint64
	maxRead   atomic.Uint64
}

func (d *sparseCountingBlock) ReadAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset+int64(len(data)) > d.size {
		return 0, io.EOF
	}
	clear(data)
	d.reads.Add(1)
	d.readBytes.Add(uint64(len(data)))
	for current := d.maxRead.Load(); uint64(len(data)) > current && !d.maxRead.CompareAndSwap(current, uint64(len(data))); current = d.maxRead.Load() {
	}
	return len(data), nil
}
func (d *sparseCountingBlock) Geometry() blockpkg.Geometry {
	return blockpkg.Geometry{Size: d.size, LogicalBlockSize: 512, PhysicalBlockSize: 4096, MinimumTransfer: 1, PreferredTransfer: 64 << 10, MaximumTransfer: nbdapi.DefaultMaxRequest}
}
func (d *sparseCountingBlock) Capabilities() blockpkg.Capabilities {
	return blockpkg.Capabilities{Concurrent: true}
}

func qemuAvailable(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("QEMU integration test")
	}
	if _, err := exec.LookPath("qemu-system-i386"); err != nil {
		t.Skip("qemu-system-i386 is not installed")
	}
}

func TestQEMUOptionAcceptsStructuredDebugEventLists(t *testing.T) {
	value, err := qemuOptionBuiltin(nil, nil, starlark.Tuple{
		starlark.String("-d"),
		starlark.NewList([]starlark.Value{starlark.String("int"), starlark.String("cpu_reset")}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	option := value.(*qemuSpecValue)
	if len(option.properties) != 1 || option.properties[0].value != "int,cpu_reset" {
		t.Fatalf("debug option = %#v", option.properties)
	}
	if _, err := qemuOptionBuiltin(nil, nil, starlark.Tuple{
		starlark.String("-d"),
		starlark.NewList([]starlark.Value{starlark.String("int,cpu_reset")}),
	}, nil); err == nil {
		t.Fatal("debug event containing a QEMU separator was accepted")
	}
	if _, err := qemuOptionBuiltin(nil, nil, starlark.Tuple{
		starlark.String("-cpu"),
		starlark.NewList([]starlark.Value{starlark.String("host")}),
	}, nil); err == nil {
		t.Fatal("a generic QEMU option accepted a list value")
	}
}

func TestQEMUPointerEventsTrackButtonState(t *testing.T) {
	events, pressed := qemuPointerEvents(vmmapi.Input{
		Kind: "pointer", X: 12, Y: -4, Buttons: []string{"left", "left"},
	}, nil)
	if len(events) != 3 || !pressed["left"] {
		t.Fatalf("press events = %#v, state = %#v", events, pressed)
	}
	assertQEMUButtonEvent(t, events[2], "left", true)

	events, pressed = qemuPointerEvents(vmmapi.Input{Kind: "pointer"}, pressed)
	if len(events) != 3 || len(pressed) != 0 {
		t.Fatalf("release events = %#v, state = %#v", events, pressed)
	}
	assertQEMUButtonEvent(t, events[2], "left", false)

	events, _ = qemuPointerEvents(vmmapi.Input{Kind: "pointer", Wheel: 1}, nil)
	if len(events) != 4 {
		t.Fatalf("wheel events = %#v", events)
	}
	assertQEMUButtonEvent(t, events[2], "wheel-up", true)
	assertQEMUButtonEvent(t, events[3], "wheel-up", false)
}

func TestQEMUTextEventsAreExplicitAndOrdered(t *testing.T) {
	events, err := qemuTextEvents("aA!")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		key  string
		down bool
	}{
		{"a", true}, {"a", false},
		{"shift", true}, {"a", true}, {"a", false}, {"shift", false},
		{"shift", true}, {"1", true}, {"1", false}, {"shift", false},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %#v", events)
	}
	for index, expected := range want {
		assertQEMUKeyEvent(t, events[index], expected.key, expected.down)
	}
}

func TestQEMUKeyCodeMapsPortableNames(t *testing.T) {
	tests := map[string]string{
		"control":   "ctrl",
		"enter":     "ret",
		"escape":    "esc",
		"page_down": "pgdn",
		"page_up":   "pgup",
		"delete":    "delete",
	}
	for input, want := range tests {
		if got := qemuKeyCode(input); got != want {
			t.Fatalf("qemuKeyCode(%q) = %q, want %q", input, got, want)
		}
	}
}

func assertQEMUButtonEvent(t *testing.T, raw any, button string, down bool) {
	t.Helper()
	event, ok := raw.(map[string]any)
	if !ok || event["type"] != "btn" {
		t.Fatalf("event = %#v, want button event", raw)
	}
	data, ok := event["data"].(map[string]any)
	if !ok || data["button"] != button || data["down"] != down {
		t.Fatalf("button event = %#v, want button=%q down=%v", raw, button, down)
	}
}

func assertQEMUKeyEvent(t *testing.T, raw any, key string, down bool) {
	t.Helper()
	event, ok := raw.(map[string]any)
	if !ok || event["type"] != "key" {
		t.Fatalf("event = %#v, want key event", raw)
	}
	data, ok := event["data"].(map[string]any)
	if !ok || data["down"] != down {
		t.Fatalf("key event = %#v, want down=%v", raw, down)
	}
	value, ok := data["key"].(map[string]any)
	if !ok || value["type"] != "qcode" || value["data"] != key {
		t.Fatalf("key event = %#v, want key=%q", raw, key)
	}
}

func TestQEMUBackendStartsOpaqueDiskOverNBD(t *testing.T) {
	qemuAvailable(t)
	backend := &qemuBackend{
		machine: "pc", accelerator: "tcg", displayFrontend: "none", blockTransport: "nbd",
		overlayLimit: 4 << 20, stderrLimit: 1 << 20, capabilities: qemuCapabilities(),
	}
	machine := vmmapi.Machine{
		Architecture: "i386", Memory: 32 << 20, CPUs: 1,
		Disks:   []vmmapi.Disk{{Device: testBlockDevice(t, 1<<20), Name: "test", Bus: "ide", Unit: 0, Snapshot: true, Required: true}},
		Display: vmmapi.Display{Mode: "capturable", Required: true}, StartPaused: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	driverValue, err := startQEMU(ctx, backend, machine)
	if err != nil {
		t.Fatal(err)
	}
	driver := driverValue.(*qemuDriver)
	overlay, ok := driver.exports[0].server.Device().(*blockstar.OverlayDevice)
	if !ok {
		_ = driver.Close(ctx)
		t.Fatalf("snapshot export device = %T, want overlay", driver.exports[0].server.Device())
	}
	if _, ok := overlay.Base().(*blockstar.CachedDevice); !ok {
		_ = driver.Close(ctx)
		t.Fatalf("snapshot overlay base = %T, want bounded read cache", overlay.Base())
	}
	state, err := driver.Status(ctx)
	if err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	if state.Running {
		t.Fatalf("paused VM reported running: %#v", state)
	}
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	gdbChannel, err := driver.Debugger(ctx, "gdb", true, false)
	if err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	gdbValue, err := debugapi.GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb", gdbChannel)}, nil)
	if err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	gdb := gdbValue.(*debugapi.Session)
	registersMethod, _ := gdb.Attr("registers")
	registersValue, err := starlark.Call(thread, registersMethod.(starlark.Callable), nil, nil)
	if err != nil {
		_ = gdb.Close()
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	if registersValue.(*starlark.Dict).Len() < 10 || gdb.Architecture() == "" {
		t.Fatalf("GDB target description is incomplete: architecture=%q registers=%d", gdb.Architecture(), registersValue.(*starlark.Dict).Len())
	}
	continueMethod, _ := gdb.Attr("continue")
	if _, err := starlark.Call(thread, continueMethod.(starlark.Callable), nil, nil); err != nil {
		_ = gdb.Close()
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	interruptMethod, _ := gdb.Attr("interrupt")
	if _, err := starlark.Call(thread, interruptMethod.(starlark.Callable), nil, nil); err != nil {
		_ = gdb.Close()
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	waitMethod, _ := gdb.Attr("wait")
	stop, err := starlark.Call(thread, waitMethod.(starlark.Callable), nil, []starlark.Tuple{{starlark.String("timeout"), starlark.Float(5)}})
	if err != nil {
		_ = gdb.Close()
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	if stop.Type() != "record" {
		t.Fatalf("GDB stop type = %s", stop.Type())
	}
	if err := gdb.Close(); err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	if err := driver.Input(ctx, vmmapi.Input{Kind: "keys", Keys: []string{"ctrl", "alt", "delete"}}); err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	screenshot, err := driver.Screenshot(ctx, "png")
	if err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	magic := make([]byte, 8)
	if _, err := screenshot.ReadAt(magic, 0); err != nil || string(magic) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("screenshot is not PNG: %x, %v", magic, err)
	}
	if err := driver.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-driver.done:
	case <-ctx.Done():
		t.Fatal("QEMU did not exit")
	}
}

func TestQEMUBackendValidatesCDROMMedia(t *testing.T) {
	backend := &qemuBackend{}
	device, err := blockpkg.NewFileDevice(&starfile.Bytes{Name: "install.iso", Data: make([]byte, 1<<20)}, blockpkg.FileDeviceOptions{LogicalBlockSize: 2048, PhysicalBlockSize: 2048})
	if err != nil {
		t.Fatal(err)
	}
	valid := vmmapi.Machine{Architecture: "i386", Disks: []vmmapi.Disk{{
		Device: device, Bus: "ide", Media: "cdrom", ReadOnly: true,
	}}}
	if issues := backend.Validate(valid); len(issues) != 0 {
		t.Fatalf("valid CD-ROM issues = %#v", issues)
	}
	invalid := valid
	invalid.Disks[0].Bus = "virtio"
	invalid.Disks[0].ReadOnly = false
	invalid.Disks[0].Device = testBlockDevice(t, 1<<20)
	issues := backend.Validate(invalid)
	codes := map[string]bool{}
	for _, issue := range issues {
		codes[issue.Code] = true
	}
	if !codes["qemu.cdrom_bus"] || !codes["qemu.cdrom_block_size"] || !codes["qemu.cdrom_mode"] {
		t.Fatalf("invalid CD-ROM issues = %#v", issues)
	}
}

func TestQEMUBackendValidatesFloppyMedia(t *testing.T) {
	backend := &qemuBackend{}
	valid := vmmapi.Machine{Architecture: "i386", Disks: []vmmapi.Disk{{
		Device: testBlockDevice(t, 1440<<10), Bus: "floppy", Media: "floppy", Unit: 0, Snapshot: true,
	}}}
	if issues := backend.Validate(valid); len(issues) != 0 {
		t.Fatalf("valid floppy issues = %#v", issues)
	}
	invalid := valid
	invalid.Disks[0].Bus = "virtio"
	invalid.Disks[0].Unit = 2
	issues := backend.Validate(invalid)
	codes := map[string]bool{}
	for _, issue := range issues {
		codes[issue.Code] = true
	}
	if !codes["qemu.floppy_bus"] || !codes["qemu.floppy_unit"] {
		t.Fatalf("invalid floppy issues = %#v", issues)
	}
}

func TestQEMUBackendValidatesLegacyCHSGeometry(t *testing.T) {
	backend := &qemuBackend{}
	valid := vmmapi.Machine{Architecture: "i386", Disks: []vmmapi.Disk{{
		Device: testBlockDevice(t, 32<<20), Bus: "ide", Media: "disk", CHS: &vmmapi.CHSGeometry{Cylinders: 66, Heads: 16, Sectors: 63}, Snapshot: true,
	}}}
	if issues := backend.Validate(valid); len(issues) != 0 {
		t.Fatalf("valid CHS issues = %#v", issues)
	}
	invalid := valid
	invalid.Disks[0].Bus = "virtio"
	issues := backend.Validate(invalid)
	if len(issues) != 1 || issues[0].Code != "qemu.chs_bus" {
		t.Fatalf("invalid CHS issues = %#v", issues)
	}
}

func TestQEMULaunchFailureReleasesOwnedTransports(t *testing.T) {
	backend := &qemuBackend{
		binary: "/missing/trex-qemu", machine: "pc", accelerator: "tcg",
		displayFrontend: "none", blockTransport: "nbd", overlayLimit: 4 << 20,
		stderrLimit: 1 << 20, capabilities: qemuCapabilities(),
	}
	machine := vmmapi.Machine{
		Architecture: "i386", Memory: 32 << 20, CPUs: 1,
		Disks:   []vmmapi.Disk{{Device: &sparseCountingBlock{size: 1 << 20}, Name: "test", Bus: "ide", Snapshot: true}},
		Display: vmmapi.Display{Mode: "none"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := startQEMU(ctx, backend, machine); err == nil {
		t.Fatal("missing QEMU binary unexpectedly started")
	}
	// A second one-shot loopback export must be able to start immediately;
	// cleanup of the failed launch cannot leave an accepted/listening channel.
	export, _, err := newQEMUNBDExport(ctx, machine.Disks[0].Device, "probe")
	if err != nil {
		t.Fatal(err)
	}
	export.Close()
	select {
	case <-export.done:
	case <-time.After(time.Second):
		t.Fatal("closed QEMU NBD export left its accept loop running")
	}
}

func TestQEMUProcessCleanupWaitsForNBDLeaseRelease(t *testing.T) {
	base := testBlockDevice(t, 1<<20)
	overlay, err := blockstar.NewOverlayDevice(base, 1<<20, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	export, port, err := newQEMUNBDExport(ctx, overlay, "cleanup-test")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		cancel()
		export.Close()
		t.Fatal(err)
	}
	defer connection.Close()

	deadline := time.Now().Add(time.Second)
	for {
		if overlay.LeaseCount() == 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			export.Close()
			t.Fatal("NBD export did not acquire its overlay lease")
		}
		time.Sleep(time.Millisecond)
	}

	driver := &qemuDriver{ctx: ctx, cancel: cancel, exports: []*qemuNBDExport{export}}
	driver.releaseTransports()
	if _, err := overlay.Commit(); err != nil {
		t.Fatalf("commit after QEMU transport cleanup: %v", err)
	}
}

func TestQEMUExportNamesAreOpaqueAndUnique(t *testing.T) {
	left, err := qemuExportName(0)
	if err != nil {
		t.Fatal(err)
	}
	right, err := qemuExportName(0)
	if err != nil {
		t.Fatal(err)
	}
	if left == right || left == "trx-disk-0" || right == "trx-disk-0" {
		t.Fatalf("QEMU NBD export credentials are not unique: %q %q", left, right)
	}
}

func TestQEMUConfiguredAudioDeviceIsStructured(t *testing.T) {
	backend := &qemuBackend{audiodevs: []*qemuSpecValue{{
		kind: "audiodev", name: "pipewire",
		properties: []qemuProperty{{name: "id", value: "audio0"}},
	}}}
	args := qemuConfiguredArgs(backend)
	if len(args) != 2 || args[0] != "-audiodev" || args[1] != "pipewire,id=audio0" {
		t.Fatalf("configured args = %q", args)
	}
}

func TestQEMUNBDStartsLargeDiskWithoutMaterializingIt(t *testing.T) {
	qemuAvailable(t)
	device := &sparseCountingBlock{size: 3 << 30}
	backend := &qemuBackend{
		machine: "pc", accelerator: "tcg", displayFrontend: "none", blockTransport: "nbd",
		overlayLimit: 4 << 20, stderrLimit: 1 << 20, capabilities: qemuCapabilities(),
	}
	machine := vmmapi.Machine{
		Architecture: "i386", Memory: 32 << 20, CPUs: 1,
		Disks:   []vmmapi.Disk{{Device: device, Name: "large", Bus: "ide", Snapshot: true, Required: true}},
		Display: vmmapi.Display{Mode: "none"}, StartPaused: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	value, err := startQEMU(ctx, backend, machine)
	if err != nil {
		t.Fatal(err)
	}
	driver := value.(*qemuDriver)
	if got := device.readBytes.Load(); got >= uint64(device.size) {
		_ = driver.Close(ctx)
		t.Fatalf("QEMU eagerly read %d-byte disk", got)
	}
	if err := driver.Resume(ctx); err != nil {
		_ = driver.Close(ctx)
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	statsValue, err := (&qemuExtensionValue{driver: driver}).blockStatsBuiltin(nil, nil, nil, nil)
	if err != nil || statsValue.(*starlark.List).Len() != 1 {
		_ = driver.Close(ctx)
		t.Fatalf("QEMU block stats = %v, %v", statsValue, err)
	}
	if err := driver.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := device.readBytes.Load(); got > 64<<20 {
		t.Fatalf("short boot read %d bytes from sparse 3 GiB disk", got)
	}
	if got := device.maxRead.Load(); got > nbdapi.DefaultMaxRequest {
		t.Fatalf("single read %d exceeds NBD request bound", got)
	}
}

func TestTwoConcurrentQEMUSessions(t *testing.T) {
	qemuAvailable(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			backend := &qemuBackend{
				machine: "pc", accelerator: "tcg", displayFrontend: "none", blockTransport: "nbd",
				overlayLimit: 4 << 20, stderrLimit: 1 << 20, capabilities: qemuCapabilities(),
			}
			machine := vmmapi.Machine{
				Architecture: "i386", Memory: 32 << 20, CPUs: 1,
				Disks:   []vmmapi.Disk{{Device: &sparseCountingBlock{size: 1 << 20}, Name: "test", Bus: "ide", Snapshot: true, Required: true}},
				Display: vmmapi.Display{Mode: "none"}, StartPaused: true,
			}
			value, err := startQEMU(ctx, backend, machine)
			if err == nil {
				driver := value.(*qemuDriver)
				thread, _, runtimeErr := newStarlarkRuntime("-")
				if runtimeErr != nil {
					err = runtimeErr
				} else {
					channel, debugErr := driver.Debugger(ctx, "gdb", true, false)
					if debugErr == nil {
						var gdbValue starlark.Value
						gdbValue, debugErr = debugapi.GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb", channel)}, nil)
						if debugErr == nil {
							gdb := gdbValue.(*debugapi.Session)
							method, _ := gdb.Attr("registers")
							_, debugErr = starlark.Call(thread, method.(starlark.Callable), nil, nil)
							_ = gdb.Close()
						}
					}
					err = debugErr
					resources, resourcesErr := lifecycle.ForThread(thread)
					if resourcesErr == nil {
						resourcesErr = resources.Close()
					}
					if err == nil {
						err = resourcesErr
					}
				}
				closeErr := driver.Close(ctx)
				if err == nil {
					err = closeErr
				}
			}
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
}
