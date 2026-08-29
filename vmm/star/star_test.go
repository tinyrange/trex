package star

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	blockpkg "github.com/tinyrange/trex/block"
	channelpkg "github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func newStarlarkRuntime(string) (*starlark.Thread, starlark.StringDict, error) {
	thread := &starlark.Thread{Name: "vmm test"}
	lifecycle.Install(thread)
	return thread, nil, nil
}

func testBlockDevice(t *testing.T, size int) *blockpkg.FileDevice {
	t.Helper()
	device, err := blockpkg.NewFileDevice(&starfile.Bytes{Name: "test", Data: make([]byte, size)}, blockpkg.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

type fakeVMMBackend struct {
	id           string
	capabilities []string
	issues       []VMMValidationIssue
	driver       *fakeVMMDriver
	starts       int
}

func (b *fakeVMMBackend) ID() string {
	if b.id != "" {
		return b.id
	}
	return "memory.v1"
}
func (b *fakeVMMBackend) Capabilities() []string                   { return b.capabilities }
func (b *fakeVMMBackend) Validate(VMMMachine) []VMMValidationIssue { return b.issues }
func (b *fakeVMMBackend) Start(_ context.Context, _ VMMMachine) (VMMDriver, error) {
	b.starts++
	if b.driver == nil {
		b.driver = newFakeVMMDriver(b.capabilities)
	}
	return b.driver, nil
}

type fakeVMMBackendValue struct{ backend VMMBackend }

func (v *fakeVMMBackendValue) VMMBackend() VMMBackend { return v.backend }
func (v *fakeVMMBackendValue) String() string         { return "<fake-vmm-backend>" }
func (v *fakeVMMBackendValue) Type() string           { return "vmm_backend" }
func (v *fakeVMMBackendValue) Freeze()                {}
func (v *fakeVMMBackendValue) Truth() starlark.Bool   { return starlark.True }
func (v *fakeVMMBackendValue) Hash() (uint32, error)  { return 0, errors.New("unhashable") }

type memoryByteChannel struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	closed bool
}

func (c *memoryByteChannel) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buffer.Len() == 0 && c.closed {
		return 0, io.EOF
	}
	return c.buffer.Read(p)
}
func (c *memoryByteChannel) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return c.buffer.Write(p)
}
func (c *memoryByteChannel) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

type fakeExtension struct{}

func (fakeExtension) String() string        { return "<memory.v1>" }
func (fakeExtension) Type() string          { return "memory.v1" }
func (fakeExtension) Freeze()               {}
func (fakeExtension) Truth() starlark.Bool  { return starlark.True }
func (fakeExtension) Hash() (uint32, error) { return 1, nil }

type fakeVMMDriver struct {
	mu           sync.Mutex
	state        VMMState
	capabilities []string
	events       chan VMMEvent
	result       chan VMMResult
	inputs       []VMMInput
	closed       int
	detached     bool
}

func newFakeVMMDriver(capabilities []string) *fakeVMMDriver {
	return &fakeVMMDriver{
		state:        VMMState{Name: "paused", Running: false},
		capabilities: capabilities,
		events:       make(chan VMMEvent, 8),
		result:       make(chan VMMResult, 1),
	}
}
func (d *fakeVMMDriver) BackendID() string      { return "memory.v1" }
func (d *fakeVMMDriver) Capabilities() []string { return d.capabilities }
func (d *fakeVMMDriver) Status(context.Context) (VMMState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state, nil
}
func (d *fakeVMMDriver) Wait(ctx context.Context) (VMMResult, error) {
	select {
	case result := <-d.result:
		return result, nil
	case <-ctx.Done():
		return VMMResult{}, ctx.Err()
	}
}
func (d *fakeVMMDriver) NextEvent(ctx context.Context) (VMMEvent, error) {
	select {
	case event := <-d.events:
		return event, nil
	case <-ctx.Done():
		return VMMEvent{}, ctx.Err()
	}
}
func (d *fakeVMMDriver) Close(context.Context) error {
	d.mu.Lock()
	d.closed++
	d.state = VMMState{Name: "stopped"}
	d.mu.Unlock()
	return nil
}
func (d *fakeVMMDriver) Resume(context.Context) error {
	d.mu.Lock()
	d.state = VMMState{Name: "running", Running: true}
	d.mu.Unlock()
	return nil
}
func (d *fakeVMMDriver) Pause(context.Context) error {
	d.mu.Lock()
	d.state = VMMState{Name: "paused"}
	d.mu.Unlock()
	return nil
}
func (d *fakeVMMDriver) Reset(context.Context) error     { return nil }
func (d *fakeVMMDriver) Powerdown(context.Context) error { return nil }
func (d *fakeVMMDriver) Stop(context.Context) error {
	d.mu.Lock()
	d.state = VMMState{Name: "stopped"}
	d.mu.Unlock()
	return nil
}
func (d *fakeVMMDriver) Channel(context.Context, string) (channelpkg.ByteChannel, error) {
	return &memoryByteChannel{}, nil
}
func (d *fakeVMMDriver) Debugger(context.Context, string, bool, bool) (channelpkg.ByteChannel, error) {
	return &memoryByteChannel{}, nil
}
func (d *fakeVMMDriver) Input(_ context.Context, input VMMInput) error {
	d.mu.Lock()
	d.inputs = append(d.inputs, input)
	d.mu.Unlock()
	return nil
}
func (d *fakeVMMDriver) Screenshot(context.Context, string) (starfile.File, error) {
	return &starfile.Bytes{Name: "fake.png", Data: []byte("png")}, nil
}
func (d *fakeVMMDriver) Extension(_ context.Context, name string) (starlark.Value, error) {
	if name != "memory.v1" {
		return nil, unsupportedVMM("extension " + name)
	}
	return fakeExtension{}, nil
}
func (d *fakeVMMDriver) Detach(context.Context) error {
	d.mu.Lock()
	d.detached = true
	d.mu.Unlock()
	return nil
}

func fullFakeCapabilities() []string {
	return []string{
		"channel.serial", "debugger.gdb", "disk", "disk.bus.ide", "disk.snapshot",
		"display.capturable", "display.interactive", "extension.memory.v1", "input.key",
		"input.pointer", "input.text", "lifecycle.pause", "network.nat", "screenshot",
	}
}

func testVMMMachine(t *testing.T) VMMMachine {
	t.Helper()
	return VMMMachine{
		Architecture: "i386",
		Memory:       64 << 20,
		CPUs:         1,
		Disks: []VMMDisk{{
			Device: testBlockDevice(t, 4096), Name: "system", Bus: "ide", Unit: 0,
			ReadOnly: true, Snapshot: true, Required: true,
		}},
		Networks:    []VMMNetwork{{Kind: "nat", Name: "net0", Required: true}},
		Display:     VMMDisplay{Mode: "interactive", Required: true},
		Channels:    []VMMChannel{{Kind: "serial", Name: "kd", Required: true}},
		StartPaused: true,
	}
}

func TestVMMSnapshotAcceptsReadOnlyBase(t *testing.T) {
	source := &starfile.Bytes{Name: "base.raw", Data: make([]byte, 4096)}
	value, err := vmmDiskBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{
		{starlark.String("snapshot"), starlark.True},
	})
	if err != nil {
		t.Fatal(err)
	}
	disk := value.(*vmmDiskValue).disk
	if !disk.Snapshot || disk.ReadOnly {
		t.Fatalf("snapshot disk = %#v", disk)
	}
	backend := &fakeVMMBackend{capabilities: []string{"disk", "disk.snapshot"}}
	issues := validateVMM(VMMMachine{
		Architecture: "i386", Memory: 64 << 20, CPUs: 1,
		Disks: []VMMDisk{disk}, Display: VMMDisplay{Mode: "none"},
	}, backend)
	for _, issue := range issues {
		if issue.Code == "disk.read_only" {
			t.Fatalf("snapshot base failed validation: %#v", issues)
		}
	}
}

func TestVMMCDROMIsExplicitReadOnlyMedia(t *testing.T) {
	source := &starfile.Bytes{Name: "install.iso", Data: make([]byte, 4096)}
	value, err := vmmDiskBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{
		{starlark.String("bus"), starlark.String("ide")},
		{starlark.String("media"), starlark.String("cdrom")},
		{starlark.String("read_only"), starlark.True},
	})
	if err != nil {
		t.Fatal(err)
	}
	disk := value.(*vmmDiskValue).disk
	if disk.Media != "cdrom" || !disk.ReadOnly || disk.Snapshot {
		t.Fatalf("CD-ROM disk = %#v", disk)
	}
	if _, err := vmmDiskBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{
		{starlark.String("media"), starlark.String("cdrom")},
		{starlark.String("snapshot"), starlark.True},
	}); err == nil {
		t.Fatal("snapshot CD-ROM unexpectedly accepted")
	}
}

func TestVMMFloppyIsExplicit512ByteMedia(t *testing.T) {
	source := &starfile.Bytes{Name: "boot.img", Data: make([]byte, 1440<<10)}
	value, err := vmmDiskBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{
		{starlark.String("bus"), starlark.String("floppy")},
		{starlark.String("media"), starlark.String("floppy")},
		{starlark.String("snapshot"), starlark.True},
	})
	if err != nil {
		t.Fatal(err)
	}
	disk := value.(*vmmDiskValue).disk
	if disk.Media != "floppy" || disk.Bus != "floppy" || disk.Device.Geometry().LogicalBlockSize != 512 || !disk.Snapshot || disk.ReadOnly {
		t.Fatalf("floppy disk = %#v, geometry = %#v", disk, disk.Device.Geometry())
	}
}

func TestVMMDiskAcceptsPortableLegacyCHSGeometry(t *testing.T) {
	source := &starfile.Bytes{Name: "dos.raw", Data: make([]byte, 32<<20)}
	value, err := vmmDiskBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{
		{starlark.String("bus"), starlark.String("ide")},
		{starlark.String("chs"), starlark.Tuple{starlark.MakeInt(66), starlark.MakeInt(16), starlark.MakeInt(63)}},
		{starlark.String("snapshot"), starlark.True},
	})
	if err != nil {
		t.Fatal(err)
	}
	disk := value.(*vmmDiskValue).disk
	if disk.CHS == nil || disk.CHS.Cylinders != 66 || disk.CHS.Heads != 16 || disk.CHS.Sectors != 63 {
		t.Fatalf("CHS geometry = %#v", disk.CHS)
	}
	backend := &fakeVMMBackend{capabilities: []string{"disk", "disk.bus.ide", "disk.geometry.chs", "disk.snapshot"}}
	issues := validateVMM(VMMMachine{
		Architecture: "i386", Memory: 16 << 20, CPUs: 1,
		Disks: []VMMDisk{disk}, Display: VMMDisplay{Mode: "none"},
	}, backend)
	if len(issues) != 0 {
		t.Fatalf("valid CHS issues = %#v", issues)
	}
}

func TestVMMValidationAggregatesPortableAndBackendIssues(t *testing.T) {
	machine := testVMMMachine(t)
	machine.Memory = 0
	machine.RequiredCapabilities = []string{"feature.missing"}
	backend := &fakeVMMBackend{
		capabilities: []string{"disk"},
		issues:       []VMMValidationIssue{{Code: "memory.limit", Field: "memory", Message: "too large"}},
	}
	issues := validateVMM(machine, backend)
	if len(issues) < 8 {
		t.Fatalf("got %d validation issues, want aggregate incompatibilities: %#v", len(issues), issues)
	}
	want := map[string]bool{"machine.memory": false, "capability.unsupported": false, "memory.limit": false}
	for _, issue := range issues {
		if _, ok := want[issue.Code]; ok {
			want[issue.Code] = true
		}
	}
	for code, found := range want {
		if !found {
			t.Errorf("missing validation issue %q", code)
		}
	}
}

func TestVMMPortableSessionContractAndRuntimeCleanup(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	driver := newFakeVMMDriver(fullFakeCapabilities())
	backend := &fakeVMMBackend{capabilities: fullFakeCapabilities(), driver: driver}
	machine := &vmmMachineValue{machine: testVMMMachine(t)}
	value, err := vmmStartBuiltin(thread, nil, starlark.Tuple{machine}, []starlark.Tuple{{starlark.String("backend"), &fakeVMMBackendValue{backend: backend}}})
	if err != nil {
		t.Fatal(err)
	}
	vm := value.(*vmmSessionValue)
	callVMMethod(t, thread, vm, "resume", nil, nil)
	if running, err := vm.Attr("running"); err != nil || running != starlark.True {
		t.Fatalf("running = %v, %v", running, err)
	}
	callVMMethod(t, thread, vm, "pause", nil, nil)
	callVMMethod(t, thread, vm, "send_text", starlark.Tuple{starlark.String("hello")}, nil)
	callVMMethod(t, thread, vm, "send_keys", starlark.Tuple{starlark.NewList([]starlark.Value{starlark.String("ctrl"), starlark.String("a")})}, nil)
	callVMMethod(t, thread, vm, "tap", starlark.Tuple{starlark.String("enter")}, nil)
	callVMMethod(t, thread, vm, "chord", starlark.Tuple{starlark.NewList([]starlark.Value{starlark.String("control"), starlark.String("alt"), starlark.String("delete")})}, nil)
	callVMMethod(t, thread, vm, "type_and_enter", starlark.Tuple{starlark.String("command")}, nil)
	hasInput := callVMMethod(t, thread, vm, "has_capability", starlark.Tuple{starlark.String("input.key")}, nil)
	if hasInput != starlark.True {
		t.Fatalf("has_capability(input.key) = %v", hasInput)
	}
	callVMMethod(t, thread, vm, "pointer", nil, []starlark.Tuple{{starlark.String("x"), starlark.Float(4)}, {starlark.String("y"), starlark.Float(8)}})
	screenshot := callVMMethod(t, thread, vm, "screenshot", nil, nil)
	if screenshot.(starfile.File).Size() != 3 {
		t.Fatalf("screenshot size = %d", screenshot.(starfile.File).Size())
	}
	extension := callVMMethod(t, thread, vm, "extension", starlark.Tuple{starlark.String("memory.v1")}, nil)
	if extension.Type() != "memory.v1" {
		t.Fatalf("extension type = %s", extension.Type())
	}
	driver.events <- VMMEvent{Kind: "paused", Timestamp: time.Unix(1, 2), Payload: starlark.String("test")}
	event := callVMMethod(t, thread, vm, "next_event", nil, []starlark.Tuple{{starlark.String("timeout"), starlark.Float(1)}})
	if event.Type() != "record" {
		t.Fatalf("event type = %s", event.Type())
	}
	driver.result <- VMMResult{Reason: "stopped", Clean: true, Backend: "memory.v1", Finished: time.Unix(3, 4)}
	firstResult := callVMMethod(t, thread, vm, "wait", nil, []starlark.Tuple{{starlark.String("timeout"), starlark.Float(1)}})
	secondResult := callVMMethod(t, thread, vm, "wait", nil, []starlark.Tuple{{starlark.String("timeout"), starlark.Float(1)}})
	if firstResult.String() != secondResult.String() {
		t.Fatalf("repeated VM result = %v, want %v", secondResult, firstResult)
	}
	if cached, err := vm.Attr("result"); err != nil || cached == starlark.None {
		t.Fatalf("cached VM result = %v, %v", cached, err)
	}
	driver.mu.Lock()
	inputs := append([]VMMInput(nil), driver.inputs...)
	driver.mu.Unlock()
	if len(inputs) != 7 {
		t.Fatalf("portable input count = %d, want 7", len(inputs))
	}
	if inputs[2].Kind != "keys" || len(inputs[2].Keys) != 1 || inputs[2].Keys[0] != "enter" {
		t.Fatalf("tap input = %+v", inputs[2])
	}
	if inputs[5].Kind != "keys" || len(inputs[5].Keys) != 1 || inputs[5].Keys[0] != "enter" {
		t.Fatalf("type-and-enter input = %+v", inputs[5])
	}
	resources, _ := lifecycle.ForThread(thread)
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	if driver.closed != 1 {
		t.Fatalf("driver close count = %d, want 1", driver.closed)
	}
	if backend.starts != 1 {
		t.Fatalf("backend starts = %d, want 1", backend.starts)
	}
}

func TestVMMDetachTransfersRuntimeOwnership(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	driver := newFakeVMMDriver(fullFakeCapabilities())
	backend := &fakeVMMBackend{capabilities: fullFakeCapabilities(), driver: driver}
	value, err := vmmStartBuiltin(thread, nil, starlark.Tuple{&vmmMachineValue{machine: testVMMMachine(t)}}, []starlark.Tuple{{starlark.String("backend"), &fakeVMMBackendValue{backend: backend}}})
	if err != nil {
		t.Fatal(err)
	}
	vm := value.(*vmmSessionValue)
	callVMMethod(t, thread, vm, "detach", nil, nil)
	resources, _ := lifecycle.ForThread(thread)
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	if driver.closed != 0 || !driver.detached {
		t.Fatalf("detached driver: closed=%d detached=%v", driver.closed, driver.detached)
	}
}

func TestTwoIndependentVMGraphs(t *testing.T) {
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			thread, _, err := newStarlarkRuntime("-")
			if err != nil {
				results <- err
				return
			}
			driver := newFakeVMMDriver(fullFakeCapabilities())
			backend := &fakeVMMBackend{capabilities: fullFakeCapabilities(), driver: driver}
			value, err := vmmStartBuiltin(thread, nil, starlark.Tuple{&vmmMachineValue{machine: testVMMMachine(t)}}, []starlark.Tuple{{starlark.String("backend"), &fakeVMMBackendValue{backend: backend}}})
			if err == nil {
				vm := value.(*vmmSessionValue)
				_, err = vm.controlBuiltin("resume")(thread, nil, nil, nil)
				if err == nil {
					_, err = vm.controlBuiltin("pause")(thread, nil, nil, nil)
				}
			}
			resources, resourcesErr := lifecycle.ForThread(thread)
			if resourcesErr == nil {
				resourcesErr = resources.Close()
			}
			results <- errors.Join(err, resourcesErr)
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

func TestVMMUnsupportedOperationHasStableCode(t *testing.T) {
	driver := &minimalVMMDriver{}
	vm := newVMMSession(VMMMachine{}, &fakeVMMBackend{}, driver)
	method, _ := vm.Attr("resume")
	_, err := starlark.Call(&starlark.Thread{Name: "test"}, method.(starlark.Callable), nil, nil)
	var vmmErr *VMMError
	if !errors.As(err, &vmmErr) || vmmErr.Code != VMMErrorUnsupported {
		t.Fatalf("resume error = %v, want unsupported VMMError", err)
	}
}

func TestPortableSessionDoesNotRequireQEMUCapabilities(t *testing.T) {
	for _, test := range []struct {
		id           string
		capabilities []string
	}{
		{id: "portable-a.v1", capabilities: []string{"lifecycle.pause"}},
		{id: "portable-b.v1", capabilities: []string{"display.capturable", "screenshot"}},
	} {
		t.Run(test.id, func(t *testing.T) {
			thread, _, err := newStarlarkRuntime("-")
			if err != nil {
				t.Fatal(err)
			}
			driver := newFakeVMMDriver(test.capabilities)
			backend := &fakeVMMBackend{id: test.id, capabilities: test.capabilities, driver: driver}
			machine := &vmmMachineValue{machine: VMMMachine{
				Architecture: "i386", Memory: 32 << 20, CPUs: 1, Display: VMMDisplay{Mode: "none"},
			}}
			value, err := vmmStartBuiltin(thread, nil, starlark.Tuple{machine}, []starlark.Tuple{{starlark.String("backend"), &fakeVMMBackendValue{backend: backend}}})
			if err != nil {
				t.Fatal(err)
			}
			vm := value.(*vmmSessionValue)
			if vm.Type() != "vm" {
				t.Fatalf("portable session type = %s", vm.Type())
			}
			if _, err := vm.VMMExtension("qemu.v1"); err == nil {
				t.Fatal("non-QEMU backend exposed qemu.v1")
			} else {
				var vmmErr *VMMError
				if !errors.As(err, &vmmErr) || vmmErr.Code != VMMErrorUnsupported {
					t.Fatalf("qemu.v1 error = %v", err)
				}
			}
			resources, _ := lifecycle.ForThread(thread)
			if err := resources.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type minimalVMMDriver struct{}

func (*minimalVMMDriver) BackendID() string      { return "minimal.v1" }
func (*minimalVMMDriver) Capabilities() []string { return nil }
func (*minimalVMMDriver) Status(context.Context) (VMMState, error) {
	return VMMState{Name: "running", Running: true}, nil
}
func (*minimalVMMDriver) Wait(context.Context) (VMMResult, error)     { return VMMResult{}, nil }
func (*minimalVMMDriver) NextEvent(context.Context) (VMMEvent, error) { return VMMEvent{}, nil }
func (*minimalVMMDriver) Close(context.Context) error                 { return nil }

func callVMMethod(t *testing.T, thread *starlark.Thread, vm *vmmSessionValue, name string, args starlark.Tuple, kwargs []starlark.Tuple) starlark.Value {
	t.Helper()
	method, err := vm.Attr(name)
	if err != nil {
		t.Fatal(err)
	}
	value, err := starlark.Call(thread, method.(starlark.Callable), args, kwargs)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return value
}
