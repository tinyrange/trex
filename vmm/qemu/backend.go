package qemu

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	blockpkg "github.com/tinyrange/trex/block"
	nbdapi "github.com/tinyrange/trex/block/nbd"
	blockstar "github.com/tinyrange/trex/block/star"
	channelpkg "github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
)

type boundedBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(p)
	if len(p) >= b.limit {
		b.data = append(b.data[:0], p[len(p)-b.limit:]...)
		return written, nil
	}
	if excess := len(b.data) + len(p) - b.limit; excess > 0 {
		copy(b.data, b.data[excess:])
		b.data = b.data[:len(b.data)-excess]
	}
	b.data = append(b.data, p...)
	return written, nil
}
func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte(nil), b.data...))
}

type qemuNBDExport struct {
	listener net.Listener
	server   *nbdapi.NBDServer
	done     chan error
}

func newQEMUNBDExport(ctx context.Context, device blockpkg.Device, name string) (*qemuNBDExport, string, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	server, err := nbdapi.NewNBDServer(device, name, nbdapi.DefaultMaxRequest)
	if err != nil {
		listener.Close()
		return nil, "", err
	}
	if metrics := lifecycle.MetricsFromContext(ctx); metrics != nil {
		server.SetMetrics(metrics)
	}
	export := &qemuNBDExport{listener: listener, server: server, done: make(chan error, 1)}
	go func() {
		connection, err := listener.Accept()
		_ = listener.Close()
		if err == nil {
			err = server.Serve(ctx, connection)
		}
		export.done <- err
		close(export.done)
	}()
	return export, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), nil
}

func (e *qemuNBDExport) Close() {
	_ = e.listener.Close()
}

type qemuDriver struct {
	backend *qemuBackend
	machine vmmapi.Machine
	cmd     *exec.Cmd
	qmp     *qmpClient
	stderr  *boundedBuffer

	ctx           context.Context
	cancel        context.CancelFunc
	events        chan vmmapi.Event
	ready         chan struct{}
	result        chan vmmapi.Result
	channels      map[string]channelpkg.ByteChannel
	gdb           channelpkg.ByteChannel
	exports       []*qemuNBDExport
	extra         []*os.File
	capture       *os.File
	captureFD     int
	started       time.Time
	closeOnce     sync.Once
	transportOnce sync.Once
	closeErr      error
	done          chan struct{}
	mu            sync.Mutex
	inputMu       sync.Mutex
	exit          vmmapi.Result
	detached      bool

	pointerButtons map[string]bool
}

func startQEMU(parent context.Context, backend *qemuBackend, machine vmmapi.Machine) (vmmapi.Driver, error) {
	if !qemuNativeAvailable() {
		return nil, unsupportedVMM("QEMU backend on this platform")
	}
	ctx, cancel := context.WithCancel(parent)
	driver := &qemuDriver{
		backend: backend, machine: machine, ctx: ctx, cancel: cancel,
		events: make(chan vmmapi.Event, 256), ready: make(chan struct{}, 1), result: make(chan vmmapi.Result, 1),
		channels: make(map[string]channelpkg.ByteChannel), stderr: &boundedBuffer{limit: backend.stderrLimit},
		started: time.Now(), done: make(chan struct{}),
	}
	fail := func(err error) (vmmapi.Driver, error) {
		driver.cleanupLaunch()
		return nil, err
	}
	if err := parent.Err(); err != nil {
		return fail(err)
	}
	args := []string{"-machine", backend.machine, "-m", fmt.Sprintf("%dB", machine.Memory), "-smp", strconv.Itoa(machine.CPUs), "-monitor", "none"}
	if backend.accelerator != "auto" {
		args = append(args, "-accel", backend.accelerator)
	}
	display := backend.displayFrontend
	if display == "auto" {
		if machine.Display.Mode == "interactive" {
			display = "gtk"
		} else {
			display = "none"
		}
	}
	args = append(args, "-display", display)
	if backend.firmware == "uefi" {
		firmware, err := qemuUEFIFirmwareMemfd()
		if err != nil {
			return fail(err)
		}
		driver.extra = append(driver.extra, firmware)
		fd := 2 + len(driver.extra)
		args = append(args, "-bios", qemuInheritedFDPath(fd))
	}

	qmpParent, qmpChild, err := inheritedSocket("qmp")
	if err != nil {
		return fail(err)
	}
	driver.extra = append(driver.extra, qmpChild)
	qmpFD := 2 + len(driver.extra)
	args = append(args, "-chardev", fmt.Sprintf("socket,id=trx-qmp,fd=%d", qmpFD), "-mon", "chardev=trx-qmp,mode=control")

	for index, channel := range machine.Channels {
		parentChannel, child, err := inheritedSocket("channel-" + channel.Name)
		if err != nil {
			_ = qmpParent.Close()
			return fail(err)
		}
		driver.channels[channel.Name] = channelpkg.NewReadyByteChannel(parentChannel, 8<<20)
		driver.extra = append(driver.extra, child)
		fd := 2 + len(driver.extra)
		id := fmt.Sprintf("trx-channel-%d", index)
		args = append(args, "-chardev", fmt.Sprintf("socket,id=%s,fd=%d", id, fd))
		switch channel.Kind {
		case "serial", "console":
			args = append(args, "-serial", "chardev:"+id)
		default:
			args = append(args, "-device", "pci-serial,chardev="+id)
		}
	}
	if len(machine.Channels) == 0 {
		args = append(args, "-serial", "none")
	}

	gdbParent, gdbChild, err := inheritedSocket("gdb")
	if err != nil {
		_ = qmpParent.Close()
		return fail(err)
	}
	driver.gdb = gdbParent
	driver.extra = append(driver.extra, gdbChild)
	gdbFD := 2 + len(driver.extra)
	args = append(args, "-chardev", fmt.Sprintf("socket,id=trx-gdb,fd=%d", gdbFD), "-gdb", "chardev:trx-gdb")
	if machine.StartPaused {
		args = append(args, "-S")
	}

	for index, disk := range machine.Disks {
		device := disk.Device
		if disk.Snapshot {
			// Lazy image extents may be backed by compressed archive entries. QEMU
			// issues small, repeated random reads, so cache immutable data below
			// the writable overlay to avoid decompressing the same source region
			// for every request. The fixed bound keeps large guests predictable.
			if !device.Capabilities().Writable {
				if _, alreadyCached := device.(*blockstar.CachedDevice); !alreadyCached {
					cached, err := blockstar.NewCachedDevice(device, blockstar.DefaultCacheSize, blockstar.DefaultCacheChunk)
					if err != nil {
						_ = qmpParent.Close()
						return fail(fmt.Errorf("disk %s read cache: %w", disk.Name, err))
					}
					device = cached
				}
			}
			overlay, err := blockstar.NewOverlayDevice(device, backend.overlayLimit, blockstar.DefaultOverlayChunk)
			if err != nil {
				_ = qmpParent.Close()
				return fail(fmt.Errorf("disk %s snapshot: %w", disk.Name, err))
			}
			device = overlay
		}
		exportName, err := qemuExportName(index)
		if err != nil {
			_ = qmpParent.Close()
			return fail(err)
		}
		export, port, err := newQEMUNBDExport(ctx, device, exportName)
		if err != nil {
			_ = qmpParent.Close()
			return fail(err)
		}
		driver.exports = append(driver.exports, export)
		node := fmt.Sprintf("trx-disk-%d", index)
		block := map[string]any{
			"driver": "nbd", "node-name": node, "export": exportName,
			"server":    map[string]any{"type": "inet", "host": "127.0.0.1", "port": port},
			"read-only": disk.ReadOnly,
		}
		encoded, _ := json.Marshal(block)
		args = append(args, "-blockdev", string(encoded))
		bus := disk.Bus
		if bus == "auto" {
			if disk.Media == "floppy" {
				bus = "floppy"
			} else {
				bus = "ide"
			}
		}
		if bus == "floppy" {
			deviceArg := "floppy,drive=" + node
			if disk.Unit >= 0 {
				deviceArg += fmt.Sprintf(",unit=%d", disk.Unit)
			}
			args = append(args, "-device", deviceArg)
		} else if bus == "ide" {
			frontend := "ide-hd"
			if disk.Media == "cdrom" {
				frontend = "ide-cd"
			}
			deviceArg := frontend + ",drive=" + node
			if disk.CHS != nil {
				physicalCylinders, physicalHeads := disk.CHS.Cylinders, disk.CHS.Heads
				biosTranslation := "auto"
				if physicalHeads > 16 {
					tracks := disk.CHS.Cylinders * disk.CHS.Heads
					if tracks%16 != 0 {
						_ = qmpParent.Close()
						return fail(fmt.Errorf("IDE logical CHS %d/%d/%d cannot be represented with QEMU's 16-head physical geometry", disk.CHS.Cylinders, disk.CHS.Heads, disk.CHS.Sectors))
					}
					physicalCylinders, physicalHeads = tracks/16, 16
					// ATA exposes at most 16 physical heads.  Keep the equivalent
					// physical geometry for IDENTIFY DEVICE, but ask SeaBIOS to
					// translate INT 13h requests to the caller-supplied logical
					// geometry.  "none" makes legacy guests issue invalid ATA CHS
					// commands once logical heads exceed the physical head count.
					biosTranslation = "lba"
				}
				deviceArg += fmt.Sprintf(",cyls=%d,heads=%d,secs=%d,lcyls=%d,lheads=%d,lsecs=%d,bios-chs-trans=%s",
					physicalCylinders, physicalHeads, disk.CHS.Sectors,
					disk.CHS.Cylinders, disk.CHS.Heads, disk.CHS.Sectors, biosTranslation)
			}
			if disk.Unit >= 0 {
				deviceArg += fmt.Sprintf(",bus=ide.%d,unit=%d", disk.Unit/2, disk.Unit%2)
			}
			args = append(args, "-device", deviceArg)
		} else {
			args = append(args, "-device", "virtio-blk-pci,drive="+node)
		}
	}
	for _, network := range machine.Networks {
		if backend.hasNetdev(network.Name) {
			continue
		}
		if network.Kind == "nat" {
			args = append(args, "-netdev", "user,id="+network.Name, "-device", "e1000,netdev="+network.Name)
		}
	}
	for _, table := range backend.acpiTables {
		file, err := fileToMemfd("trex-acpi", table.file)
		if err != nil {
			_ = qmpParent.Close()
			return fail(err)
		}
		driver.extra = append(driver.extra, file)
		fd := 2 + len(driver.extra)
		args = append(args, "-acpitable", "file="+qemuInheritedFDPath(fd))
	}
	if machine.Display.Mode == "capturable" || machine.Display.Mode == "interactive" {
		capture, child, err := qemuCreateCaptureFiles("trex-capture")
		if err != nil {
			_ = qmpParent.Close()
			return fail(err)
		}
		driver.capture = capture
		driver.extra = append(driver.extra, child)
		driver.captureFD = 2 + len(driver.extra)
	}
	args = append(args, qemuConfiguredArgs(backend)...)

	binaryName := backend.binary
	if binaryName == "" {
		binaryName = "qemu-system-" + machine.Architecture
	}
	driver.cmd = exec.Command(binaryName, args...)
	driver.cmd.ExtraFiles = driver.extra
	driver.cmd.Stderr = driver.stderr
	if err := driver.cmd.Start(); err != nil {
		_ = qmpParent.Close()
		return fail(&vmmapi.Error{Code: vmmapi.ErrorBackend, Message: "start QEMU", Detail: driver.stderr.String(), Err: err})
	}
	for _, child := range driver.extra {
		_ = child.Close()
	}
	driver.extra = nil
	go driver.waitProcess()
	if setter, ok := qmpParent.(interface{ SetDeadline(time.Time) error }); ok {
		_ = setter.SetDeadline(time.Now().Add(15 * time.Second))
		defer setter.SetDeadline(time.Time{})
	}
	driver.qmp, err = newQMPClient(parent, qmpParent, driver.qmpEvent)
	if err != nil {
		_ = driver.Close(context.Background())
		return nil, &vmmapi.Error{Code: vmmapi.ErrorBackend, Message: "initialize QMP", Detail: driver.stderr.String(), Err: err}
	}
	driver.emit(vmmapi.Event{Kind: "started", Timestamp: time.Now()})
	return driver, nil
}

func qemuExportName(index int) (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate QEMU NBD export credential: %w", err)
	}
	return fmt.Sprintf("trx-disk-%d-%x", index, token), nil
}

func fileToMemfd(name string, source starfile.File) (*os.File, error) {
	file, err := qemuCreateAnonymousFile(name)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(file, io.NewSectionReader(source, 0, source.Size())); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func qemuUEFIFirmwareMemfd() (*os.File, error) {
	candidates := []string{
		"/usr/share/edk2/x64/OVMF.4m.fd",
		"/usr/share/OVMF/OVMF.fd",
		"/usr/share/qemu/OVMF.fd",
	}
	var source *os.File
	var sourceName string
	for _, candidate := range candidates {
		file, err := os.Open(candidate)
		if err == nil {
			source, sourceName = file, candidate
			break
		}
	}
	if source == nil {
		return nil, fmt.Errorf("QEMU UEFI firmware is not installed (looked for %s)", strings.Join(candidates, ", "))
	}
	defer source.Close()
	firmware, err := qemuCreateAnonymousFile("trex-ovmf")
	if err != nil {
		return nil, fmt.Errorf("load QEMU UEFI firmware %s: %w", sourceName, err)
	}
	if _, err := io.Copy(firmware, source); err != nil {
		firmware.Close()
		return nil, fmt.Errorf("load QEMU UEFI firmware %s: %w", sourceName, err)
	}
	if _, err := firmware.Seek(0, io.SeekStart); err != nil {
		firmware.Close()
		return nil, err
	}
	return firmware, nil
}

func inheritedSocket(name string) (channelpkg.ByteChannel, *os.File, error) {
	fds, err := qemuSocketpair()
	if err != nil {
		return nil, nil, err
	}
	parentFile := os.NewFile(uintptr(fds[0]), name+"-parent")
	child := os.NewFile(uintptr(fds[1]), name+"-child")
	connection, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	return connection, child, nil
}

func qemuConfiguredArgs(backend *qemuBackend) []string {
	var args []string
	for _, audiodev := range backend.audiodevs {
		args = append(args, "-audiodev", qemuJoinedSpec(audiodev))
	}
	for _, netdev := range backend.netdevs {
		args = append(args, "-netdev", qemuJoinedSpec(netdev))
	}
	for _, chardev := range backend.chardevs {
		args = append(args, "-chardev", qemuJoinedSpec(chardev))
	}
	for _, device := range backend.devices {
		args = append(args, "-device", qemuJoinedSpec(device))
	}
	for _, option := range backend.options {
		args = append(args, option.name)
		if len(option.properties) != 0 {
			args = append(args, option.properties[0].value)
		}
	}
	return args
}

func qemuJoinedSpec(spec *qemuSpecValue) string {
	parts := []string{spec.name}
	for _, property := range spec.properties {
		parts = append(parts, property.name+"="+property.value)
	}
	return strings.Join(parts, ",")
}

func (d *qemuDriver) cleanupLaunch() {
	d.releaseTransports()
	for _, file := range d.extra {
		_ = file.Close()
	}
}

func (d *qemuDriver) releaseTransports() {
	d.transportOnce.Do(func() {
		d.cancel()
		for _, export := range d.exports {
			export.Close()
		}
		for _, export := range d.exports {
			<-export.done
		}
		for _, channel := range d.channels {
			_ = channel.Close()
		}
		if d.gdb != nil {
			_ = d.gdb.Close()
		}
		if d.qmp != nil {
			_ = d.qmp.Close()
		}
		if d.capture != nil {
			_ = d.capture.Close()
		}
	})
}

func (d *qemuDriver) waitProcess() {
	err := d.cmd.Wait()
	d.releaseTransports()
	result := vmmapi.Result{Reason: "exited", Clean: err == nil, Backend: d.BackendID(), Detail: d.stderr.String(), Finished: time.Now()}
	if d.cmd.ProcessState != nil {
		result.Code = d.cmd.ProcessState.ExitCode()
	}
	d.mu.Lock()
	d.exit = result
	d.mu.Unlock()
	d.result <- result
	close(d.result)
	d.emit(vmmapi.Event{Kind: "stopped", Timestamp: result.Finished, Payload: vmmResultValue(result)})
	close(d.done)
}

func (d *qemuDriver) qmpEvent(name string, data any) {
	payload, _ := jsonValueToStarlark(data)
	d.emit(vmmapi.Event{Kind: "backend", Backend: "qemu." + strings.ToLower(name), Timestamp: time.Now(), Payload: payload})
}

func (d *qemuDriver) emit(event vmmapi.Event) {
	select {
	case d.events <- event:
		select {
		case d.ready <- struct{}{}:
		default:
		}
	default:
		select {
		case d.events <- vmmapi.Event{Kind: "overflow", Timestamp: time.Now(), Backend: "qemu.events"}:
		default:
		}
	}
}
