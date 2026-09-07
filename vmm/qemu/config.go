package qemu

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

const (
	defaultQEMUOverlayLimit = 256 << 20
	defaultQEMUStderrLimit  = 1 << 20
)

var qemuAtomName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type qemuProperty struct {
	name  string
	value string
}

type qemuSpecValue struct {
	kind       string
	name       string
	properties []qemuProperty
	file       starfile.File
}

func (v *qemuSpecValue) String() string       { return fmt.Sprintf("<qemu.%s %q>", v.kind, v.name) }
func (v *qemuSpecValue) Type() string         { return "qemu_" + v.kind }
func (v *qemuSpecValue) Freeze()              {}
func (v *qemuSpecValue) Truth() starlark.Bool { return starlark.True }
func (v *qemuSpecValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", v.Type())
}
func (v *qemuSpecValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(v.name), nil
	case "properties":
		dict := starlark.NewDict(len(v.properties))
		for _, property := range v.properties {
			_ = dict.SetKey(starlark.String(property.name), starlark.String(property.value))
		}
		return dict, nil
	case "file":
		if v.file != nil {
			return v.file, nil
		}
	}
	return nil, nil
}
func (v *qemuSpecValue) AttrNames() []string {
	names := []string{"name", "properties"}
	if v.file != nil {
		names = append(names, "file")
	}
	return names
}

type qemuBackend struct {
	binary          string
	machine         string
	accelerator     string
	displayFrontend string
	blockTransport  string
	firmware        string
	overlayLimit    int64
	stderrLimit     int
	devices         []*qemuSpecValue
	netdevs         []*qemuSpecValue
	audiodevs       []*qemuSpecValue
	chardevs        []*qemuSpecValue
	options         []*qemuSpecValue
	acpiTables      []*qemuSpecValue
	capabilities    []string
}

func (b *qemuBackend) String() string {
	return fmt.Sprintf("<qemu.backend machine=%q accelerator=%q>", b.machine, b.accelerator)
}
func (b *qemuBackend) Type() string          { return "vmm_backend" }
func (b *qemuBackend) Freeze()               {}
func (b *qemuBackend) Truth() starlark.Bool  { return starlark.True }
func (b *qemuBackend) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", b.Type()) }
func (b *qemuBackend) Attr(name string) (starlark.Value, error) {
	switch name {
	case "id":
		return starlark.String(b.ID()), nil
	case "capabilities":
		return stringListValue(b.Capabilities()), nil
	case "machine":
		return starlark.String(b.machine), nil
	case "accelerator":
		return starlark.String(b.accelerator), nil
	case "block_transport":
		return starlark.String(b.blockTransport), nil
	case "firmware":
		return starlark.String(b.firmware), nil
	}
	return nil, nil
}
func (b *qemuBackend) AttrNames() []string {
	return []string{"accelerator", "block_transport", "capabilities", "firmware", "id", "machine"}
}
func (b *qemuBackend) VMMBackend() vmmapi.Backend { return b }
func (b *qemuBackend) ID() string                 { return "qemu.v1" }
func (b *qemuBackend) Capabilities() []string     { return append([]string(nil), b.capabilities...) }
func (b *qemuBackend) Validate(machine vmmapi.Machine) []vmmapi.ValidationIssue {
	var issues []vmmapi.ValidationIssue
	switch machine.Architecture {
	case "i386", "x86_64":
	default:
		issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.architecture", Field: "architecture", Message: "QEMU backend supports i386 and x86_64"})
	}
	if b.blockTransport == "direct" && len(machine.Disks) != 0 {
		issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.block_transport", Field: "disks", Message: "direct transport requires a backend-native host file and is unavailable for opaque block devices"})
	}
	for index, disk := range machine.Disks {
		switch disk.Bus {
		case "auto", "floppy", "ide", "virtio":
		default:
			issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.disk_bus", Field: fmt.Sprintf("disks[%d].bus", index), Message: "unsupported QEMU disk bus"})
		}
		switch disk.Media {
		case "", "disk":
		case "cdrom":
			if disk.Bus == "virtio" {
				issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.cdrom_bus", Field: fmt.Sprintf("disks[%d].bus", index), Message: "QEMU CD-ROM media requires an IDE bus"})
			}
			if disk.Device.Geometry().LogicalBlockSize != 2048 {
				issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.cdrom_block_size", Field: fmt.Sprintf("disks[%d].device", index), Message: "QEMU CD-ROM media requires 2048-byte logical blocks"})
			}
			if !disk.ReadOnly || disk.Snapshot {
				issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.cdrom_mode", Field: fmt.Sprintf("disks[%d]", index), Message: "QEMU CD-ROM media must be read-only without a snapshot"})
			}
		case "floppy":
			if disk.Bus != "auto" && disk.Bus != "floppy" {
				issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.floppy_bus", Field: fmt.Sprintf("disks[%d].bus", index), Message: "QEMU floppy media requires a floppy bus"})
			}
			if disk.Device.Geometry().LogicalBlockSize != 512 {
				issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.floppy_block_size", Field: fmt.Sprintf("disks[%d].device", index), Message: "QEMU floppy media requires 512-byte logical blocks"})
			}
			if disk.Unit > 1 {
				issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.floppy_unit", Field: fmt.Sprintf("disks[%d].unit", index), Message: "QEMU floppy unit must be 0 or 1"})
			}
		default:
			issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.disk_media", Field: fmt.Sprintf("disks[%d].media", index), Message: "unsupported QEMU disk media"})
		}
		if disk.Bus == "floppy" && disk.Media != "floppy" {
			issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.floppy_media", Field: fmt.Sprintf("disks[%d].media", index), Message: "QEMU floppy bus requires floppy media"})
		}
		if disk.CHS != nil && disk.Bus != "auto" && disk.Bus != "ide" {
			issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.chs_bus", Field: fmt.Sprintf("disks[%d].chs", index), Message: "QEMU legacy CHS geometry requires an IDE disk"})
		}
		if disk.CHS != nil && disk.Media != "" && disk.Media != "disk" {
			issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.chs_media", Field: fmt.Sprintf("disks[%d].chs", index), Message: "QEMU legacy CHS geometry requires hard-disk media"})
		}
		if disk.ReadOnly && !disk.Snapshot && disk.Bus != "virtio" && disk.Media != "cdrom" && disk.Media != "floppy" {
			issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.read_only_disk", Field: fmt.Sprintf("disks[%d].read_only", index), Message: "this QEMU disk frontend cannot attach a read-only block node; use a writable overlay or snapshot"})
		}
	}
	for index, network := range machine.Networks {
		if network.Kind == "bridge" && !b.hasNetdev(network.Name) {
			issues = append(issues, vmmapi.ValidationIssue{Code: "qemu.bridge", Field: fmt.Sprintf("networks[%d]", index), Message: "bridge networking requires a qemu.netdev specification with the matching id"})
		}
	}
	return issues
}

func (b *qemuBackend) hasNetdev(id string) bool {
	for _, spec := range b.netdevs {
		for _, property := range spec.properties {
			if property.name == "id" && property.value == id {
				return true
			}
		}
	}
	return false
}
func (b *qemuBackend) Start(ctx context.Context, machine vmmapi.Machine) (vmmapi.Driver, error) {
	return startQEMU(ctx, b, machine)
}

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"acpi_table": starlark.NewBuiltin("acpi_table", qemuACPITableBuiltin),
		"backend":    starlark.NewBuiltin("backend", qemuBackendBuiltin),
		"audiodev":   starlark.NewBuiltin("audiodev", qemuSpecBuiltin("audiodev")),
		"chardev":    starlark.NewBuiltin("chardev", qemuSpecBuiltin("chardev")),
		"device":     starlark.NewBuiltin("device", qemuSpecBuiltin("device")),
		"extension":  starlark.NewBuiltin("extension", qemuExtensionBuiltin),
		"netdev":     starlark.NewBuiltin("netdev", qemuSpecBuiltin("netdev")),
		"option":     starlark.NewBuiltin("option", qemuOptionBuiltin),
	}
}

func Available() bool { return qemuNativeAvailable() }

func Capabilities() []string { return qemuCapabilities() }

func qemuCapabilities() []string {
	return normalizedCapabilities([]string{
		"channel.console", "channel.custom", "channel.debugger", "channel.serial",
		"debugger.gdb", "disk", "disk.bus.auto", "disk.bus.floppy", "disk.bus.ide", "disk.bus.virtio", "disk.geometry.chs",
		"disk.snapshot", "display.capturable", "display.interactive", "extension.qemu.v1",
		"input.key", "input.pointer", "input.text", "lifecycle.pause", "lifecycle.powerdown",
		"lifecycle.reset", "lifecycle.stop", "network.bridge", "network.nat", "screenshot",
	})
}

func qemuBackendBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	binaryName, machine, accelerator := "", "pc", "auto"
	displayFrontend, blockTransport, firmware := "auto", "auto", "bios"
	overlayLimit := int64(defaultQEMUOverlayLimit)
	stderrLimit := defaultQEMUStderrLimit
	var devices, netdevs, audiodevs, chardevs, options, acpiTables *starlark.List
	if err := starlark.UnpackArgs("backend", args, kwargs,
		"binary?", &binaryName,
		"machine?", &machine,
		"accelerator?", &accelerator,
		"display_frontend?", &displayFrontend,
		"block_transport?", &blockTransport,
		"firmware?", &firmware,
		"overlay_limit?", &overlayLimit,
		"stderr_limit?", &stderrLimit,
		"devices?", &devices,
		"netdevs?", &netdevs,
		"audiodevs?", &audiodevs,
		"chardevs?", &chardevs,
		"options?", &options,
		"acpi_tables?", &acpiTables,
	); err != nil {
		return nil, err
	}
	if machine == "" || !qemuAtomName.MatchString(machine) {
		return nil, fmt.Errorf("backend: invalid machine name")
	}
	switch accelerator {
	case "auto", "kvm", "tcg":
	default:
		return nil, fmt.Errorf("backend: accelerator must be auto, kvm, or tcg")
	}
	switch displayFrontend {
	case "auto", "none", "gtk", "sdl", "cocoa":
	default:
		return nil, fmt.Errorf("backend: unsupported display_frontend %q", displayFrontend)
	}
	switch blockTransport {
	case "auto", "nbd", "direct":
	default:
		return nil, fmt.Errorf("backend: block_transport must be auto, nbd, or direct")
	}
	switch firmware {
	case "bios", "uefi":
	default:
		return nil, fmt.Errorf("backend: firmware must be bios or uefi")
	}
	if overlayLimit <= 0 || stderrLimit <= 0 || stderrLimit > 64<<20 {
		return nil, fmt.Errorf("backend: invalid resource limit")
	}
	backend := &qemuBackend{
		binary: binaryName, machine: machine, accelerator: accelerator,
		displayFrontend: displayFrontend, blockTransport: blockTransport, firmware: firmware,
		overlayLimit: overlayLimit, stderrLimit: stderrLimit, capabilities: qemuCapabilities(),
	}
	var err error
	if backend.devices, err = qemuSpecList(devices, "device"); err != nil {
		return nil, err
	}
	if backend.netdevs, err = qemuSpecList(netdevs, "netdev"); err != nil {
		return nil, err
	}
	if backend.audiodevs, err = qemuSpecList(audiodevs, "audiodev"); err != nil {
		return nil, err
	}
	if backend.chardevs, err = qemuSpecList(chardevs, "chardev"); err != nil {
		return nil, err
	}
	if backend.options, err = qemuSpecList(options, "option"); err != nil {
		return nil, err
	}
	if backend.acpiTables, err = qemuSpecList(acpiTables, "acpi_table"); err != nil {
		return nil, err
	}
	return backend, nil
}

func qemuSpecBuiltin(kind string) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("%s: got %d positional arguments, want 1", kind, len(args))
		}
		name, ok := starlark.AsString(args[0])
		if !ok || !qemuAtomName.MatchString(name) {
			return nil, fmt.Errorf("%s: invalid name", kind)
		}
		properties, err := qemuProperties(kwargs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", kind, err)
		}
		return &qemuSpecValue{kind: kind, name: name, properties: properties}, nil
	}
}

func qemuOptionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Value = starlark.None
	if err := starlark.UnpackArgs("option", args, kwargs, "name", &name, "value?", &value); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(name, "-") || !qemuAtomName.MatchString(strings.TrimPrefix(name, "-")) {
		return nil, fmt.Errorf("option: invalid option name %q", name)
	}
	reserved := map[string]bool{
		"-accel": true, "-blockdev": true, "-chardev": true, "-daemonize": true,
		"-display": true, "-drive": true, "-gdb": true, "-incoming": true,
		"-m": true, "-machine": true, "-monitor": true, "-pidfile": true,
		"-qmp": true, "-S": true, "-serial": true, "-smp": true,
	}
	if reserved[name] {
		return nil, fmt.Errorf("option: %s is owned by the QEMU backend lifecycle", name)
	}
	properties := []qemuProperty(nil)
	if value != starlark.None {
		atom, err := qemuOptionValue(name, value)
		if err != nil {
			return nil, fmt.Errorf("option: value: %w", err)
		}
		properties = []qemuProperty{{name: "value", value: atom}}
	}
	return &qemuSpecValue{kind: "option", name: name, properties: properties}, nil
}

func qemuOptionValue(name string, value starlark.Value) (string, error) {
	if name == "-boot" {
		list, ok := value.(*starlark.List)
		if !ok {
			return qemuPropertyValue(value)
		}
		if list.Len() == 0 || list.Len() > 16 {
			return "", fmt.Errorf("-boot option list must contain between 1 and 16 values")
		}
		parts := make([]string, list.Len())
		for index := 0; index < list.Len(); index++ {
			part, err := qemuPropertyValue(list.Index(index))
			if err != nil {
				return "", fmt.Errorf("-boot option %d: %w", index, err)
			}
			if !strings.Contains(part, "=") {
				return "", fmt.Errorf("-boot option %d must be key=value", index)
			}
			parts[index] = part
		}
		return strings.Join(parts, ","), nil
	}
	if name != "-d" {
		return qemuPropertyValue(value)
	}
	list, ok := value.(*starlark.List)
	if !ok {
		return qemuPropertyValue(value)
	}
	if list.Len() == 0 || list.Len() > 64 {
		return "", fmt.Errorf("-d debug event list must contain between 1 and 64 names")
	}
	events := make([]string, list.Len())
	seen := make(map[string]bool, list.Len())
	for index := 0; index < list.Len(); index++ {
		event, ok := starlark.AsString(list.Index(index))
		if !ok || !qemuAtomName.MatchString(event) {
			return "", fmt.Errorf("-d debug event %d is invalid", index)
		}
		if seen[event] {
			return "", fmt.Errorf("-d debug event %q is duplicated", event)
		}
		seen[event] = true
		events[index] = event
	}
	return strings.Join(events, ","), nil
}

func qemuACPITableBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("acpi_table", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	return &qemuSpecValue{kind: "acpi_table", name: "table", file: file}, nil
}

func qemuExtensionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("extension", args, kwargs, "vm", &value); err != nil {
		return nil, err
	}
	vm, ok := value.(interface {
		VMMExtension(string) (starlark.Value, error)
	})
	if !ok {
		return nil, fmt.Errorf("extension: got %s, want vm", value.Type())
	}
	return vm.VMMExtension("qemu.v1")
}

func qemuProperties(kwargs []starlark.Tuple) ([]qemuProperty, error) {
	properties := make([]qemuProperty, 0, len(kwargs))
	seen := make(map[string]bool)
	for _, kwarg := range kwargs {
		name, ok := starlark.AsString(kwarg[0])
		if !ok || !qemuAtomName.MatchString(name) || seen[name] {
			return nil, fmt.Errorf("invalid or duplicate property name")
		}
		value, err := qemuPropertyValue(kwarg[1])
		if err != nil {
			return nil, fmt.Errorf("property %s: %w", name, err)
		}
		seen[name] = true
		properties = append(properties, qemuProperty{name: name, value: value})
	}
	sort.Slice(properties, func(left, right int) bool { return properties[left].name < properties[right].name })
	return properties, nil
}

func qemuPropertyValue(value starlark.Value) (string, error) {
	var result string
	switch value := value.(type) {
	case starlark.String:
		result = string(value)
	case starlark.Bool:
		result = map[bool]string{true: "on", false: "off"}[bool(value)]
	case starlark.Int:
		result = value.String()
	case starlark.Float:
		result = strconv.FormatFloat(float64(value), 'g', -1, 64)
	default:
		return "", fmt.Errorf("got %s, want string, bool, int, or float", value.Type())
	}
	if strings.IndexByte(result, 0) >= 0 || strings.ContainsAny(result, ",\r\n") {
		return "", fmt.Errorf("value contains an unsafe QEMU separator")
	}
	return result, nil
}

func qemuSpecList(list *starlark.List, kind string) ([]*qemuSpecValue, error) {
	if list == nil {
		return nil, nil
	}
	result := make([]*qemuSpecValue, list.Len())
	for index := range result {
		value, ok := list.Index(index).(*qemuSpecValue)
		if !ok || value.kind != kind {
			return nil, fmt.Errorf("backend: %ss[%d] is %s, want qemu_%s", kind, index, list.Index(index).Type(), kind)
		}
		result[index] = value
	}
	return result, nil
}
