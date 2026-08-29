package star

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	blockpkg "github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type VMMErrorCode = vmmapi.ErrorCode

const (
	VMMErrorUnsupported = vmmapi.ErrorUnsupported
	VMMErrorInvalid     = vmmapi.ErrorInvalid
	VMMErrorState       = vmmapi.ErrorState
	VMMErrorGuest       = vmmapi.ErrorGuest
	VMMErrorTimeout     = vmmapi.ErrorTimeout
	VMMErrorBackend     = vmmapi.ErrorBackend
	VMMErrorRuntime     = vmmapi.ErrorRuntime
)

type VMMError = vmmapi.Error
type VMMValidationIssue = vmmapi.ValidationIssue
type VMMDisk = vmmapi.Disk
type VMMCHSGeometry = vmmapi.CHSGeometry
type VMMNetwork = vmmapi.Network
type VMMDisplay = vmmapi.Display
type VMMChannel = vmmapi.Channel
type VMMMachine = vmmapi.Machine
type VMMBackend = vmmapi.Backend

type starlarkVMMBackend interface {
	starlark.Value
	VMMBackend() VMMBackend
}

type vmmBackendDescriptor struct {
	id           string
	capabilities []string
}

var vmmBackendRegistry = struct {
	sync.RWMutex
	backends map[string]vmmBackendDescriptor
}{backends: make(map[string]vmmBackendDescriptor)}

func RegisterBackend(id string, capabilities []string) {
	vmmBackendRegistry.Lock()
	defer vmmBackendRegistry.Unlock()
	vmmBackendRegistry.backends[id] = vmmBackendDescriptor{id: id, capabilities: normalizedCapabilities(capabilities)}
}

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"backends": starlark.NewBuiltin("backends", vmmBackendsBuiltin),
		"channel":  starlark.NewBuiltin("channel", vmmChannelBuiltin),
		"disk":     starlark.NewBuiltin("disk", vmmDiskBuiltin),
		"display":  starlark.NewBuiltin("display", vmmDisplayBuiltin),
		"machine":  starlark.NewBuiltin("machine", vmmMachineBuiltin),
		"network":  starlark.NewBuiltin("network", vmmNetworkBuiltin),
		"start":    starlark.NewBuiltin("start", vmmStartBuiltin),
		"validate": starlark.NewBuiltin("validate", vmmValidateBuiltin),
	}
}

type vmmDiskValue struct{ disk VMMDisk }

func (v *vmmDiskValue) String() string {
	return fmt.Sprintf("<vmm.disk name=%q bus=%q media=%q unit=%d>", v.disk.Name, v.disk.Bus, v.disk.Media, v.disk.Unit)
}
func (v *vmmDiskValue) Type() string          { return "vmm_disk" }
func (v *vmmDiskValue) Freeze()               {}
func (v *vmmDiskValue) Truth() starlark.Bool  { return starlark.True }
func (v *vmmDiskValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *vmmDiskValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(v.disk.Name), nil
	case "bus":
		return starlark.String(v.disk.Bus), nil
	case "media":
		return starlark.String(v.disk.Media), nil
	case "unit":
		return starlark.MakeInt(v.disk.Unit), nil
	case "chs":
		if v.disk.CHS == nil {
			return starlark.None, nil
		}
		return starlark.Tuple{starlark.MakeInt(v.disk.CHS.Cylinders), starlark.MakeInt(v.disk.CHS.Heads), starlark.MakeInt(v.disk.CHS.Sectors)}, nil
	case "read_only":
		return starlark.Bool(v.disk.ReadOnly), nil
	case "snapshot":
		return starlark.Bool(v.disk.Snapshot), nil
	case "required":
		return starlark.Bool(v.disk.Required), nil
	case "device":
		return blockstar.NewValue(v.disk.Name, v.disk.Device), nil
	}
	return nil, nil
}
func (v *vmmDiskValue) AttrNames() []string {
	return []string{"bus", "chs", "device", "media", "name", "read_only", "required", "snapshot", "unit"}
}

type vmmNetworkValue struct{ network VMMNetwork }

func (v *vmmNetworkValue) String() string {
	return fmt.Sprintf("<vmm.network name=%q kind=%q>", v.network.Name, v.network.Kind)
}
func (v *vmmNetworkValue) Type() string          { return "vmm_network" }
func (v *vmmNetworkValue) Freeze()               {}
func (v *vmmNetworkValue) Truth() starlark.Bool  { return starlark.True }
func (v *vmmNetworkValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *vmmNetworkValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "kind":
		return starlark.String(v.network.Kind), nil
	case "name":
		return starlark.String(v.network.Name), nil
	case "required":
		return starlark.Bool(v.network.Required), nil
	}
	return nil, nil
}
func (v *vmmNetworkValue) AttrNames() []string { return []string{"kind", "name", "required"} }

type vmmDisplayValue struct{ display VMMDisplay }

func (v *vmmDisplayValue) String() string {
	return fmt.Sprintf("<vmm.display mode=%q>", v.display.Mode)
}
func (v *vmmDisplayValue) Type() string { return "vmm_display" }
func (v *vmmDisplayValue) Freeze()      {}
func (v *vmmDisplayValue) Truth() starlark.Bool {
	return starlark.True
}
func (v *vmmDisplayValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *vmmDisplayValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "mode":
		return starlark.String(v.display.Mode), nil
	case "required":
		return starlark.Bool(v.display.Required), nil
	}
	return nil, nil
}
func (v *vmmDisplayValue) AttrNames() []string { return []string{"mode", "required"} }

type vmmChannelValue struct{ channel VMMChannel }

func (v *vmmChannelValue) String() string {
	return fmt.Sprintf("<vmm.channel name=%q kind=%q>", v.channel.Name, v.channel.Kind)
}
func (v *vmmChannelValue) Type() string          { return "vmm_channel" }
func (v *vmmChannelValue) Freeze()               {}
func (v *vmmChannelValue) Truth() starlark.Bool  { return starlark.True }
func (v *vmmChannelValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *vmmChannelValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "kind":
		return starlark.String(v.channel.Kind), nil
	case "name":
		return starlark.String(v.channel.Name), nil
	case "required":
		return starlark.Bool(v.channel.Required), nil
	}
	return nil, nil
}
func (v *vmmChannelValue) AttrNames() []string { return []string{"kind", "name", "required"} }

type vmmMachineValue struct{ machine VMMMachine }

func (v *vmmMachineValue) String() string {
	return fmt.Sprintf("<vmm.machine architecture=%q memory=%d cpus=%d>", v.machine.Architecture, v.machine.Memory, v.machine.CPUs)
}
func (v *vmmMachineValue) Type() string          { return "vmm_machine" }
func (v *vmmMachineValue) Freeze()               {}
func (v *vmmMachineValue) Truth() starlark.Bool  { return starlark.True }
func (v *vmmMachineValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *vmmMachineValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "architecture":
		return starlark.String(v.machine.Architecture), nil
	case "memory":
		return starlark.MakeInt64(v.machine.Memory), nil
	case "cpus":
		return starlark.MakeInt(v.machine.CPUs), nil
	case "start_paused":
		return starlark.Bool(v.machine.StartPaused), nil
	case "disks":
		values := make([]starlark.Value, len(v.machine.Disks))
		for index, disk := range v.machine.Disks {
			values[index] = &vmmDiskValue{disk: disk}
		}
		return starlark.NewList(values), nil
	case "networks":
		values := make([]starlark.Value, len(v.machine.Networks))
		for index, network := range v.machine.Networks {
			values[index] = &vmmNetworkValue{network: network}
		}
		return starlark.NewList(values), nil
	case "channels":
		values := make([]starlark.Value, len(v.machine.Channels))
		for index, channel := range v.machine.Channels {
			values[index] = &vmmChannelValue{channel: channel}
		}
		return starlark.NewList(values), nil
	case "display":
		return &vmmDisplayValue{display: v.machine.Display}, nil
	case "required_capabilities":
		return stringListValue(v.machine.RequiredCapabilities), nil
	}
	return nil, nil
}
func (v *vmmMachineValue) AttrNames() []string {
	return []string{"architecture", "channels", "cpus", "disks", "display", "memory", "networks", "required_capabilities", "start_paused"}
}

func vmmDiskBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	name, bus, media, unit := "disk0", "auto", "disk", -1
	readOnlyValue := starlark.Value(starlark.None)
	chsValue := starlark.Value(starlark.None)
	snapshot, required := false, true
	if err := starlark.UnpackArgs("disk", args, kwargs,
		"source", &source,
		"name?", &name,
		"bus?", &bus,
		"media?", &media,
		"unit?", &unit,
		"chs?", &chsValue,
		"read_only?", &readOnlyValue,
		"snapshot?", &snapshot,
		"required?", &required,
	); err != nil {
		return nil, err
	}
	var device blockpkg.Device
	if value, ok := source.(*blockstar.Value); ok {
		device = value.Device()
	} else if file, ok := source.(starfile.File); ok {
		var err error
		blockSize := uint32(blockpkg.DefaultBlockSize)
		if media == "cdrom" {
			blockSize = 2048
		}
		device, err = blockpkg.NewFileDevice(file, blockpkg.FileDeviceOptions{LogicalBlockSize: blockSize, PhysicalBlockSize: blockSize})
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("disk: source is %s, want block_device or file", source.Type())
	}
	readOnly := !device.Capabilities().Writable
	if snapshot && readOnlyValue == starlark.None {
		readOnly = false
	}
	if readOnlyValue != starlark.None {
		value, ok := readOnlyValue.(starlark.Bool)
		if !ok {
			return nil, fmt.Errorf("disk: read_only must be bool")
		}
		readOnly = bool(value)
	}
	if !readOnly && !snapshot && !device.Capabilities().Writable {
		return nil, fmt.Errorf("disk: writable attachment requires a writable block device")
	}
	if media != "disk" && media != "cdrom" && media != "floppy" {
		return nil, fmt.Errorf("disk: media must be disk, cdrom, or floppy")
	}
	if media == "cdrom" && (!readOnly || snapshot) {
		return nil, fmt.Errorf("disk: cdrom media must be read-only without a snapshot")
	}
	if media == "cdrom" && device.Geometry().LogicalBlockSize != 2048 {
		return nil, fmt.Errorf("disk: cdrom media requires 2048-byte logical blocks")
	}
	if media == "floppy" && device.Geometry().LogicalBlockSize != 512 {
		return nil, fmt.Errorf("disk: floppy media requires 512-byte logical blocks")
	}
	chs, err := vmmCHSGeometry(chsValue)
	if err != nil {
		return nil, fmt.Errorf("disk: chs: %w", err)
	}
	return &vmmDiskValue{disk: VMMDisk{Device: device, Name: name, Bus: bus, Media: media, Unit: unit, CHS: chs, ReadOnly: readOnly, Snapshot: snapshot, Required: required}}, nil
}

func vmmCHSGeometry(value starlark.Value) (*VMMCHSGeometry, error) {
	if value == starlark.None {
		return nil, nil
	}
	var values []starlark.Value
	switch value := value.(type) {
	case starlark.Tuple:
		values = []starlark.Value(value)
	case *starlark.List:
		values = make([]starlark.Value, value.Len())
		for index := range values {
			values[index] = value.Index(index)
		}
	default:
		return nil, fmt.Errorf("got %s, want a three-item tuple or list", value.Type())
	}
	if len(values) != 3 {
		return nil, fmt.Errorf("got %d values, want cylinders, heads, and sectors", len(values))
	}
	decoded := [3]int{}
	for index, item := range values {
		integer, err := starlark.AsInt32(item)
		if err != nil {
			return nil, fmt.Errorf("value %d is %s, want int", index, item.Type())
		}
		decoded[index] = integer
	}
	return &VMMCHSGeometry{Cylinders: decoded[0], Heads: decoded[1], Sectors: decoded[2]}, nil
}

func vmmNetworkBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind string
	name := "net0"
	required := true
	if err := starlark.UnpackArgs("network", args, kwargs, "kind", &kind, "name?", &name, "required?", &required); err != nil {
		return nil, err
	}
	return &vmmNetworkValue{network: VMMNetwork{Kind: kind, Name: name, Required: required}}, nil
}

func vmmDisplayBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var mode string
	required := true
	if err := starlark.UnpackArgs("display", args, kwargs, "mode", &mode, "required?", &required); err != nil {
		return nil, err
	}
	return &vmmDisplayValue{display: VMMDisplay{Mode: mode, Required: required}}, nil
}

func vmmChannelBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind, name string
	required := true
	if err := starlark.UnpackArgs("channel", args, kwargs, "kind", &kind, "name", &name, "required?", &required); err != nil {
		return nil, err
	}
	return &vmmChannelValue{channel: VMMChannel{Kind: kind, Name: name, Required: required}}, nil
}

func vmmMachineBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var architecture string
	var memory int64
	cpus := 1
	var disksValue, networksValue, channelsValue, requiredValue *starlark.List
	var displayValue starlark.Value = &vmmDisplayValue{display: VMMDisplay{Mode: "none", Required: true}}
	startPaused := false
	if err := starlark.UnpackArgs("machine", args, kwargs,
		"architecture", &architecture,
		"memory", &memory,
		"cpus?", &cpus,
		"disks?", &disksValue,
		"networks?", &networksValue,
		"display?", &displayValue,
		"channels?", &channelsValue,
		"start_paused?", &startPaused,
		"required_capabilities?", &requiredValue,
	); err != nil {
		return nil, err
	}
	display, ok := displayValue.(*vmmDisplayValue)
	if !ok {
		return nil, fmt.Errorf("machine: display is %s, want vmm_display", displayValue.Type())
	}
	machine := VMMMachine{Architecture: architecture, Memory: memory, CPUs: cpus, Display: display.display, StartPaused: startPaused}
	if err := appendTypedList(disksValue, "disks", func(index int, value starlark.Value) error {
		disk, ok := value.(*vmmDiskValue)
		if !ok {
			return fmt.Errorf("machine: disks[%d] is %s, want vmm_disk", index, value.Type())
		}
		machine.Disks = append(machine.Disks, disk.disk)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := appendTypedList(networksValue, "networks", func(index int, value starlark.Value) error {
		network, ok := value.(*vmmNetworkValue)
		if !ok {
			return fmt.Errorf("machine: networks[%d] is %s, want vmm_network", index, value.Type())
		}
		machine.Networks = append(machine.Networks, network.network)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := appendTypedList(channelsValue, "channels", func(index int, value starlark.Value) error {
		channel, ok := value.(*vmmChannelValue)
		if !ok {
			return fmt.Errorf("machine: channels[%d] is %s, want vmm_channel", index, value.Type())
		}
		machine.Channels = append(machine.Channels, channel.channel)
		return nil
	}); err != nil {
		return nil, err
	}
	capabilities, err := starlarkStringList(requiredValue, "required_capabilities")
	if err != nil {
		return nil, err
	}
	machine.RequiredCapabilities = normalizedCapabilities(capabilities)
	return &vmmMachineValue{machine: machine}, nil
}

func appendTypedList(list *starlark.List, _ string, appendValue func(int, starlark.Value) error) error {
	if list == nil {
		return nil
	}
	for index := 0; index < list.Len(); index++ {
		if err := appendValue(index, list.Index(index)); err != nil {
			return err
		}
	}
	return nil
}

func starlarkStringList(list *starlark.List, name string) ([]string, error) {
	if list == nil {
		return nil, nil
	}
	values := make([]string, list.Len())
	for index := range values {
		value, ok := starlark.AsString(list.Index(index))
		if !ok {
			return nil, fmt.Errorf("%s[%d] is %s, want string", name, index, list.Index(index).Type())
		}
		values[index] = value
	}
	return values, nil
}

func normalizedCapabilities(capabilities []string) []string {
	set := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if capability = strings.TrimSpace(capability); capability != "" {
			set[capability] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for capability := range set {
		result = append(result, capability)
	}
	sort.Strings(result)
	return result
}

func stringListValue(values []string) *starlark.List {
	items := make([]starlark.Value, len(values))
	for index, value := range values {
		items[index] = starlark.String(value)
	}
	return starlark.NewList(items)
}
