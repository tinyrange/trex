package star

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/tinyrange/trex/lifecycle"
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

func vmmBackendsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("backends", args, kwargs); err != nil {
		return nil, err
	}
	vmmBackendRegistry.RLock()
	ids := make([]string, 0, len(vmmBackendRegistry.backends))
	for id := range vmmBackendRegistry.backends {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	values := make([]starlark.Value, len(ids))
	for index, id := range ids {
		descriptor := vmmBackendRegistry.backends[id]
		values[index] = starvalue.NewRecord(starlark.StringDict{
			"capabilities": stringListValue(descriptor.capabilities),
			"id":           starlark.String(descriptor.id),
		})
	}
	vmmBackendRegistry.RUnlock()
	return starlark.NewList(values), nil
}

func vmmValidateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var machineValue, backendValue starlark.Value
	if err := starlark.UnpackArgs("validate", args, kwargs, "machine", &machineValue, "backend", &backendValue); err != nil {
		return nil, err
	}
	machine, backend, err := unpackVMMStart("validate", machineValue, backendValue)
	if err != nil {
		return nil, err
	}
	return vmmIssuesValue(validateVMM(machine, backend)), nil
}

func vmmStartBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var machineValue, backendValue starlark.Value
	if err := starlark.UnpackArgs("start", args, kwargs, "machine", &machineValue, "backend", &backendValue); err != nil {
		return nil, err
	}
	machine, backend, err := unpackVMMStart("start", machineValue, backendValue)
	if err != nil {
		return nil, err
	}
	issues := validateVMM(machine, backend)
	if len(issues) != 0 {
		return nil, &VMMError{Code: VMMErrorInvalid, Message: "machine is incompatible with backend", Detail: formatVMMIssues(issues)}
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	driver, err := backend.Start(resources.Context(), machine)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "start backend", err)
	}
	if driver == nil {
		return nil, &VMMError{Code: VMMErrorBackend, Message: "backend returned no VM driver"}
	}
	session := newVMMSession(machine, backend, driver)
	unregister, err := resources.Add(session)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	session.unregister = unregister
	return session, nil
}

func unpackVMMStart(name string, machineValue, backendValue starlark.Value) (VMMMachine, VMMBackend, error) {
	machine, ok := machineValue.(*vmmMachineValue)
	if !ok {
		return VMMMachine{}, nil, fmt.Errorf("%s: machine is %s, want vmm_machine", name, machineValue.Type())
	}
	backend, ok := backendValue.(starlarkVMMBackend)
	if !ok {
		return VMMMachine{}, nil, fmt.Errorf("%s: backend is %s, want vmm_backend", name, backendValue.Type())
	}
	return machine.machine, backend.VMMBackend(), nil
}

func validateVMM(machine VMMMachine, backend VMMBackend) []VMMValidationIssue {
	issues := validateVMMCore(machine)
	if backend == nil {
		return append(issues, VMMValidationIssue{Code: "backend.required", Field: "backend", Message: "backend is required"})
	}
	backendID := backend.ID()
	capabilities := make(map[string]struct{})
	for _, capability := range backend.Capabilities() {
		capabilities[capability] = struct{}{}
	}
	require := func(capability, field, message string, required bool) {
		if !required {
			return
		}
		if _, ok := capabilities[capability]; !ok {
			issues = append(issues, VMMValidationIssue{Code: "capability.unsupported", Field: field, Message: message + " requires " + capability, Backend: backendID})
		}
	}
	for _, capability := range machine.RequiredCapabilities {
		require(capability, "required_capabilities", "required capability", true)
	}
	if machine.StartPaused {
		require("lifecycle.pause", "start_paused", "paused startup", true)
	}
	for index, disk := range machine.Disks {
		field := fmt.Sprintf("disks[%d]", index)
		require("disk", field, "disk attachment", disk.Required)
		if disk.Snapshot {
			require("disk.snapshot", field+".snapshot", "snapshot attachment", disk.Required)
		}
		if disk.CHS != nil {
			require("disk.geometry.chs", field+".chs", "legacy CHS geometry", disk.Required)
		}
		if disk.Bus != "" && disk.Bus != "auto" {
			require("disk.bus."+disk.Bus, field+".bus", "disk bus", disk.Required)
		}
	}
	for index, network := range machine.Networks {
		require("network."+network.Kind, fmt.Sprintf("networks[%d]", index), "network attachment", network.Required)
	}
	if machine.Display.Mode != "none" {
		require("display."+machine.Display.Mode, "display", "display mode", machine.Display.Required)
	}
	for index, channel := range machine.Channels {
		require("channel."+channel.Kind, fmt.Sprintf("channels[%d]", index), "channel attachment", channel.Required)
	}
	for _, issue := range backend.Validate(machine) {
		if issue.Backend == "" {
			issue.Backend = backendID
		}
		issues = append(issues, issue)
	}
	sort.SliceStable(issues, func(left, right int) bool {
		if issues[left].Field != issues[right].Field {
			return issues[left].Field < issues[right].Field
		}
		return issues[left].Code < issues[right].Code
	})
	return issues
}

func validateVMMCore(machine VMMMachine) []VMMValidationIssue {
	var issues []VMMValidationIssue
	add := func(code, field, message string) {
		issues = append(issues, VMMValidationIssue{Code: code, Field: field, Message: message})
	}
	if strings.TrimSpace(machine.Architecture) == "" {
		add("machine.architecture", "architecture", "architecture must not be empty")
	}
	if machine.Memory <= 0 {
		add("machine.memory", "memory", "memory must be positive")
	}
	if machine.CPUs <= 0 {
		add("machine.cpus", "cpus", "CPU count must be positive")
	}
	diskNames := make(map[string]int)
	units := make(map[string]int)
	for index, disk := range machine.Disks {
		field := fmt.Sprintf("disks[%d]", index)
		if disk.Device == nil {
			add("disk.device", field+".device", "block device is required")
		}
		if strings.TrimSpace(disk.Name) == "" {
			add("disk.name", field+".name", "disk name must not be empty")
		} else if prior, ok := diskNames[disk.Name]; ok {
			add("name.duplicate", field+".name", fmt.Sprintf("disk name duplicates disks[%d]", prior))
		} else {
			diskNames[disk.Name] = index
		}
		if disk.Unit < -1 {
			add("disk.unit", field+".unit", "disk unit must be -1 or non-negative")
		}
		if disk.Unit >= 0 {
			key := disk.Bus + ":" + fmt.Sprint(disk.Unit)
			if prior, ok := units[key]; ok {
				add("disk.unit_duplicate", field+".unit", fmt.Sprintf("disk unit duplicates disks[%d]", prior))
			} else {
				units[key] = index
			}
		}
		if disk.CHS != nil {
			chs := disk.CHS
			if chs.Cylinders < 1 || chs.Cylinders > 1024 || chs.Heads < 1 || chs.Heads > 256 || chs.Sectors < 1 || chs.Sectors > 63 {
				add("disk.chs", field+".chs", "legacy CHS geometry must use 1..1024 cylinders, 1..256 heads, and 1..63 sectors")
			} else if disk.Device != nil && disk.Device.Geometry().LogicalBlockSize > 0 {
				sectors := (disk.Device.Geometry().Size + int64(disk.Device.Geometry().LogicalBlockSize) - 1) / int64(disk.Device.Geometry().LogicalBlockSize)
				capacity := int64(chs.Cylinders) * int64(chs.Heads) * int64(chs.Sectors)
				if capacity < sectors {
					add("disk.chs_capacity", field+".chs", fmt.Sprintf("legacy CHS capacity %d sectors is smaller than disk size %d", capacity, sectors))
				}
			}
		}
		if !disk.ReadOnly && !disk.Snapshot && disk.Device != nil && !disk.Device.Capabilities().Writable {
			add("disk.read_only", field+".read_only", "writable attachment has a read-only block device")
		}
	}
	validateNames := func(kind string, count int, name func(int) string) {
		seen := make(map[string]int)
		for index := 0; index < count; index++ {
			value := name(index)
			field := fmt.Sprintf("%s[%d].name", kind, index)
			if strings.TrimSpace(value) == "" {
				add("name.empty", field, "attachment name must not be empty")
			} else if prior, ok := seen[value]; ok {
				add("name.duplicate", field, fmt.Sprintf("name duplicates %s[%d]", kind, prior))
			} else {
				seen[value] = index
			}
		}
	}
	validateNames("networks", len(machine.Networks), func(index int) string { return machine.Networks[index].Name })
	validateNames("channels", len(machine.Channels), func(index int) string { return machine.Channels[index].Name })
	for index, network := range machine.Networks {
		if strings.TrimSpace(network.Kind) == "" {
			add("network.kind", fmt.Sprintf("networks[%d].kind", index), "network kind must not be empty")
		}
	}
	for index, channel := range machine.Channels {
		if strings.TrimSpace(channel.Kind) == "" {
			add("channel.kind", fmt.Sprintf("channels[%d].kind", index), "channel kind must not be empty")
		}
	}
	switch machine.Display.Mode {
	case "none", "interactive", "capturable":
	default:
		add("display.mode", "display.mode", "display mode must be none, interactive, or capturable")
	}
	return issues
}

func vmmIssuesValue(issues []VMMValidationIssue) *starlark.List {
	values := make([]starlark.Value, len(issues))
	for index, issue := range issues {
		values[index] = starvalue.NewRecord(starlark.StringDict{
			"backend": starlark.String(issue.Backend),
			"code":    starlark.String(issue.Code),
			"field":   starlark.String(issue.Field),
			"message": starlark.String(issue.Message),
		})
	}
	return starlark.NewList(values)
}

func formatVMMIssues(issues []VMMValidationIssue) string {
	parts := make([]string, len(issues))
	for index, issue := range issues {
		parts[index] = fmt.Sprintf("%s [%s]: %s", issue.Field, issue.Code, issue.Message)
	}
	return strings.Join(parts, "; ")
}

func normalizeVMMError(code VMMErrorCode, message string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*VMMError); ok {
		return err
	}
	if err == context.DeadlineExceeded {
		code = VMMErrorTimeout
	}
	return &VMMError{Code: code, Message: message, Detail: err.Error(), Err: err}
}
