package rfe

import (
	"fmt"
	"slices"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
	"renvo.dev/rfe/x86"
)

var realModeGeneralNames = [...]string{"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}
var realModeSegmentNames = [...]string{"es", "cs", "ss", "ds", "fs", "gs"}

func runRealModeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const name = "rfe.run_real_mode"
	var source starlark.Value
	var registers *starlark.Dict
	var limit uint64
	if err := starlark.UnpackArgs(name, args, kwargs, "memory", &source, "registers", &registers, "instruction_limit", &limit); err != nil {
		return nil, err
	}
	if limit == 0 {
		return nil, fmt.Errorf("%s: instruction_limit must be positive", name)
	}
	// FFFF:FFFF is the last address with A20 enabled and 16-bit segment limits.
	ram, err := starfile.BytesForValue(source, 0x10fff0)
	if err != nil {
		return nil, fmt.Errorf("%s: memory: %w", name, err)
	}
	c := &cpu{a20: true, ram: ram, regions: []hypervisor.RAMRegion{{Size: uint64(len(ram))}}}
	c.system = x86.NewPCSystem(&c.core, c, nil)
	initial := make(map[string]uint16, registers.Len())
	for _, item := range registers.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok || (key != "ip" && key != "flags" && !slices.Contains(realModeGeneralNames[:], key) && !slices.Contains(realModeSegmentNames[:], key)) {
			return nil, fmt.Errorf("%s: unknown register %s", name, item[0])
		}
		var value uint16
		if err := starlark.AsInt(item[1], &value); err != nil {
			return nil, fmt.Errorf("%s: register %s: %w", name, key, err)
		}
		initial[key] = value
	}
	for index, key := range realModeGeneralNames {
		c.core.R[index] = uint64(initial[key])
	}
	for index, key := range realModeSegmentNames {
		selector := initial[key]
		c.system.Segments[index].Selector = selector
		c.system.Segments[index].Base = uint64(selector) << 4
	}
	c.core.PC, c.core.Flags = uint64(initial["ip"]), uint64(initial["flags"]&0x7fd5|2)
	entry := c.system.Segments[1].Base + c.core.PC
	if entry >= uint64(len(ram)) {
		return nil, fmt.Errorf("%s: entry %#x outside supplied RAM", name, entry)
	}

	reason, detail := "instruction_limit", ""
	for step := uint64(0); step < limit; step++ {
		if err := c.core.Step(); err != nil {
			reason, detail = "fault", err.Error()
			break
		}
		if c.system.Halted {
			reason = "halt"
			break
		}
	}
	interrupts := starlark.NewDict(0)
	for vector, count := range c.system.InterruptCounts {
		if count != 0 {
			_ = interrupts.SetKey(starlark.MakeInt(vector), starlark.MakeUint64(count))
		}
	}
	interrupts.Freeze()
	return starvalue.NewRecord(starlark.StringDict{
		"reason":     starlark.String(reason),
		"detail":     starlark.String(detail),
		"retired":    starlark.MakeUint64(c.core.Retired),
		"registers":  starvalue.NewRecord(realModeRegisterValues(c)),
		"memory":     &starfile.Bytes{Name: "rfe.real_mode.ram", Data: ram},
		"interrupts": interrupts,
	}), nil
}

func realModeRegisterValues(c *cpu) starlark.StringDict {
	values := starlark.StringDict{
		"ip":    starlark.MakeUint64(c.core.PC),
		"flags": starlark.MakeUint64(c.core.Flags & 0xffff),
	}
	for index, key := range realModeGeneralNames {
		values[key] = starlark.MakeUint64(c.core.R[index] & 0xffff)
	}
	for index, key := range realModeSegmentNames {
		values[key] = starlark.MakeUint(uint(c.system.Segments[index].Selector))
	}
	return values
}
