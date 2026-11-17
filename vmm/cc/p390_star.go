package cc

import (
	"fmt"
	"github.com/tinyrange/trex/emulator/s390"
	"github.com/tinyrange/trex/vmm/device"
	"go.starlark.net/starlark"
	"time"
)

func p390Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name, start := "p390", ""
	slot := 5
	compat := false
	if err := starlark.UnpackArgs("cc.p390", args, kwargs, "name?", &name, "slot?", &slot, "s370?", &compat, "start?", &start); err != nil {
		return nil, err
	}
	if slot < 0 || slot > 31 || name == "" {
		return nil, fmt.Errorf("cc.p390: nonempty name and slot 0..31 required")
	}
	var epoch time.Time
	if start != "" {
		var err error
		epoch, err = time.Parse(time.RFC3339, start)
		if err != nil {
			return nil, fmt.Errorf("cc.p390: invalid start: %w", err)
		}
	}
	spec := s390.P390Device(name, uint16(slot<<3), compat, epoch)
	if err := device.Validate([]device.Spec{spec}, device.Profile{Architecture: "i386", CPUs: 1}, reservedPCISlots()); err != nil {
		return nil, err
	}
	return NewPCIDeviceValue(spec), nil
}
func (b *Backend) deviceSpecs() []device.Spec {
	out := append([]device.Spec(nil), b.Devices...)
	if b.P390 {
		out = append(out, s390.P390Device("p390", 5<<3, b.P390S370, b.P390Start))
	}
	return out
}
