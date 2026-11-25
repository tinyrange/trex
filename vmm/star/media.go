package star

import (
	"fmt"
	blockpkg "github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func (v *vmmSessionValue) replaceMediaBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var source starlark.Value
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("replace_media", args, kwargs, "name", &name, "source", &source, "timeout?", &timeout); err != nil {
		return nil, err
	}
	driver, ok := v.driver.(vmmapi.MediaReplacer)
	if !ok {
		return nil, unsupportedVMM("replace_media")
	}
	var disk *VMMDisk
	for i := range v.machine.Disks {
		if v.machine.Disks[i].Name == name {
			disk = &v.machine.Disks[i]
			break
		}
	}
	if disk == nil {
		return nil, fmt.Errorf("replace_media: unknown disk %q", name)
	}
	var device blockpkg.Device
	if value, ok := source.(*blockstar.Value); ok {
		device = value.Device()
	} else if file, ok := source.(starfile.File); ok {
		size := uint32(512)
		if disk.Media == "cdrom" {
			size = 2048
		}
		var err error
		device, err = blockpkg.NewFileDevice(file, blockpkg.FileDeviceOptions{LogicalBlockSize: size, PhysicalBlockSize: size})
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("replace_media: source is %s, want file or block_device", source.Type())
	}
	ctx, cancel, err := v.operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	if err := driver.ReplaceMedia(ctx, name, device); err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "replace media (do not automatically retry)", err)
	}
	return starlark.None, nil
}
