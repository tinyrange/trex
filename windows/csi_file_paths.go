package windows

import (
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func csiFileDirectoryMacroBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var target, architecture, name string
	if err := starlark.UnpackArgs("csi_file_directory_macro", args, kwargs, "target", &target, "architecture", &architecture, "name", &name); err != nil {
		return nil, err
	}
	id, err := uup.CSIFileDirectoryMacro(target, architecture, name)
	if err != nil {
		return nil, err
	}
	return starlark.MakeUint64(uint64(id)), nil
}

func csiFileDestinationNameBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var override starlark.Value = starlark.None
	if err := starlark.UnpackArgs("csi_file_destination_name", args, kwargs, "name", &name, "destination_name?", &override); err != nil {
		return nil, err
	}
	file := uup.AssemblyFile{Name: name}
	if override != starlark.None {
		var value string
		if err := starlark.UnpackArgs("csi_file_destination_name", starlark.Tuple{override}, nil, "destination_name", &value); err != nil {
			return nil, err
		}
		file.Attributes = []uup.ManifestAttribute{{Name: "destinationName", Value: value}}
	}
	value, err := uup.CSIFileDestinationName(file)
	if err != nil {
		return nil, err
	}
	return starlark.String(value), nil
}

func csiFileAttributesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var attributes starlark.Value = starlark.None
	if err := starlark.UnpackArgs("csi_file_attributes", args, kwargs, "attributes?", &attributes); err != nil {
		return nil, err
	}
	var file uup.AssemblyFile
	if attributes != starlark.None {
		var value string
		if err := starlark.UnpackArgs("csi_file_attributes", starlark.Tuple{attributes}, nil, "attributes", &value); err != nil {
			return nil, err
		}
		file.Attributes = []uup.ManifestAttribute{{Name: "attributes", Value: value}}
	}
	mask, err := uup.CSIFileAttributes(file)
	if err != nil {
		return nil, err
	}
	return starlark.MakeUint64(uint64(mask)), nil
}
