package windows

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
)

// dmrTargetPlatformBuiltin takes TargetDeviceFamily.Name, not its database ID.
// The native unknown-name sentinel -1 is preserved as 0xffffffff.
func dmrTargetPlatformBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var family int64
	var minimum, maximum uint64
	if err := starlark.UnpackArgs("dmr_target_platform", args, kwargs, "target_device_family_name", &family, "minimum_version", &minimum, "maximum_version_tested", &maximum); err != nil {
		return nil, err
	}
	if family < -1 || family > 0x7fffffff {
		return nil, fmt.Errorf("dmr_target_platform: family name does not fit native enum field")
	}
	data := dmr.EncodeTargetPlatform(dmr.TargetPlatform{Platform: uint32(family), Value16: minimum, Value24: maximum})
	return &starfile.Bytes{Data: data}, nil
}

func mrmLiteralReferenceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	if err := starlark.UnpackArgs("mrm_literal_reference", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := dmr.EncodeLiteralResourceReference(value)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func mrmMissingFileReferenceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var packagePath, value string
	if err := starlark.UnpackArgs("mrm_missing_file_reference", args, kwargs, "package_path", &packagePath, "value", &value); err != nil {
		return nil, err
	}
	data, err := dmr.EncodeMissingFileResourceReference(packagePath, value)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func mrmIndexReferenceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var index uint32
	if err := starlark.UnpackArgs("mrm_index_reference", args, kwargs, "index", &index); err != nil {
		return nil, err
	}
	data, err := dmr.EncodeIndexResourceReference(index)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func dmrPackageResourcesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var display, publisher, logo starlark.Value
	var description starlark.Value = starlark.None
	if err := starlark.UnpackArgs("dmr_package_resources", args, kwargs, "display_name", &display, "publisher_display_name", &publisher, "logo", &logo, "description?", &description); err != nil {
		return nil, err
	}
	var refs [4][]byte
	for i, value := range []starlark.Value{display, publisher, description, logo} {
		if i == 2 && value == starlark.None {
			continue
		}
		file, ok := value.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("dmr_package_resources: field %d requires a reference file", i+1)
		}
		if file.Size() < 0 || file.Size() > 8192 {
			return nil, fmt.Errorf("dmr_package_resources: reference exceeds native limit")
		}
		data, err := starfile.ReadAll(file)
		if err != nil {
			return nil, err
		}
		if data == nil {
			// An explicitly supplied empty file is invalid, not an omitted
			// optional Description reference.
			data = []byte{}
		}
		refs[i] = data
	}
	data, err := dmr.EncodePackageResources(dmr.PackageResourceReferences{DisplayName: refs[0], PublisherDisplayName: refs[1], Description: refs[2], Logo: refs[3]})
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func dmrApplicationResourcesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var index uint16
	var display, description, large, small starlark.Value
	var start starlark.Value = starlark.None
	if err := starlark.UnpackArgs("dmr_application_resources", args, kwargs, "index", &index,
		"display_name", &display, "description", &description, "square150x150_logo", &large,
		"square44x44_logo", &small, "start_page?", &start); err != nil {
		return nil, err
	}
	var refs [5][]byte
	for i, value := range []starlark.Value{display, description, large, small, start} {
		if i == 4 && value == starlark.None {
			continue
		}
		file, ok := value.(starfile.File)
		if !ok || file.Size() < 0 || file.Size() > 8192 {
			return nil, fmt.Errorf("dmr_application_resources: field %d requires a bounded reference file", i)
		}
		data, err := starfile.ReadAll(file)
		if err != nil {
			return nil, err
		}
		if data == nil {
			data = []byte{}
		}
		refs[i] = data
	}
	data, err := dmr.EncodeApplicationResources(index, dmr.ApplicationResourceReferences{
		DisplayName: refs[0], Description: refs[1], Square150x150Logo: refs[2], Square44x44Logo: refs[3], StartPage: refs[4],
	})
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}
