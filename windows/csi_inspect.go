package windows

import (
	"fmt"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func csiIdentityRecord(id uup.AssemblyIdentity) starlark.Value {
	kind := ""
	for _, a := range id.Attributes {
		if a.Name == "type" && a.Namespace == "" {
			kind = a.Value
		}
	}
	return starvalue.NewRecord(starlark.StringDict{
		"name": starlark.String(id.Name), "version": starlark.String(id.Version),
		"language": starlark.String(id.Language), "processor_architecture": starlark.String(id.ProcessorArchitecture),
		"public_key_token": starlark.String(id.PublicKeyToken), "version_scope": starlark.String(id.VersionScope),
		"type": starlark.String(kind),
	})
}

func csiInspectBytes(name string, args starlark.Tuple, kwargs []starlark.Tuple) ([]byte, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs(name, args, kwargs, "data", &value); err != nil {
		return nil, err
	}
	data, ok := value.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("%s requires bytes", name)
	}
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("%s exceeds 64 KiB", name)
	}
	return []byte(data), nil
}

func csiIdentityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := csiInspectBytes("csi_identity", args, kwargs)
	if err != nil {
		return nil, err
	}
	id, err := uup.ParseCSIIdentity(data)
	if err != nil {
		return nil, err
	}
	return csiIdentityRecord(id), nil
}

func csiDeploymentKeyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := csiInspectBytes("csi_deployment_key", args, kwargs)
	if err != nil {
		return nil, err
	}
	key, err := uup.CSIDeploymentKey(data)
	if err != nil {
		return nil, err
	}
	return starlark.String(key), nil
}

func cbsDeploymentSourceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := csiInspectBytes("cbs_deployment_source", args, kwargs)
	if err != nil {
		return nil, err
	}
	source, err := uup.ParseCBSDeploymentSource(data)
	if err != nil {
		return nil, err
	}
	return starvalue.NewRecord(starlark.StringDict{
		"package": starlark.String(source.Primary[:len(source.Primary)-len(source.Update)-1]), "update": starlark.String(source.Update),
		"primary": starlark.String(source.Primary), "secondary": starlark.Bytes(source.Secondary),
		"source_key": starlark.String(source.SourceKey),
	}), nil
}
