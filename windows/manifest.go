package windows

import (
	"bytes"
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func assemblyManifestBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("assembly_manifest", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, fmt.Errorf("assembly_manifest: %w", err)
	}
	manifest, err := uup.ParseAssemblyManifest(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("assembly_manifest: parse XML: %w", err)
	}
	attributes := make([]starlark.Value, len(manifest.Identity.Attributes))
	for index, attribute := range manifest.Identity.Attributes {
		attributes[index] = starfile.NewRecord(starlark.StringDict{"namespace": starlark.String(attribute.Namespace), "name": starlark.String(attribute.Name), "value": starlark.String(attribute.Value)})
	}
	files := make([]starlark.Value, len(manifest.Files))
	for index, file := range manifest.Files {
		files[index] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(file.Name), "hash": starlark.String(strings.ToLower(file.Hash)), "hash_algorithm": starlark.String(file.HashAlgorithm)})
	}
	references := make([]starlark.Value, len(manifest.References))
	for index, reference := range manifest.References {
		referenceAttributes := make([]starlark.Value, len(reference.Identity.Attributes))
		for attributeIndex, attribute := range reference.Identity.Attributes {
			referenceAttributes[attributeIndex] = starfile.NewRecord(starlark.StringDict{"namespace": starlark.String(attribute.Namespace), "name": starlark.String(attribute.Name), "value": starlark.String(attribute.Value)})
		}
		references[index] = starfile.NewRecord(starlark.StringDict{"kind": starlark.String(reference.Kind), "identity": starlark.NewList(referenceAttributes)})
	}
	keys := make([]starlark.Value, len(manifest.RegistryKeys))
	for index, key := range manifest.RegistryKeys {
		keys[index] = starlark.String(key)
	}
	return starfile.NewRecord(starlark.StringDict{"identity": starlark.NewList(attributes), "files": starlark.NewList(files), "references": starlark.NewList(references), "registry_keys": starlark.NewList(keys)}), nil
}
