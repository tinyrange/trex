package windows

import (
	"fmt"
	"strings"
	"sync"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func assemblyManifestBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("assembly_manifest", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	// Metadata readers own immutable validated parses. Reuse them here too:
	// runtime inspection and payload hashes otherwise decode the same XML again.
	manifest, _, err := cbsManifestForValue(value, defaultBinaryBuilderLimit)
	if err != nil {
		return nil, fmt.Errorf("assembly_manifest: parse XML: %w", err)
	}
	return &assemblyManifestValue{manifest: manifest}, nil
}

// The parse is immutable; projections are materialized only when requested.
// Each returned view owns its mutable Starlark projections, preserving legacy
// list behavior without duplicating unrelated references/files on every call.
type assemblyManifestValue struct {
	mu       sync.Mutex
	manifest *uup.AssemblyManifest
	fields   starlark.StringDict
	frozen   bool
}

func (v *assemblyManifestValue) String() string       { return "<assembly_manifest>" }
func (v *assemblyManifestValue) Type() string         { return "assembly_manifest" }
func (v *assemblyManifestValue) Truth() starlark.Bool { return starlark.True }
func (v *assemblyManifestValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: assembly_manifest")
}
func (v *assemblyManifestValue) Freeze() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.frozen = true
	for _, field := range v.fields {
		field.Freeze()
	}
}
func (v *assemblyManifestValue) AttrNames() []string {
	return []string{"deployment", "files", "identity", "references", "registry_keys"}
}
func (v *assemblyManifestValue) Attr(name string) (starlark.Value, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if field := v.fields[name]; field != nil {
		return field, nil
	}
	field := assemblyManifestProjection(v.manifest, name)
	if field != nil {
		if v.frozen {
			field.Freeze()
		}
		if v.fields == nil {
			v.fields = make(starlark.StringDict)
		}
		v.fields[name] = field
	}
	return field, nil
}
func assemblyManifestProjection(manifest *uup.AssemblyManifest, name string) starlark.Value {
	switch name {
	case "identity":
		attributes := make([]starlark.Value, len(manifest.Identity.Attributes))
		for index, attribute := range manifest.Identity.Attributes {
			attributes[index] = starfile.NewRecord(starlark.StringDict{"namespace": starlark.String(attribute.Namespace), "name": starlark.String(attribute.Name), "value": starlark.String(attribute.Value)})
		}

		return starlark.NewList(attributes)
	case "files":
		files := make([]starlark.Value, len(manifest.Files))
		for index, file := range manifest.Files {
			var digest starlark.Value = starlark.None
			if file.Digest != nil {
				transforms := make([]starlark.Value, len(file.Digest.Transforms))
				for i, transform := range file.Digest.Transforms {
					transforms[i] = starlark.String(transform)
				}
				digest = starfile.NewRecord(starlark.StringDict{
					"algorithm":  starlark.String(file.Digest.Algorithm),
					"transforms": starlark.NewList(transforms),
					"value":      starlark.String(file.Digest.Value),
				})
			}
			files[index] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(file.Name), "hash": starlark.String(strings.ToLower(file.Hash)), "hash_algorithm": starlark.String(file.HashAlgorithm), "digest": digest})
		}

		return starlark.NewList(files)
	case "references":
		references := make([]starlark.Value, len(manifest.References))
		for index, reference := range manifest.References {
			referenceAttributes := make([]starlark.Value, len(reference.Identity.Attributes))
			for attributeIndex, attribute := range reference.Identity.Attributes {
				referenceAttributes[attributeIndex] = starfile.NewRecord(starlark.StringDict{"namespace": starlark.String(attribute.Namespace), "name": starlark.String(attribute.Name), "value": starlark.String(attribute.Value)})
			}
			redirects := make([]starlark.Value, len(reference.BindingRedirects))
			for i, redirect := range reference.BindingRedirects {
				redirects[i] = starfile.NewRecord(starlark.StringDict{"old_version": starlark.String(redirect.OldVersion), "new_version": starlark.String(redirect.NewVersion)})
			}
			references[index] = starfile.NewRecord(starlark.StringDict{
				"kind": starlark.String(reference.Kind), "identity": starlark.NewList(referenceAttributes),
				"dependency_type": starlark.String(reference.DependencyType), "resource_type": starlark.String(reference.ResourceType),
				"attributes": assemblyAttributeRecords(reference.Attributes), "binding_redirects": starlark.NewList(redirects),
			})
		}

		return starlark.NewList(references)
	case "registry_keys":
		keys := make([]starlark.Value, len(manifest.RegistryKeys))
		for index, key := range manifest.RegistryKeys {
			keys[index] = starlark.String(key)
		}

		return starlark.NewList(keys)
	case "deployment":
		var deployment starlark.Value = starlark.None
		if manifest.Deployment != nil {
			deployment = assemblyAttributeRecords(manifest.Deployment.Attributes)
		}

		return deployment
	}
	return nil
}

func assemblyAttributeRecords(attributes []uup.ManifestAttribute) *starlark.List {
	values := make([]starlark.Value, len(attributes))
	for i, attribute := range attributes {
		values[i] = starfile.NewRecord(starlark.StringDict{"namespace": starlark.String(attribute.Namespace), "name": starlark.String(attribute.Name), "value": starlark.String(attribute.Value)})
	}
	return starlark.NewList(values)
}
