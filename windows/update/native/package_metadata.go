package native

import (
	"fmt"
	"strings"
	"sync"

	"github.com/tinyrange/trex/archive/wim"
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// Each record indexes the complete metadata namespace, not the preliminary
// selected effects. Building it does not authorize servicing or change an image.
func servicingMetadataBuiltin(stages []*uup.CumulativeStage, metadata []uup.UpdateStagePlan) *starlark.Builtin {
	type cached struct {
		once  sync.Once
		value starlark.Value
		err   error
	}
	cache := make([]cached, len(stages))
	return starlark.NewBuiltin("servicing_metadata", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var feature string
		if err := starlark.UnpackArgs("servicing_metadata", args, kwargs, "feature_id", &feature); err != nil {
			return nil, err
		}
		if len(stages) != len(metadata) {
			return nil, fmt.Errorf("servicing_metadata: mismatched stage metadata")
		}
		selected := -1
		for i, m := range metadata {
			if strings.EqualFold(m.FeatureID, feature) {
				if selected >= 0 {
					return nil, fmt.Errorf("servicing_metadata: ambiguous feature %q", feature)
				}
				selected = i
			}
		}
		if selected < 0 {
			return nil, fmt.Errorf("servicing_metadata: unknown installed-OS feature %q", feature)
		}
		c := &cache[selected]
		c.once.Do(func() {
			index, err := uup.NewPackageMetadataIndex(stages[selected])
			if err != nil {
				c.err = err
				return
			}
			components, err := uup.NewComponentMetadataIndex(stages[selected])
			if err != nil {
				c.err = err
				return
			}
			c.value = packageMetadataRecord(index, components, stages[selected])
			c.value.Freeze()
		})
		return c.value, c.err
	})
}

func packageMetadataRecord(index *uup.PackageMetadataIndex, components *uup.ComponentMetadataIndex, stage *uup.CumulativeStage) starlark.Value {
	packages := []starlark.Value{}
	roots := []starlark.Value{}
	for _, entry := range index.Entries() {
		packages = append(packages, starlark.String(entry.Package))
		if entry.Aggregate {
			roots = append(roots, starlark.String(entry.Package))
		}
	}
	open := starlark.NewBuiltin("servicing_metadata.open_package", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("servicing_metadata.open_package", args, kwargs, "package", &name); err != nil {
			return nil, err
		}
		file, err := index.Open(name)
		if err != nil {
			return nil, err
		}
		return starvalue.NewReader(name, file), nil
	})
	openMany := starlark.NewBuiltin("servicing_metadata.open_packages", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var values *starlark.List
		workers := 4
		if err := starlark.UnpackArgs("servicing_metadata.open_packages", args, kwargs, "packages", &values, "workers?", &workers); err != nil {
			return nil, err
		}
		if values.Len() > 4096 || workers < 1 || workers > 8 {
			return nil, fmt.Errorf("open_packages requires at most 4096 names and 1..8 workers")
		}
		names := make([]string, values.Len())
		for i := range names {
			name, ok := starlark.AsString(values.Index(i))
			if !ok {
				return nil, fmt.Errorf("open_packages: package %d must be a string", i)
			}
			names[i] = name
		}
		files, err := index.OpenMany(names, workers)
		if err != nil {
			return nil, err
		}
		result := make([]starlark.Value, len(files))
		for i, file := range files {
			result[i] = starvalue.NewReader(names[i], file)
		}
		return starlark.NewList(result), nil
	})
	openCatalog := starlark.NewBuiltin("servicing_metadata.open_catalog", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		manifestValue := starlark.Value(starlark.None)
		if err := starlark.UnpackArgs("servicing_metadata.open_catalog", args, kwargs, "package", &name, "manifest?", &manifestValue); err != nil {
			return nil, err
		}
		var manifest *uup.ParsedAssemblyFile
		if manifestValue != starlark.None {
			reader, ok := manifestValue.(*starvalue.ReaderValue)
			if ok {
				manifest, _ = reader.StorageReader().(*uup.ParsedAssemblyFile)
			}
			if manifest == nil {
				return nil, fmt.Errorf("open_catalog: manifest must be an owned package metadata snapshot")
			}
		}
		file, err := index.OpenCatalogWithManifest(name, manifest)
		if err != nil {
			return nil, err
		}
		value, ok := file.(starlark.Value)
		if !ok {
			return nil, fmt.Errorf("package catalog %q is not a Starlark file", name)
		}
		return value, nil
	})
	openComponent := starlark.NewBuiltin("servicing_metadata.open_component", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var identity starlark.Bytes
		if err := starlark.UnpackArgs("servicing_metadata.open_component", args, kwargs, "identity", &identity); err != nil {
			return nil, err
		}
		file, found, err := components.Open([]byte(identity))
		if err != nil {
			return nil, err
		}
		if !found {
			return starlark.None, nil
		}
		return starvalue.NewReader("component manifest", file), nil
	})
	return starvalue.NewRecord(starlark.StringDict{"packages": starlark.NewList(packages), "roots": starlark.NewList(roots), "open_package": open, "open_packages": openMany, "open_catalog": openCatalog, "open_catalogs": packageCatalogBatchBuiltin(index), "open_component": openComponent, "plan_components": exactComponentPlanBuiltin(stage, components)})
}

func residentComponentMetadataBuiltins(base *wim.Archive, imagePath string) (*starlark.Builtin, *starlark.Builtin) {
	var once sync.Once
	var index *uup.ComponentMetadataIndex
	var indexErr error
	single := starlark.NewBuiltin("open_resident_component", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var identity starlark.Bytes
		if err := starlark.UnpackArgs("open_resident_component", args, kwargs, "identity", &identity); err != nil {
			return nil, err
		}
		once.Do(func() { index, indexErr = uup.NewResidentComponentMetadataIndex(base, imagePath) })
		if indexErr != nil {
			return nil, indexErr
		}
		file, found, err := index.Open([]byte(identity))
		if err != nil {
			return nil, err
		}
		if !found {
			return starlark.None, nil
		}
		return starvalue.NewReader("resident component manifest", file), nil
	})
	batch := starlark.NewBuiltin("open_resident_components", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var values *starlark.List
		workers := 4
		if err := starlark.UnpackArgs("open_resident_components", args, kwargs, "identities", &values, "workers?", &workers); err != nil {
			return nil, err
		}
		if values.Len() > 65536 || workers < 1 || workers > 8 {
			return nil, fmt.Errorf("open_resident_components requires at most 65536 identities and 1..8 workers")
		}
		identities := make([][]byte, values.Len())
		for i := range identities {
			identity, ok := values.Index(i).(starlark.Bytes)
			if !ok {
				return nil, fmt.Errorf("open_resident_components: identity %d must be bytes", i)
			}
			identities[i] = []byte(identity)
		}
		once.Do(func() { index, indexErr = uup.NewResidentComponentMetadataIndex(base, imagePath) })
		if indexErr != nil {
			return nil, indexErr
		}
		files, err := index.OpenMany(identities, workers)
		if err != nil {
			return nil, err
		}
		result := make([]starlark.Value, len(files))
		for i, file := range files {
			result[i] = starlark.None
			if file != nil {
				result[i] = starvalue.NewReader("resident component manifest", file)
			}
		}
		return starlark.NewList(result), nil
	})
	return single, batch
}
