package windows

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/windows/registry"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func cbsCachedPhasesBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var softwareValue, componentsValue starlark.Value
	var files *starlark.Dict
	var inputs *starlark.List
	var build starlark.Callable
	var workLimit int
	if err := starlark.UnpackArgs("cbs_cached_phases", args, kwargs,
		"software", &softwareValue, "components", &componentsValue, "files", &files,
		"inputs", &inputs, "work_limit", &workLimit, "build", &build); err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil || resources.Derived == nil {
		return starlark.Call(thread, build, nil, nil)
	}
	software, ok := softwareValue.(*registryHive)
	components, componentsOK := componentsValue.(storage.Reader)
	if !ok || !componentsOK || files.Len() > 131072 || inputs.Len() > 1024 {
		return nil, fmt.Errorf("cbs_cached_phases: bounded package files, inputs and baseline hives are required")
	}
	hive, err := software.portableReader()
	if err != nil {
		return nil, err
	}
	if !hive.IsSnapshot() {
		return nil, fmt.Errorf("cbs_cached_phases requires an immutable SOFTWARE hive")
	}
	key := sha256.New()
	var number [8]byte
	writeNumber := func(n uint64) {
		binary.LittleEndian.PutUint64(number[:], n)
		key.Write(number[:])
	}
	writeText := func(s string) {
		writeNumber(uint64(len(s)))
		io.WriteString(key, s)
	}
	// These are the four SOFTWARE subtrees read by the phase planner. Binding
	// their ordered key/value declarations avoids invalidation on unrelated
	// registry changes or different cell placement when building the baseline.
	// A change in which declarations the planner reads requires a policy bump.
	swRoot := []string{"Microsoft", "Windows", "CurrentVersion", "Component Based Servicing"}
	visited := 0
	var writeKey func(registry.Key, int) error
	writeKey = func(record registry.Key, depth int) error {
		visited++
		if visited > 1<<20 || depth > 128 {
			return fmt.Errorf("cbs_cached_phases: SOFTWARE declaration tree exceeds bound")
		}
		if err := resources.Context().Err(); err != nil {
			return err
		}
		writeText(record.Name)
		cells, err := hive.ValueCells(record)
		if err != nil {
			return err
		}
		writeNumber(uint64(len(cells)))
		for _, cell := range cells {
			value, err := hive.ReadValue(cell)
			if err != nil {
				return err
			}
			writeText(value.Name)
			writeNumber(uint64(value.Type))
			writeNumber(uint64(len(value.Data)))
			key.Write(value.Data)
		}
		children, err := hive.ReadSubkeys(record)
		if err != nil {
			return err
		}
		writeNumber(uint64(len(children)))
		for _, child := range children {
			if err := writeKey(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, subtree := range []string{"Packages", "PackageDetect", "UpdateDetect", "PackageIndex"} {
		record, err := hive.LookupParts(append(swRoot, subtree))
		if err != nil {
			return nil, err
		}
		if err := writeKey(record, 0); err != nil {
			return nil, err
		}
	}
	scratch := make([]byte, 128<<10)
	writeFile := func(file storage.Reader, limit int64) error {
		if file.Size() < 0 || file.Size() > limit {
			return fmt.Errorf("cbs_cached_phases: invalid source size %d", file.Size())
		}
		writeNumber(uint64(file.Size()))
		_, err := io.CopyBuffer(key, io.NewSectionReader(file, 0, file.Size()), scratch)
		return err
	}
	if err := writeFile(components, 1<<30); err != nil {
		return nil, err
	}
	writeNumber(uint64(workLimit))
	writeNumber(uint64(inputs.Len()))
	for i := 0; i < inputs.Len(); i++ {
		text, ok := starlark.AsString(inputs.Index(i))
		if !ok || len(text) > 4096 {
			return nil, fmt.Errorf("cbs_cached_phases: input %d must be a bounded string", i)
		}
		writeText(text)
	}
	items := files.Items()
	for _, item := range items {
		_, nameOK := starlark.AsString(item[0])
		_, fileOK := item[1].(storage.Reader)
		if !nameOK || !fileOK {
			return nil, fmt.Errorf("cbs_cached_phases: expected exact package-name to file entries")
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i][0].(starlark.String) < items[j][0].(starlark.String) })
	writeNumber(uint64(len(items)))
	for _, item := range items {
		if err := resources.Context().Err(); err != nil {
			return nil, err
		}
		writeText(string(item[0].(starlark.String)))
		if err := writeFile(item[1].(storage.Reader), 16<<20); err != nil {
			return nil, err
		}
	}
	plan, err := uup.LoadCBSPhasePlan(resources.Context(), resources.Derived, [sha256.Size]byte(key.Sum(nil)), func() (*uup.CBSPhasePlan, error) {
		value, err := starlark.Call(thread, build, nil, nil)
		if err != nil {
			return nil, err
		}
		pair, ok := value.(starlark.Tuple)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("cbs_cached_phases: builder must return stage packages and a deployment plan")
		}
		stage, stageOK := pair[0].(*starlark.List)
		install, installOK := pair[1].(*cbsPopulationRecord)
		if !stageOK || !installOK || install.captured == nil {
			return nil, fmt.Errorf("cbs_cached_phases: invalid stage packages or deployment plan")
		}
		plan := *install.captured
		plan.StagePackages = make([]string, stage.Len())
		for i := range plan.StagePackages {
			name, ok := starlark.AsString(stage.Index(i))
			if !ok {
				return nil, fmt.Errorf("cbs_cached_phases: stage package %d must be a string", i)
			}
			plan.StagePackages[i] = name
		}
		return &plan, nil
	})
	if err != nil {
		return nil, err
	}
	names := make([]starlark.Value, len(plan.StagePackages))
	for i, name := range plan.StagePackages {
		names[i] = starlark.String(name)
	}
	return starlark.Tuple{starlark.NewList(names), cbsCapturedDeploymentPlan(plan.Actions, plan.Executions, plan.Admissions, plan.PackageNames)}, nil
}
