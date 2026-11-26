package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func csiResidentSourcesBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var selected *starlark.Dict
	if err := starlark.UnpackArgs("csi_resident_sources", args, kwargs, "components", &value, "selected", &selected); err != nil {
		return nil, err
	}
	hive, ok := value.(*registryHive)
	if !ok {
		return nil, fmt.Errorf("csi_resident_sources requires a COMPONENTS hive snapshot")
	}
	reader, err := hive.portableReader()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	var cache storage.DerivedCache
	if resources, err := lifecycle.ForThread(thread); err == nil {
		ctx, cache = resources.Context(), resources.Derived
	}
	rows, err := uup.ReadCBSResidentSources(ctx, reader, cache)
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, 0, selected.Len())
	for _, row := range rows {
		key := starlark.String(strings.ToLower(string(row.Identity)))
		if _, found, err := selected.Get(key); err != nil {
			return nil, err
		} else if !found {
			continue
		}
		values := make([]starlark.Value, len(row.Values))
		for i, value := range row.Values {
			dict := starlark.NewDict(3)
			dict.SetKey(starlark.String("name"), starlark.String(value.Name))
			dict.SetKey(starlark.String("type"), starlark.MakeUint64(uint64(value.Type)))
			dict.SetKey(starlark.String("data"), starlark.Bytes(value.Data))
			values[i] = dict
		}
		result = append(result, starlark.Tuple{key, starlark.Bytes(row.Identity), starlark.NewList(values)})
	}
	return starlark.NewList(result), nil
}

func csiSourcePlanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var before, changes *starlark.List
	if err := starlark.UnpackArgs("csi_source_plan", args, kwargs, "before", &before, "changes", &changes); err != nil {
		return nil, err
	}
	if before.Len() > 1<<20 || changes.Len() > 1<<20 {
		return nil, fmt.Errorf("CSI source input exceeds bound")
	}
	var size uint64
	payload := func(data starlark.Bytes) ([]byte, error) {
		size += uint64(len(data))
		if len(data) > 64<<10 || size > 64<<20 {
			return nil, fmt.Errorf("CSI source payload exceeds bound")
		}
		return []byte(data), nil
	}
	values := make([]registry.Value, 0, before.Len())
	for v := range before.Elements() {
		d, ok := v.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("CSI source baseline value requires a dict")
		}
		var value registry.Value
		var data starlark.Bytes
		if err := starlark.UnpackArgs("CSI source baseline", nil, d.Items(), "name", &value.Name, "type", &value.Type, "data", &data); err != nil {
			return nil, err
		}
		if len(value.Name) > 256 {
			return nil, fmt.Errorf("CSI source value name exceeds bound")
		}
		var err error
		value.Data, err = payload(data)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	delta := make([]uup.CSISourceChange, 0, changes.Len())
	for v := range changes.Elements() {
		d, ok := v.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("CSI source change requires a dict")
		}
		var change uup.CSISourceChange
		var data starlark.Bytes
		if err := starlark.UnpackArgs("CSI source change", nil, d.Items(), "kind", &change.Kind, "delete", &change.Delete, "data", &data); err != nil {
			return nil, err
		}
		var err error
		change.Data, err = payload(data)
		if err != nil {
			return nil, err
		}
		delta = append(delta, change)
	}
	plan, err := uup.PlanCSISourceWrites(values, delta)
	if err != nil {
		return nil, err
	}
	edits := make([]starlark.Value, 0, len(plan.Edits))
	for _, edit := range plan.Edits {
		edits = append(edits, starvalue.NewRecord(starlark.StringDict{
			"name": starlark.String(edit.Value.Name), "delete": starlark.Bool(edit.Delete),
			"type": starlark.MakeUint64(uint64(edit.Value.Type)), "data": starlark.Bytes(edit.Value.Data),
		}))
	}
	counts := func(c uup.CSISourceCounts) starlark.Value {
		return starvalue.NewRecord(starlark.StringDict{"pinned": starlark.MakeUint64(uint64(c.Pinned)), "installed": starlark.MakeUint64(uint64(c.Installed)), "staged": starlark.MakeUint64(uint64(c.Staged))})
	}
	return starvalue.NewRecord(starlark.StringDict{"edits": starlark.NewList(edits), "before": counts(plan.Before), "after": counts(plan.After)}), nil
}
