package irix

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func PlanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var descriptors, selected *starlark.List
	var machine, installed, versions, indexes, images, existing, previous *starlark.Dict
	if err := starlark.UnpackArgs("irix_plan", args, kwargs, "descriptors", &descriptors, "selected", &selected, "machine?", &machine, "installed?", &installed, "versions?", &versions, "indexes?", &indexes, "images?", &images, "existing?", &existing, "previous?", &previous); err != nil {
		return nil, err
	}
	products := []Product{}
	for i := 0; i < descriptors.Len(); i++ {
		file, ok := descriptors.Index(i).(starfile.File)
		if !ok {
			return nil, fmt.Errorf("irix_plan: descriptor must be a file")
		}
		p, err := ReadProducts(file, 1000000)
		if err != nil {
			return nil, err
		}
		products = append(products, p...)
	}
	options := PlanOptions{Machine: map[string]string{}, Installed: map[string]uint32{}, Versions: map[string]uint32{}, Indexes: map[string][]Item{}, Images: map[string]starfile.File{}, Existing: map[string]starfile.File{}, Previous: map[string]uint16{}}
	for i := 0; i < selected.Len(); i++ {
		s, ok := starlark.AsString(selected.Index(i))
		if !ok {
			return nil, fmt.Errorf("irix_plan: selected names must be strings")
		}
		options.Selected = append(options.Selected, s)
	}
	if machine != nil {
		for _, pair := range machine.Items() {
			k, ok := starlark.AsString(pair[0])
			v, okv := starlark.AsString(pair[1])
			if !ok || !okv {
				return nil, fmt.Errorf("irix_plan: machine facts must be strings")
			}
			options.Machine[k] = v
		}
	}
	numbers := func(dict *starlark.Dict, dest map[string]uint32) error {
		if dict == nil {
			return nil
		}
		for _, pair := range dict.Items() {
			key, ok := starlark.AsString(pair[0])
			var n uint32
			if !ok {
				return fmt.Errorf("irix_plan: dictionary keys must be strings")
			}
			if err := starlark.AsInt(pair[1], &n); err != nil {
				return err
			}
			dest[key] = n
		}
		return nil
	}
	if err := numbers(installed, options.Installed); err != nil {
		return nil, err
	}
	if err := numbers(versions, options.Versions); err != nil {
		return nil, err
	}
	files := func(dict *starlark.Dict, dest map[string]starfile.File) error {
		if dict == nil {
			return nil
		}
		for _, pair := range dict.Items() {
			key, ok := starlark.AsString(pair[0])
			file, okf := pair[1].(starfile.File)
			if !ok || !okf {
				return fmt.Errorf("irix_plan: expected string-to-file dictionary")
			}
			dest[key] = file
		}
		return nil
	}
	if err := files(images, options.Images); err != nil {
		return nil, err
	}
	if err := files(existing, options.Existing); err != nil {
		return nil, err
	}
	if indexes != nil {
		for _, pair := range indexes.Items() {
			key, ok := starlark.AsString(pair[0])
			file, okf := pair[1].(starfile.File)
			if !ok || !okf {
				return nil, fmt.Errorf("irix_plan: expected string-to-IDB dictionary")
			}
			items, err := ReadIDB(file, 1000000)
			if err != nil {
				return nil, err
			}
			options.Indexes[key] = items
		}
	}
	if previous != nil {
		for _, pair := range previous.Items() {
			key, ok := starlark.AsString(pair[0])
			var n uint16
			if !ok {
				return nil, fmt.Errorf("irix_plan: expected checksum path string")
			}
			if err := starlark.AsInt(pair[1], &n); err != nil {
				return nil, err
			}
			options.Previous[key] = n
		}
	}
	plan, err := Plan(products, options)
	if err != nil {
		return nil, err
	}
	selections := []starlark.Value{}
	for _, s := range plan.Selected {
		selections = append(selections, starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "image": starlark.String(s.Image), "index_key": starlark.String(s.IndexKey), "version": starlark.MakeUint(uint(s.Version)), "descriptor": starlark.MakeInt(s.Descriptor), "order": starlark.MakeInt(int(s.Order))}))
	}
	operations := []starlark.Value{}
	for _, o := range plan.Operations {
		var data starlark.Value = starlark.None
		if o.Data != nil {
			data = o.Data
		}
		operations = append(operations, starfile.NewRecord(starlark.StringDict{"kind": starlark.String(o.Kind), "path": starlark.String(o.Path), "target": starlark.String(o.Target), "owner": starlark.String(o.Owner), "group": starlark.String(o.Group), "mode": starlark.MakeUint(uint(o.Mode)), "major": starlark.MakeInt64(o.Major), "minor": starlark.MakeInt64(o.Minor), "image": starlark.String(o.Image), "source": starlark.String(o.Source), "idb_ordinal": starlark.MakeInt(o.Ordinal), "attributes": pdStrings(o.Attributes), "data": data}))
	}
	hooks := []starlark.Value{}
	for _, h := range plan.Hooks {
		hooks = append(hooks, starfile.NewRecord(starlark.StringDict{"phase": starlark.String(h.Phase), "path": starlark.String(h.Path), "command": starlark.String(h.Command)}))
	}
	issues := []starlark.Value{}
	for _, i := range plan.Issues {
		groups := []starlark.Value{}
		for _, g := range i.Alternatives {
			groups = append(groups, pdMarks(g))
		}
		issues = append(issues, starfile.NewRecord(starlark.StringDict{"kind": starlark.String(i.Kind), "subject": starlark.String(i.Subject), "detail": starlark.String(i.Detail), "alternatives": starlark.NewList(groups)}))
	}
	return starfile.NewRecord(starlark.StringDict{"selected": starlark.NewList(selections), "removed": pdStrings(plan.Removed), "operations": starlark.NewList(operations), "hooks": starlark.NewList(hooks), "issues": starlark.NewList(issues), "resolved": starlark.Bool(len(plan.Issues) == 0)}), nil
}
