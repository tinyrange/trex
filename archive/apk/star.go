package apk

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func fields(value starlark.Value) (map[string]string, error) {
	record, ok := value.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("apk: expected an APKINDEX field dictionary")
	}
	result := make(map[string]string, record.Len())
	for _, pair := range record.Items() {
		key, keyOK := starlark.AsString(pair[0])
		field, fieldOK := starlark.AsString(pair[1])
		if !keyOK || !fieldOK || len(key) != 1 {
			return nil, fmt.Errorf("apk: expected single-character keys and string fields")
		}
		result[key] = field
	}
	return result, nil
}

func resolveInputs(values *starlark.List, repository string) ([]Package, error) {
	packages := make([]Package, 0, values.Len())
	for value := range starlark.Elements(values) {
		f, err := fields(value)
		if err != nil {
			return nil, err
		}
		if !ValidIdentity(f["P"]) || !ValidIdentity(f["V"]) {
			return nil, fmt.Errorf("apk: invalid package identity %q=%q", f["P"], f["V"])
		}
		priority := 0
		if f["k"] != "" {
			priority, err = strconv.Atoi(f["k"])
			if err != nil {
				return nil, fmt.Errorf("apk: %s provider priority: %w", f["P"], err)
			}
		}
		packages = append(packages, Package{Repository: repository, Record: Record{
			Name: f["P"], Version: f["V"], Dependencies: strings.Fields(f["D"]),
			Provides: strings.Fields(f["p"]), ProviderPriority: priority,
		}})
	}
	return packages, nil
}

func ResolveBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var available, base, selected *starlark.List
	if err := starlark.UnpackArgs("apk_resolve", args, kwargs, "available", &available, "base", &base, "selected", &selected); err != nil {
		return nil, err
	}
	candidates, err := resolveInputs(available, "available")
	if err != nil {
		return nil, err
	}
	current, err := resolveInputs(base, "")
	if err != nil {
		return nil, err
	}
	wanted := make([]string, 0, selected.Len())
	for value := range starlark.Elements(selected) {
		id, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("apk: expected a package name=version selection")
		}
		wanted = append(wanted, "available/"+id)
	}
	result, err := Resolve(candidates, current, wanted, nil)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(result))
	for _, pkg := range result {
		values = append(values, starlark.String(pkg.Name+"="+pkg.Version))
	}
	return starlark.NewList(values), nil
}

func InstalledBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var packages *starlark.List
	if err := starlark.UnpackArgs("apk_installed", args, kwargs, "packages", &packages); err != nil {
		return nil, err
	}
	results := make([]InstalledPackage, 0, packages.Len())
	for value := range starlark.Elements(packages) {
		pair, ok := value.(starlark.Tuple)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("apk_installed: expected (fields, entries) tuples")
		}
		record, err := fields(pair[0])
		if err != nil {
			return nil, err
		}
		entries, err := unixfs.ParseEntries(pair[1])
		if err != nil {
			return nil, err
		}
		results = append(results, InstalledPackage{Fields: record, Payload: entries})
	}
	var output bytes.Buffer
	if err := WriteInstalled(&output, results); err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "APK installed records", Data: output.Bytes()}, nil
}
