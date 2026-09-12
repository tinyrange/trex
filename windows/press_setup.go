package windows

import (
	"fmt"
	"path"
	"sort"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// pressSetupPlanBuiltin handles the SETUP.INI/SETUP.CMD format used by the
// Microsoft Press books on the Office Developer Edition Resource Library.
func pressSetupPlanBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var inf *infFile
	var media *starlark.Dict
	target := ""
	if err := starlark.UnpackArgs("press_setup_plan", args, kwargs, "inf", &inf, "media", &media, "target?", &target); err != nil {
		return nil, err
	}
	section, found, err := infSection(inf.json, "Setup")
	if err != nil || !found {
		return nil, fmt.Errorf("press_setup_plan: missing Setup section")
	}
	properties := map[string]string{}
	for _, pair := range section.Items() {
		key, _ := starlark.AsString(pair[0])
		if values, ok := pair[1].(*starlark.List); ok && values.Len() > 0 {
			value, _ := starlark.AsString(values.Index(0))
			properties[strings.ToLower(key)] = value
		}
	}
	if target == "" {
		target = properties["destdir"]
	}
	if len(target) < 3 || target[1] != ':' {
		return nil, fmt.Errorf("press_setup_plan: missing absolute target")
	}
	codeDir := strings.Trim(strings.ReplaceAll(properties["codedir"], `\`, "/"), "/")
	if codeDir == "" {
		return nil, fmt.Errorf("press_setup_plan: missing CodeDir")
	}
	sources := map[string]starfile.File{}
	names := []string{}
	for _, pair := range media.Items() {
		name, ok := starlark.AsString(pair[0])
		f, valid := pair[1].(starfile.File)
		if !ok || !valid {
			return nil, fmt.Errorf("press_setup_plan: media must map names to files")
		}
		name = strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/")
		if sources[strings.ToLower(name)] != nil {
			return nil, fmt.Errorf("press_setup_plan: ambiguous media name %s", name)
		}
		sources[strings.ToLower(name)] = f
		names = append(names, name)
	}
	sort.Strings(names)
	files, actions, dependencies, gaps := []starlark.Value{}, []starlark.Value{}, []starlark.Value{}, []starlark.Value{}
	for _, name := range names {
		if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(codeDir)+"/") {
			continue
		}
		relative := name[len(codeDir)+1:]
		source := sources[strings.ToLower(name)]
		if strings.EqualFold(properties["filescompressed"], "Yes") {
			source, err = decodeSetupFile(thread, source)
			if err != nil {
				return nil, err
			}
			if decoded, ok := source.(*starfile.Bytes); ok && decoded.Name != "" && decoded.Name != "szdd.bin" && decoded.Name != "kwaj.bin" {
				relative = path.Join(path.Dir(relative), decoded.Name)
			}
		}
		files = append(files, acmeRecord(map[string]starlark.Value{"source": starlark.String(name), "file": source, "destination": starlark.String(strings.TrimRight(target, `\`) + `\` + strings.ReplaceAll(relative, "/", `\`)), "resolved": starlark.True, "provenance": section}))
	}
	if len(files) == 0 {
		gaps = append(gaps, starlark.String("missing CodeDir payload "+codeDir))
	}
	if command := properties["commandfile"]; command != "" {
		f := sources[strings.ToLower(strings.ReplaceAll(command, `\`, "/"))]
		if f == nil {
			gaps = append(gaps, starlark.String("missing command file "+command))
		} else {
			variables := starlark.NewDict(1)
			_ = variables.SetKey(starlark.String("startdir"), starlark.String(""))
			plan, err := batchPlanBuiltin(thread, nil, starlark.Tuple{f, media}, []starlark.Tuple{{starlark.String("variables"), variables}})
			if err != nil {
				return nil, err
			}
			actions = append(actions, plan)
			dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String("command_file"), "expression": starlark.String(command), "declaration": plan}))
			gapList := acmeGet(plan.(*starlark.Dict), "unresolved").(*starlark.List)
			for i := 0; i < gapList.Len(); i++ {
				gaps = append(gaps, gapList.Index(i))
			}
		}
	}
	if location := properties["shortcutlocation"]; location != "" && !strings.EqualFold(location, "NULL") {
		dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String("shortcut"), "expression": starlark.String(location), "declaration": section}))
	}
	return acmeRecord(map[string]starlark.Value{"format": starlark.String("microsoft_press_setup"), "inf": inf, "files": starlark.NewList(files), "actions": starlark.NewList(actions), "runtime_dependencies": starlark.NewList(dependencies), "unresolved": starlark.NewList(gaps), "media": media}), nil
}
