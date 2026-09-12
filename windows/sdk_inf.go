package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"path"
	"strconv"
	"strings"
)

// sdkInfPlanBuiltin handles the disk:file catalogue shared by the Windows 3.1
// and Windows for Workgroups SDKs. Disk zero references another INF section.
// The data section supplies destination category defaults; callers can select
// categories and override destinations without reference to the host OS.
func sdkInfPlanBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var inf *infFile
	var media, locations *starlark.Dict
	var sections *starlark.List
	target := ""
	if err := starlark.UnpackArgs("sdk_inf_plan", args, kwargs, "inf", &inf, "media", &media, "target?", &target, "sections?", &sections, "locations?", &locations); err != nil {
		return nil, err
	}
	data, found, err := infSection(inf.json, "data")
	if err != nil || !found {
		return nil, fmt.Errorf("sdk_inf_plan: missing data section")
	}
	defaults := map[string]string{}
	for _, pair := range data.Items() {
		key, _ := starlark.AsString(pair[0])
		if row, ok := pair[1].(*starlark.List); ok && row.Len() > 0 {
			value, _ := starlark.AsString(row.Index(0))
			defaults[strings.ToLower(key)] = value
		}
	}
	if target == "" {
		target = defaults["defsdkdir"]
		if target == "" {
			target = defaults["defrestoolsdir"]
		}
	}
	if len(target) < 3 || target[1] != ':' {
		return nil, fmt.Errorf("sdk_inf_plan: target must be an absolute guest Windows path")
	}
	sources := map[string]starfile.File{}
	for _, pair := range media.Items() {
		key, ok := starlark.AsString(pair[0])
		file, valid := pair[1].(starfile.File)
		if !ok || !valid {
			return nil, fmt.Errorf("sdk_inf_plan: media must map names to files")
		}
		key = strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(key, `\`, "/"), "/"))
		if sources[key] != nil {
			return nil, fmt.Errorf("sdk_inf_plan: ambiguous media file %s", key)
		}
		sources[key] = file
	}
	logicalPrefixes := map[string]string{}
	logicalDisks := map[string]bool{}
	if disks, found, _ := infSection(inf.json, "disks"); found {
		for _, pair := range disks.Items() {
			id, _ := starlark.AsString(pair[0])
			row, ok := pair[1].(*starlark.List)
			if !ok || row.Len() < 3 {
				continue
			}
			directory, _ := starlark.AsString(row.Index(0))
			marker, _ := starlark.AsString(row.Index(2))
			marker = strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(marker, `\`, "/"), "/"))
			logicalDisks[id] = true
			subdir := strings.Trim(strings.TrimPrefix(strings.ReplaceAll(directory, `\`, "/"), "."), "/")
			if subdir != "" {
				candidates := map[string]bool{}
				for name := range sources {
					first, relative, found := strings.Cut(name, "/")
					if found && strings.HasPrefix(relative, strings.ToLower(subdir)+"/") {
						candidates[path.Join(first, subdir)] = true
					}
				}
				if len(candidates) == 1 {
					for candidate := range candidates {
						logicalPrefixes[id] = candidate
					}
				}
			}
			for name := range sources {
				first, relative, found := strings.Cut(name, "/")
				if found && relative == marker {
					prefix := path.Join(first, strings.TrimPrefix(strings.ReplaceAll(directory, `\`, "/"), "./"))
					if prior, exists := logicalPrefixes[id]; exists && prior != prefix {
						return nil, fmt.Errorf("sdk_inf_plan: ambiguous disk marker %s", marker)
					}
					logicalPrefixes[id] = prefix
				}
			}
		}
	}
	destinationKeys := map[string]string{"restools": "defrestoolsdir", "convert": "defrestoolsdir", "analysis": "defanalysisdir", "dbgtools": "defdbgtoolsdir", "debug": "defdebugdir", "nodebug": "defnodebugdir", "winstub": "defrestoolsdir", "inc": "defincdir", "dll": "defrestoolsdir", "wlib": "deflibdir", "redist": "defredistdir", "pen": "defpendir", "mailext": "defpendir", "guisetup": "defguidir", "samples": "defsamplesdir", "guide": "defguidedir", "guidirs": "defguidir", "win31qh": "defquickhelpdir", "win31wh": "defquickhelpdir", "mmwhelp": "defquickhelpdir", "mmqhelp": "defquickhelpdir", "readme": "", "install": "", "libexe": "defrestoolsdir", "sdktools": "defrestoolsdir", "skernel": "defdebugdir", "cinc": "defincdir", "sys": "defincdir", "clib": "deflibdir", "clibs": "deflibdir", "clibm": "deflibdir", "clibc": "deflibdir", "clibl": "deflibdir", "wlibs": "deflibdir", "wlibm": "deflibdir", "wlibc": "deflibdir", "wlibl": "deflibdir", "sdkadv": "defquickhelpdir", "sdkwin": "defquickhelpdir"}
	selected := []string{}
	if sections != nil {
		for i := 0; i < sections.Len(); i++ {
			name, ok := starlark.AsString(sections.Index(i))
			if !ok {
				return nil, fmt.Errorf("sdk_inf_plan: sections must contain strings")
			}
			selected = append(selected, name)
		}
	} else {
		for _, pair := range inf.json.Items() {
			name, _ := starlark.AsString(pair[0])
			if _, ok := destinationKeys[strings.ToLower(name)]; ok {
				selected = append(selected, name)
			}
		}
	}
	overrides := map[string]string{}
	if locations != nil {
		for _, pair := range locations.Items() {
			key, ok := starlark.AsString(pair[0])
			value, valid := starlark.AsString(pair[1])
			if !ok || !valid {
				return nil, fmt.Errorf("sdk_inf_plan: locations must map section names to guest paths")
			}
			overrides[strings.ToLower(key)] = value
		}
	}
	files, actions, gaps := []starlark.Value{}, []starlark.Value{}, []starlark.Value{}
	visiting := map[string]bool{}
	decoded := map[string]starfile.File{}
	var walk func(string, string, int) error
	walk = func(section, directory string, depth int) error {
		if depth > 64 || visiting[strings.ToLower(section)] {
			return fmt.Errorf("sdk_inf_plan: cyclic or excessive section reference %s", section)
		}
		visiting[strings.ToLower(section)] = true
		defer delete(visiting, strings.ToLower(section))
		table, found, err := infSection(inf.json, section)
		if err != nil || !found {
			return fmt.Errorf("sdk_inf_plan: missing section %s", section)
		}
		for index, pair := range table.Items() {
			row, ok := pair[1].(*starlark.List)
			if !ok || row.Len() != 1 {
				return fmt.Errorf("sdk_inf_plan: invalid file row in %s", section)
			}
			item, ok := starlark.AsString(row.Index(0))
			if !ok {
				return fmt.Errorf("sdk_inf_plan: invalid file row in %s", section)
			}
			disk, name, found := strings.Cut(item, ":")
			if !found {
				return fmt.Errorf("sdk_inf_plan: file row lacks disk number in %s: %s", section, item)
			}
			number, err := strconv.Atoi(disk)
			if (err != nil || number < 0) && !logicalDisks[disk] {
				return fmt.Errorf("sdk_inf_plan: invalid disk number %s", disk)
			}
			name = strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/")
			_, nested, _ := infSection(inf.json, strings.ReplaceAll(name, "/", `\`))
			if disk == "0" || (nested && path.Ext(name) == "") {
				if err := walk(strings.ReplaceAll(name, "/", `\`), strings.TrimRight(directory, `\`)+`\`+strings.ReplaceAll(name, "/", `\`), depth+1); err != nil {
					return err
				}
				continue
			}
			source := starfile.File(nil)
			sourceKey := ""
			candidates := []string{name}
			// These catalogues target DOS 8.3 media. Windows 3.1's commdlg
			// catalogue spells landscape.ico, stored on both CD trees as
			// LANDSCAP.ICO (and LANDSCAP.IC_ in the compressed install tree).
			base := path.Base(name)
			extension := path.Ext(base)
			stem := strings.TrimSuffix(base, extension)
			if len(stem) > 8 {
				name = path.Join(path.Dir(name), stem[:8]+extension)
				candidates = append(candidates, name)
			}
			if len(name) > 0 {
				ext := path.Ext(name)
				compressed := name + "_"
				if ext == "" {
					compressed = name + "._"
				} else if len(ext) >= 4 {
					compressed = name[:len(name)-1] + "_"
				}
				candidates = append(candidates, compressed)
			}
			for _, candidate := range candidates {
				keys := []string{candidate, disk + "/" + candidate}
				if prefix, ok := logicalPrefixes[disk]; ok {
					keys = append([]string{path.Join(prefix, candidate)}, keys...)
				}
				for _, key := range keys {
					key = strings.ToLower(key)
					if sources[key] != nil {
						source = sources[key]
						sourceKey = key
						break
					}
				}
				if source != nil {
					break
				}
			}
			provenance := acmeRecord(map[string]starlark.Value{"section": starlark.String(section), "row": starlark.MakeInt(index), "disk": starlark.String(disk)})
			var value starlark.Value = starlark.None
			if source == nil {
				gaps = append(gaps, starlark.String("missing media file "+disk+":"+name))
			} else {
				if cached := decoded[sourceKey]; cached != nil {
					source = cached
				} else {
					var err error
					source, err = decodeSetupFile(thread, source)
					if err != nil {
						return fmt.Errorf("sdk_inf_plan: %s: %w", sourceKey, err)
					}
					decoded[sourceKey] = source
				}
				value = source
			}
			output := path.Base(name)
			if data, ok := source.(*starfile.Bytes); ok && strings.HasSuffix(output, "$") && data.Name != "kwaj.bin" && data.Name != "szdd.bin" && data.Name != "" {
				output = data.Name
			}
			files = append(files, acmeRecord(map[string]starlark.Value{"source": starlark.String(name), "file": value, "destination": starlark.String(strings.TrimRight(directory, `\`) + `\` + output), "resolved": starlark.Bool(source != nil), "provenance": provenance}))
		}
		return nil
	}
	for _, section := range selected {
		key, known := destinationKeys[strings.ToLower(section)]
		directory := target
		if key != "" {
			directory = defaults[key]
			if len(directory) < 3 || directory[1] != ':' {
				directory = strings.TrimRight(target, `\`) + `\` + directory
			}
		}
		if override := overrides[strings.ToLower(section)]; override != "" {
			directory = override
			known = true
		}
		if !known {
			return nil, fmt.Errorf("sdk_inf_plan: supply location for section %s", section)
		}
		if err := walk(section, directory, 0); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"sdkgrp", "sdkgrphlp", "append"} {
		if rows, found, _ := infSection(inf.json, name); found {
			actions = append(actions, acmeRecord(map[string]starlark.Value{"section": starlark.String(name), "rows": rows, "requires_execution": starlark.True}))
		}
	}
	for _, name := range []string{"install.exe", "1/install.exe", "setup.exe", "1/setup.exe"} {
		if file := sources[name]; file != nil {
			actions = append(actions, acmeRecord(map[string]starlark.Value{"kind": starlark.String("launcher_policy"), "source": starlark.String(name), "file": file, "declaration": inf}))
			break
		}
	}
	return acmeRecord(map[string]starlark.Value{"format": starlark.String("microsoft_sdk_inf"), "target": starlark.String(target), "files": starlark.NewList(files), "actions": starlark.NewList(actions), "unresolved": starlark.NewList(gaps), "media": media, "inf": inf, "runtime_dependencies": starlark.NewList(actions)}), nil
}
