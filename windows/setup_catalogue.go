package windows

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// cataloguePlan retains every option and OS-specific section in the early
// Office catalogue format. It does not choose options or consult the host.
func (s *setupINF) cataloguePlan(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var media *starlark.Dict
	target, variant := "", ""
	if err := starlark.UnpackArgs("setup_inf.catalogue_plan", args, kwargs, "media", &media, "target?", &target, "variant?", &variant); err != nil {
		return nil, err
	}
	if target == "" {
		for _, row := range s.sections["data"] {
			key, value, ok := strings.Cut(row.text, "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "defdir") {
				target = strings.Trim(strings.TrimSpace(value), `"`)
			}
		}
	}
	sources, decoded := map[string]starfile.File{}, map[string]starfile.File{}
	for _, pair := range media.Items() {
		name, ok := starlark.AsString(pair[0])
		f, valid := pair[1].(starfile.File)
		if !ok || !valid {
			return nil, fmt.Errorf("catalogue_plan: media must map names to files")
		}
		sources[strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/"))] = f
	}
	files, actions, dependencies, gaps := []starlark.Value{}, []starlark.Value{}, []starlark.Value{}, []starlark.Value{}
	for _, section := range s.names {
		rows := s.sections[strings.ToLower(section)]
		expanded := []setupLine{}
		for _, row := range rows {
			fields, err := acmeArguments(row.text)
			if err != nil || len(fields) == 0 {
				expanded = append(expanded, row)
				continue
			}
			disk, pattern, ok := strings.Cut(fields[0], ":")
			if !ok || !strings.ContainsAny(pattern, "*?") {
				expanded = append(expanded, row)
				continue
			}
			prefix := disk + "/"
			matches := []string{}
			for name := range sources {
				if !strings.HasPrefix(name, prefix) {
					continue
				}
				if matched, _ := path.Match(strings.ToLower(strings.ReplaceAll(pattern, `\`, "/")), strings.TrimPrefix(name, prefix)); matched {
					matches = append(matches, strings.TrimPrefix(name, prefix))
				}
			}
			sort.Strings(matches)
			if len(matches) == 0 {
				expanded = append(expanded, row)
				continue
			}
			suffix := ""
			if comma := strings.IndexByte(row.text, ','); comma >= 0 {
				suffix = row.text[comma:]
			}
			for _, name := range matches {
				expanded = append(expanded, setupLine{text: disk + ":" + name + suffix, line: row.line, offset: row.offset})
			}
		}
		rows = expanded
		base, suffix, specialized := strings.Cut(section, "*")
		selectedVariant := !specialized || strings.EqualFold(suffix, variant)
		if !specialized && variant != "" {
			if _, exists := s.sections[strings.ToLower(base+"*"+variant)]; exists {
				selectedVariant = false
			}
		}
		directory := target
		for _, row := range rows {
			key, value, ok := strings.Cut(row.text, "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "destination") {
				value = strings.Trim(strings.TrimSpace(value), `"`)
				if strings.Contains(value, ":") {
					directory = value
				} else {
					directory = strings.TrimRight(target, `\`) + `\` + value
				}
			}
		}
		for _, row := range rows {
			provenance := acmeRecord(map[string]starlark.Value{"section": starlark.String(section), "line": starlark.MakeInt(row.line), "offset": starlark.MakeInt(row.offset)})
			declaration := acmeRecord(map[string]starlark.Value{"text": starlark.String(row.text), "provenance": provenance})
			actions = append(actions, declaration)
			if !selectedVariant {
				continue
			}
			// The first field is either disk:filename or disk,filename.
			fields, err := acmeArguments(row.text)
			flat := section == "$preamble"
			if flat {
				fields = strings.Fields(row.text)
			}
			if err != nil || len(fields) < 2 {
				continue
			}
			disk, filename, colon := strings.Cut(fields[0], ":")
			if !colon {
				disk, filename = fields[0], fields[1]
			}
			if disk == "" || disk[0] < '0' || disk[0] > '9' {
				continue
			}
			number, err := strconv.Atoi(disk)
			if err != nil || number <= 0 || filename == "" || strings.Contains(filename, "=") {
				continue
			}
			if colon && len(fields) > 5 && fields[4] == "8" && fields[5] == "0" {
				dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String("file_policy"), "expression": starlark.String(row.text), "declaration": declaration}))
				continue
			}
			name := strings.ReplaceAll(filename, `\`, "/")
			if strings.HasPrefix(strings.ToLower(section), "list ") && path.Ext(name) == "" && sources[strings.ToLower(disk+"/"+name)] == nil {
				dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String("list_value"), "expression": starlark.String(row.text), "declaration": declaration}))
				continue
			}
			key := strings.ToLower(strconv.Itoa(number) + "/" + name)
			source := sources[key]
			if source == nil {
				source = sources[strings.ToLower(name)]
			}
			if source == nil && colon && len(fields) > 1 && fields[1] != "" {
				literal := strings.TrimSuffix(name, path.Ext(name)) + "." + fields[1]
				source = sources[strings.ToLower(strconv.Itoa(number)+"/"+literal)]
			}
			if source == nil && len(name) > 0 {
				for _, suffix := range []string{"_", "$"} {
					candidate := strings.ToLower(strconv.Itoa(number) + "/" + name[:len(name)-1] + suffix)
					if sources[candidate] != nil {
						source, key = sources[candidate], candidate
						break
					}
				}
			}
			if source == nil && strings.HasSuffix(name, "$") {
				// PowerPoint mastering replaces '$' with consecutive fragment
				// numbers; only fragment zero carries the compression header.
				extents := []filesystemapi.ExtentSpec{}
				total := int64(0)
				for part := 0; part < 10; part++ {
					partName := strings.ToLower(name[:len(name)-1] + strconv.Itoa(part))
					var fragment starfile.File
					for candidate, file := range sources {
						if path.Base(candidate) == path.Base(partName) {
							if fragment != nil {
								return nil, fmt.Errorf("catalogue_plan: ambiguous fragment %s", partName)
							}
							fragment = file
						}
					}
					if fragment == nil {
						break
					}
					extents = append(extents, filesystemapi.ExtentSpec{Start: total, Size: fragment.Size(), File: fragment})
					total += fragment.Size()
				}
				if len(extents) > 1 {
					source = filesystemapi.NewGeneratedImage(name, total, extents)
					key = "fragments/" + strings.ToLower(name)
				}
			}
			output := path.Base(name)
			if colon && len(fields) >= 6 && strings.HasSuffix(output, "$") && fields[1] != "" {
				output = strings.TrimSuffix(output, path.Ext(output)) + "." + fields[1]
			}
			var value starlark.Value = starlark.None
			if source == nil {
				gaps = append(gaps, starlark.String("missing media file "+key))
			} else {
				if cached := decoded[key]; cached != nil {
					source = cached
				} else {
					source, err = decodeSetupFile(thread, source)
					if err != nil {
						return nil, fmt.Errorf("catalogue_plan: %s: %w", key, err)
					}
					decoded[key] = source
				}
				if data, ok := source.(*starfile.Bytes); ok && strings.ContainsAny(name, "$_") && data.Name != "" && data.Name != "kwaj.bin" && data.Name != "szdd.bin" {
					output = data.Name
				}
				value = source
			}
			dest := directory
			if colon && len(fields) >= 6 {
				dest = fields[2]
				if strings.HasPrefix(dest, "0:") {
					dest = strings.TrimRight(target, `\`) + `\` + strings.TrimLeft(dest[2:], `\`)
				} else if len(dest) >= 2 && dest[1] == ':' {
					dest = "[LOCATION:" + dest[:1] + "]\\" + strings.TrimLeft(dest[2:], `\`)
				}
			}
			if flat {
				if len(fields) > 2 {
					dest = strings.TrimRight(target, `\`) + `\` + fields[2]
				}
				dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String("launcher_filename_policy"), "expression": starlark.String(filename), "declaration": declaration}))
			}
			destination := strings.TrimRight(dest, `\`) + `\` + output
			resolved := !flat && source != nil && len(destination) > 2 && destination[1] == ':' && ((destination[0] >= 'A' && destination[0] <= 'Z') || (destination[0] >= 'a' && destination[0] <= 'z')) && !strings.ContainsAny(destination, "%$[")
			if !resolved && source != nil {
				dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String("destination"), "expression": starlark.String(destination), "declaration": declaration}))
			}
			files = append(files, acmeRecord(map[string]starlark.Value{"source": starlark.String(key), "file": value, "destination": starlark.String(destination), "resolved": starlark.Bool(resolved), "condition": starlark.String("SELECT " + section), "fields": starlark.String(row.text), "declaration": declaration}))
		}
	}
	// Flag 2 starts a logical file; flag 1 appends another independently
	// compressed fragment. The first row declares the complete output size.
	type joinedFile struct {
		row            *starlark.Dict
		extents        []filesystemapi.ExtentSpec
		size, expected int64
	}
	joins := map[string]*joinedFile{}
	combined := []starlark.Value{}
	for _, value := range files {
		row := value.(*starlark.Dict)
		fields, _ := acmeArguments(acmeText(row, "fields"))
		if len(fields) < 6 || !strings.Contains(fields[0], ":") || (fields[3] != "1" && fields[3] != "2") {
			combined = append(combined, row)
			continue
		}
		key := acmeText(row, "condition") + "\x00" + strings.ToLower(acmeText(row, "destination"))
		group := joins[key]
		if fields[3] == "2" {
			if group != nil {
				return nil, fmt.Errorf("catalogue_plan: repeated start fragment for %s", key)
			}
			expected, err := strconv.ParseInt(fields[5], 10, 64)
			if err != nil || expected < 0 {
				return nil, fmt.Errorf("catalogue_plan: invalid joined size")
			}
			group = &joinedFile{row: row, expected: expected}
			joins[key] = group
			combined = append(combined, row)
		} else if group == nil {
			gaps = append(gaps, starlark.String("continuation without first fragment: "+acmeText(row, "source")))
			combined = append(combined, row)
			continue
		}
		if file, ok := acmeGet(row, "file").(starfile.File); ok {
			group.extents = append(group.extents, filesystemapi.ExtentSpec{Start: group.size, Size: file.Size(), File: file})
			group.size += file.Size()
		}
	}
	for _, group := range joins {
		if group.size != group.expected {
			gaps = append(gaps, starlark.String(fmt.Sprintf("joined source size %d, expected %d: %s", group.size, group.expected, acmeText(group.row, "source"))))
			_ = group.row.SetKey(starlark.String("resolved"), starlark.False)
		}
		_ = group.row.SetKey(starlark.String("file"), filesystemapi.NewGeneratedImage(acmeText(group.row, "destination"), group.size, group.extents))
	}
	files = combined
	return acmeRecord(map[string]starlark.Value{"format": starlark.String("microsoft_setup_catalogue"), "files": starlark.NewList(files), "actions": starlark.NewList(actions), "runtime_dependencies": starlark.NewList(dependencies), "unresolved": starlark.NewList(gaps), "media": media, "script": s}), nil
}
