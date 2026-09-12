package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"maps"
	"path"
	"strconv"
	"strings"
)

func acmeGet(d *starlark.Dict, name string) starlark.Value {
	v, _, _ := d.Get(starlark.String(name))
	if v == nil {
		return starlark.None
	}
	return v
}
func acmeText(d *starlark.Dict, name string) string {
	s, _ := starlark.AsString(acmeGet(d, name))
	return s
}
func acmeRecord(values map[string]starlark.Value) *starlark.Dict {
	d := starlark.NewDict(len(values))
	for k, v := range values {
		_ = d.SetKey(starlark.String(k), v)
	}
	return d
}

func acmeLongName(value string) string {
	start := strings.IndexByte(value, '<')
	end := strings.LastIndexByte(value, '>')
	if start < 0 || end < start {
		return value
	}
	long := value[start+1 : end]
	if strings.ContainsAny(long, `\/%`) || strings.Contains(long, ":") {
		return long + value[end+1:]
	}
	parent := strings.LastIndexAny(value[:start], `\/`)
	return value[:parent+1] + long + value[end+1:]
}

func expandACMEReferences(value string, destinations, filenames map[string]string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '%' {
			out.WriteByte(value[i])
			i++
			continue
		}
		start := i
		i++
		file := i < len(value) && value[i] == 'F'
		if file {
			i++
		}
		digits := i
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
		if digits == i {
			out.WriteString(value[start:i])
			continue
		}
		values := destinations
		if file {
			values = filenames
		}
		if replacement, found := values[value[digits:i]]; found {
			out.WriteString(replacement)
		} else {
			out.WriteString(value[start:i])
		}
	}
	return out.String()
}

// acmePlanBuiltin retains conditional object paths as part of the plan. An
// unknown detection/custom predicate never silently selects the false arm.
func acmePlanBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table starfile.File
	var inf *infFile
	var media, predicates *starlark.Dict
	target, systemRoot, root := "", `C:\WINDOWS`, ""
	if err := starlark.UnpackArgs("acme_plan", args, kwargs, "table", &table, "inf", &inf, "media", &media, "target?", &target, "system_root?", &systemRoot, "root?", &root, "predicates?", &predicates); err != nil {
		return nil, err
	}
	parsed, err := acmeTableBuiltin(thread, nil, starlark.Tuple{table}, nil)
	if err != nil {
		return nil, err
	}
	stf := parsed.(*starlark.Dict)
	objects := acmeGet(stf, "objects").(*starlark.Dict)
	header := acmeGet(stf, "header").(*starlark.Dict)
	if root == "" {
		for _, key := range []string{"Batch Mode Root Object ID", "Floppy Mode Root Object ID"} {
			root = strings.TrimSpace(strings.SplitN(acmeText(header, key), ":", 2)[0])
			if root != "" {
				break
			}
		}
	}
	if root == "" {
		return nil, fmt.Errorf("acme_plan: no install root; supply root explicitly")
	}
	sources := map[string]starfile.File{}
	decoded := map[string]starfile.File{}
	for _, pair := range media.Items() {
		name, ok := starlark.AsString(pair[0])
		f, valid := pair[1].(starfile.File)
		if !ok || !valid {
			return nil, fmt.Errorf("acme_plan: media must map relative names to files")
		}
		sources[strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/"))] = f
	}
	destinations, filenames := map[string]string{}, map[string]string{}
	if target == "" {
		for _, pair := range objects.Items() {
			row := pair[1].(*starlark.Dict)
			if acmeText(row, "type") == "AppSearch" {
				a := acmeGet(row, "arguments").(*starlark.List)
				if a.Len() > 0 {
					target, _ = starlark.AsString(a.Index(0))
					break
				}
			}
		}
	}
	expand := func(value, current string) string {
		// Only supplied Windows and traversal destinations are concrete.
		// Shared/system/program folders and source scopes require setup queries.
		value = strings.NewReplacer("%w", systemRoot, "%W", systemRoot, "%D", current, "%d", current).Replace(value)
		value = expandACMEReferences(value, destinations, filenames)
		return strings.ReplaceAll(value, "/", `\`)
	}
	// AppSearch defaults can refer to earlier search objects even when the
	// searches are initialization objects outside the executable root graph.
	for pass := 0; pass < objects.Len(); pass++ {
		changed := false
		for _, pair := range objects.Items() {
			row := pair[1].(*starlark.Dict)
			if acmeText(row, "type") != "AppSearch" {
				continue
			}
			id := acmeText(row, "id")
			a := acmeGet(row, "arguments").(*starlark.List)
			if a.Len() == 0 {
				continue
			}
			value, _ := starlark.AsString(a.Index(0))
			value = expand(acmeLongName(value), target)
			if !strings.Contains(value, "%") && destinations[id] != value {
				destinations[id] = value
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	dependencies := []starlark.Value{}
	dependency := func(kind, expression string, declaration starlark.Value) {
		dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String(kind), "expression": starlark.String(expression), "declaration": declaration}))
	}
	steps := 0
	files, actions, gaps := []starlark.Value{}, []starlark.Value{}, []starlark.Value{}
	visiting := map[string]bool{}
	seen := map[string]bool{}
	var walk func(string, string, []string, int) error
	walk = func(id, inherited string, conditions []string, depth int) error {
		steps++
		if steps > 1000000 {
			return fmt.Errorf("acme_plan: object expansion exceeds bound")
		}
		if depth > 256 {
			return fmt.Errorf("acme_plan: object graph exceeds depth bound")
		}
		identity := id + "\x00" + inherited + "\x00" + strings.Join(conditions, "&")
		if seen[identity] {
			return nil
		}
		seen[identity] = true
		if visiting[id] {
			return fmt.Errorf("acme_plan: cyclic object %s", id)
		}
		visiting[id] = true
		defer delete(visiting, id)
		value := acmeGet(objects, id)
		row, ok := value.(*starlark.Dict)
		if !ok {
			return fmt.Errorf("acme_plan: missing object %s", id)
		}
		kind := acmeText(row, "type")
		data := strings.Trim(strings.TrimSpace(acmeText(row, "data")), `"`)
		argv := acmeGet(row, "arguments").(*starlark.List)
		a := []string{}
		for i := 0; i < argv.Len(); i++ {
			s, _ := starlark.AsString(argv.Index(i))
			a = append(a, s)
		}
		dest := inherited
		if v := acmeText(row, "destination"); v != "" {
			parts, err := acmeArguments(v)
			if err != nil {
				return err
			}
			if len(parts) > 0 {
				dest = expand(acmeLongName(parts[0]), inherited)
			}
		}
		// Object destinations are scoped to this traversal path. A value
		// computed in one optional branch must not resolve another branch.
		previousDestinations, previousFilenames := destinations, filenames
		destinations, filenames = maps.Clone(destinations), maps.Clone(filenames)
		defer func() { destinations, filenames = previousDestinations, previousFilenames }()
		destinations[id] = dest
		cond := []starlark.Value{}
		for _, c := range conditions {
			cond = append(cond, starlark.String(c))
		}
		provenance := acmeRecord(map[string]starlark.Value{"object": starlark.String(id), "line": acmeGet(row, "line"), "offset": acmeGet(row, "offset")})
		action := acmeRecord(map[string]starlark.Value{"type": starlark.String(kind), "arguments": argv, "destination": starlark.String(dest), "conditions": starlark.NewList(cond), "provenance": provenance})
		actions = append(actions, action)
		switch kind {
		case "CustomDlg", "OptionDlg", "YesNoDlg", "AppMainDlg":
			choices, common, _ := strings.Cut(data, ":")
			for _, child := range strings.Fields(choices) {
				next := append(append([]string(nil), conditions...), "SELECT "+id+"="+child)
				if err := walk(child, dest, next, depth+1); err != nil {
					return err
				}
			}
			for _, child := range strings.Fields(common) {
				if err := walk(child, dest, conditions, depth+1); err != nil {
					return err
				}
			}
			return nil
		case "Group":
			for _, child := range strings.Fields(data) {
				if err := walk(child, dest, conditions, depth+1); err != nil {
					return err
				}
			}
			return nil
		case "Depend", "DependAsk":
			question := strings.IndexByte(data, '?')
			colon := strings.IndexByte(data, ':')
			if question < 0 {
				gaps = append(gaps, starlark.String("object "+id+": unrecognized dependency expression"))
				return nil
			}
			if colon < 0 {
				colon = len(data)
			}
			predicate := strings.TrimSpace(data[:question])
			branches := []string{data[question+1 : colon], ""}
			if colon < len(data) {
				branches[1] = data[colon+1:]
			}
			known := false
			truth := false
			if predicates != nil {
				v, found, _ := predicates.Get(starlark.String(predicate))
				if found {
					b, ok := v.(starlark.Bool)
					if !ok {
						return fmt.Errorf("acme_plan: predicate %s must be boolean", predicate)
					}
					known = true
					truth = bool(b)
				}
			}
			for arm, branch := range branches {
				if known && ((arm == 0) != truth) {
					continue
				}
				next := append([]string(nil), conditions...)
				if !known {
					c := predicate
					if arm == 1 {
						c = "NOT " + c
					}
					next = append(next, c)
				}
				for _, child := range strings.Fields(branch) {
					if err := walk(child, dest, next, depth+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		fileKinds := map[string]bool{"CopySection": true, "CopyFile": true, "InstallSysFile": true, "InstallShared": true, "InstallTTFFile": true, "InstallOLE": true, "InstallProofTool": true, "InstallProofLex": true, "CompanionFile": true, "CopyBindExe": true}
		if kind == "CompanionFile" && len(a) > 0 {
			parent, section, found := strings.Cut(a[0], ":")
			if found {
				_ = action.SetKey(starlark.String("companion"), starlark.String(strings.TrimSpace(parent)))
				a[0] = strings.Trim(strings.TrimSpace(section), `"`)
			}
		}
		if fileKinds[kind] && len(a) > 0 {
			section, found, err := infSection(inf.json, a[0])
			if err != nil {
				return err
			}
			if !found {
				gaps = append(gaps, starlark.String("object "+id+": missing INF section "+a[0]))
				return nil
			}
			matched := false
			for _, entry := range section.Items() {
				key, _ := starlark.AsString(entry[0])
				if kind != "CopySection" && len(a) > 1 && !strings.EqualFold(strings.Trim(key, `"`), a[1]) {
					continue
				}
				matched = true
				rows := []starlark.Value{entry[1]}
				if list, ok := entry[1].(*starlark.List); ok && list.Len() > 0 {
					if _, nested := list.Index(0).(*starlark.List); nested {
						rows = nil
						for i := 0; i < list.Len(); i++ {
							rows = append(rows, list.Index(i))
						}
					}
				}
				for _, r := range rows {
					list, ok := r.(*starlark.List)
					if !ok || list.Len() < 2 {
						continue
					}
					if list.Len() > 4 {
						if flag, _ := starlark.AsString(list.Index(4)); strings.EqualFold(flag, "!COPY") {
							actions = append(actions, acmeRecord(map[string]starlark.Value{"type": starlark.String("file_policy"), "inf_section": starlark.String(a[0]), "inf_key": entry[0], "inf_fields": r, "provenance": provenance, "conditions": starlark.NewList(cond)}))
							continue
						}
					}
					sourceName, _ := starlark.AsString(list.Index(1))
					if sourceName == "" {
						continue
					}
					normalized := strings.TrimPrefix(strings.ReplaceAll(acmeLongName(sourceName), `\`, "/"), "/")
					output := path.Base(normalized)
					if list.Len() > 11 {
						if name, ok := starlark.AsString(list.Index(11)); ok && name != "" {
							output = acmeLongName(name)
						}
					}
					source := sources[strings.ToLower(normalized)]
					if source == nil {
						short, _, _ := strings.Cut(sourceName, "<")
						source = sources[strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(short, `\`, "/"), "/"))]
					}
					if source == nil {
						disk, _ := starlark.AsString(list.Index(0))
						short, _, _ := strings.Cut(sourceName, "<")
						candidates := []string{normalized, strings.ReplaceAll(short, `\`, "/")}
						for _, candidate := range candidates {
							compressed := candidate
							if len(compressed) > 0 {
								compressed = compressed[:len(compressed)-1] + "_"
							}
							for _, name := range []string{disk + "/" + candidate, compressed, disk + "/" + compressed} {
								if found := sources[strings.ToLower(name)]; found != nil {
									source = found
									break
								}
							}
							if source != nil {
								break
							}
						}
					}
					if source != nil {
						disk, _ := starlark.AsString(list.Index(0))
						cacheKey := disk + "/" + normalized
						if cached := decoded[cacheKey]; cached != nil {
							source = cached
						} else {
							var err error
							source, err = decodeSetupFile(thread, source)
							if err != nil {
								return fmt.Errorf("acme_plan: %s: %w", sourceName, err)
							}
							decoded[cacheKey] = source
						}
					}
					var f starlark.Value = starlark.None
					if source != nil {
						f = source
					} else {
						gaps = append(gaps, starlark.String("object "+id+": missing media file "+sourceName))
					}
					destination := strings.TrimRight(dest, `\`) + `\` + output
					resolved := source != nil && !strings.Contains(destination, "%") && len(destination) > 2 && destination[1] == ':'
					if strings.Contains(destination, "%") {
						dependency("destination", destination, provenance)
					}
					files = append(files, acmeRecord(map[string]starlark.Value{"source": starlark.String(sourceName), "file": f, "destination": starlark.String(destination), "conditions": starlark.NewList(cond), "resolved": starlark.Bool(resolved), "provenance": provenance, "inf_section": starlark.String(a[0]), "inf_key": entry[0], "inf_fields": r}))
					filenames[id] = output
				}
			}
			if !matched {
				gaps = append(gaps, starlark.String("object "+id+": missing INF symbol"))
			}
		}
		if kind == "CustomAction" && len(a) > 1 {
			_ = action.SetKey(starlark.String("library"), starlark.String(a[0]))
			_ = action.SetKey(starlark.String("entry_point"), starlark.String(a[1]))
			if f := sources[strings.ToLower(strings.ReplaceAll(a[0], `\`, "/"))]; f != nil {
				_ = action.SetKey(starlark.String("binary"), f)
			}
		}
		return nil
	}
	if _, err := strconv.ParseUint(root, 10, 32); err != nil {
		return nil, fmt.Errorf("acme_plan: invalid root %s", root)
	}
	if err := walk(root, target, nil, 0); err != nil {
		return nil, err
	}
	custom := []starlark.Value{}
	for _, action := range actions {
		if acmeText(action.(*starlark.Dict), "type") == "CustomAction" {
			custom = append(custom, action)
			dependency("custom_action", acmeText(action.(*starlark.Dict), "entry_point"), action)
		}
	}
	return acmeRecord(map[string]starlark.Value{"format": starlark.String("microsoft_acme"), "root": starlark.String(root), "target": starlark.String(target), "files": starlark.NewList(files), "actions": starlark.NewList(actions), "custom_actions": starlark.NewList(custom), "objects": objects, "inf": inf, "unresolved": starlark.NewList(gaps), "media": media, "runtime_dependencies": starlark.NewList(dependencies)}), nil
}
