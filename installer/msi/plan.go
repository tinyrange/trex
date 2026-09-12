package msi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/archive/cab"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type PlanOptions struct {
	Properties map[string]string
	Features   []string
	Media      map[string]starfile.File
}
type planContext struct {
	db                                                *Database
	properties                                        map[string]string
	unknown                                           map[string]bool
	directories, sourceDirs, componentDirs, filePaths map[string]string
	selected                                          map[string]bool
	unresolved                                        []string
	runtime                                           []starlark.Value
}

func text(row map[string]starlark.Value, key string) string {
	v := row[key]
	s, _ := starlark.AsString(v)
	return s
}
func integer(row map[string]starlark.Value, key string) int {
	v := row[key]
	if v == nil || v == starlark.None {
		return 0
	}
	n, _ := starlark.AsInt32(v)
	return n
}
func record(fields map[string]starlark.Value) *starlark.Dict {
	d := starlark.NewDict(len(fields))
	for k, v := range fields {
		if v == nil {
			v = starlark.None
		}
		_ = d.SetKey(starlark.String(k), v)
	}
	return d
}
func winJoin(parent, name string) string {
	if name == "." || name == "" {
		return parent
	}
	return strings.TrimRight(parent, `\/`) + `\` + strings.Trim(name, `\/`)
}
func longName(name string) string {
	if _, long, found := strings.Cut(name, "|"); found {
		return long
	}
	return name
}

func directoryNames(value string, shortSource bool) (string, string) {
	// The Whistler SDK repeats the complete target:source pair on each
	// side of '|', rather than giving each filename its own short/long pair.
	short, long, paired := strings.Cut(value, "|")
	if paired && strings.Contains(short, ":") && strings.Contains(long, ":") && strings.Count(value, "|") == 1 {
		dest, source, _ := strings.Cut(long, ":")
		if shortSource {
			_, source, _ = strings.Cut(short, ":")
		}
		return dest, source
	}
	dest, source, _ := strings.Cut(value, ":")
	if source == "" {
		source = dest
	}
	if shortSource {
		source, _, _ = strings.Cut(source, "|")
	} else {
		source = longName(source)
	}
	return longName(dest), source
}
func (p *planContext) conditionState(value, where string) (bool, bool) {
	yes, err := evaluateCondition(value, p.properties, p.unknown)
	if err != nil {
		var dependency runtimeConditionError
		if errors.As(err, &dependency) {
			p.dependency("condition", value, starlark.String(where))
			return true, false
		}
		p.unresolved = append(p.unresolved, where+": "+err.Error())
		return false, true
	}
	return yes, true
}
func (p *planContext) condition(value, where string) bool {
	yes, _ := p.conditionState(value, where)
	return yes
}
func (p *planContext) format(value string) string {
	var out strings.Builder
	for len(value) > 0 {
		start := strings.IndexByte(value, '[')
		if start < 0 {
			out.WriteString(value)
			break
		}
		out.WriteString(value[:start])
		value = value[start+1:]
		end := strings.IndexByte(value, ']')
		if end < 0 {
			out.WriteByte('[')
			out.WriteString(value)
			break
		}
		key := value[:end]
		value = value[end+1:]
		if strings.HasPrefix(key, `\`) {
			out.WriteString(strings.TrimPrefix(key, `\`))
			continue
		}
		if key == "~" {
			out.WriteByte(0)
			continue
		}
		switch {
		case strings.HasPrefix(key, "!"):
			p.dependency("short_path", key, starlark.String(key[1:]))
			out.WriteString("[" + key + "]")
		case strings.HasPrefix(key, "#"):
			v, found := p.filePaths[key[1:]]
			if !found {
				p.unresolved = append(p.unresolved, "formatted file reference: "+key)
			}
			out.WriteString(v)
		case strings.HasPrefix(key, "$"):
			v, found := p.componentDirs[key[1:]]
			if !found {
				p.unresolved = append(p.unresolved, "formatted component reference: "+key)
			}
			out.WriteString(v)
		default:
			if p.unknown[key] {
				p.dependency("property", key, starlark.String(key))
				out.WriteString("[" + key + "]")
				continue
			}
			if v, found := p.directories[key]; found {
				out.WriteString(v)
			} else {
				out.WriteString(p.properties[key])
			}
		}
	}
	return out.String()
}

// Plan resolves native files and declarative table effects for an explicit
// fresh-install environment. Unmodeled actions stay visible with provenance.
func (d *Database) Plan(options PlanOptions) (*starlark.Dict, error) {
	wordCount, err := d.summaryWordCount()
	if err != nil {
		return nil, err
	}
	sourceName := func(name string) string {
		if wordCount&1 != 0 {
			short, _, _ := strings.Cut(name, "|")
			return short
		}
		return longName(name)
	}
	p := &planContext{db: d, properties: map[string]string{}, directories: map[string]string{}, sourceDirs: map[string]string{}, componentDirs: map[string]string{}, filePaths: map[string]string{}, selected: map[string]bool{}}
	for _, row := range d.Tables["Property"] {
		p.properties[text(row, "Property")] = text(row, "Value")
	}
	maps.Copy(p.properties, options.Properties)
	p.unknown = map[string]bool{}
	for _, row := range d.Tables["AppSearch"] {
		name := text(row, "Property")
		if _, supplied := options.Properties[name]; !supplied {
			p.unknown[name] = true
		}
	}
	for _, name := range []string{"AppSearch", "RegLocator", "CompLocator", "IniLocator", "DrLocator", "Signature", "CCPSearch", "RMCCPSearch"} {
		for _, row := range d.Tables[name] {
			p.dependency("machine_query", name, record(row))
		}
	}
	for _, name := range []string{"InstallUISequence", "InstallExecuteSequence", "AdminUISequence", "AdminExecuteSequence", "AdvtExecuteSequence"} {
		for _, row := range d.Tables[name] {
			if integer(row, "Sequence") <= 0 || name != "InstallExecuteSequence" {
				p.dependency("scheduled_action", name, record(row))
			}
		}
	}
	custom := map[string]map[string]starlark.Value{}
	for _, row := range d.Tables["CustomAction"] {
		custom[text(row, "Action")] = row
	}
	sequence := append([]map[string]starlark.Value(nil), d.Tables["InstallExecuteSequence"]...)
	sort.SliceStable(sequence, func(i, j int) bool { return integer(sequence[i], "Sequence") < integer(sequence[j], "Sequence") })
	// Property actions before costing contribute to feature/directory selection.
	for _, row := range sequence {
		if text(row, "Action") == "CostFinalize" {
			break
		}
		if integer(row, "Sequence") <= 0 {
			continue
		}
		action := custom[text(row, "Action")]
		if action != nil && integer(action, "Type")&63 == 51 {
			yes, known := p.conditionState(text(row, "Condition"), text(row, "Action"))
			if yes && known {
				p.properties[text(action, "Source")] = p.format(text(action, "Target"))
			}
			if !known {
				p.unknown[text(action, "Source")] = true
			}
		}
	}
	level := 1
	if value, err := strconv.Atoi(p.properties["INSTALLLEVEL"]); err == nil {
		level = value
	}
	requested := map[string]bool{}
	for _, name := range options.Features {
		requested[name] = true
	}
	featureSelected := map[string]bool{}
	featureRows := map[string]map[string]starlark.Value{}
	featureLevels := map[string]int{}
	for _, row := range d.Tables["Feature"] {
		name := text(row, "Feature")
		featureRows[name] = row
		n := integer(row, "Level")
		for _, condition := range d.Tables["Condition"] {
			if text(condition, "Feature_") == name {
				yes, known := p.conditionState(text(condition, "Condition"), "Feature "+name)
				if yes && known {
					n = integer(condition, "Level")
				}
				if !known {
					n = 1
				}
			}
		}
		chosen := n > 0 && n <= level
		if options.Features != nil {
			chosen = n > 0 && (requested[name] || requested["ALL"])
		}
		featureLevels[name] = n
		featureSelected[name] = chosen
		p.properties["!"+name] = "2"
		p.properties["&"+name] = "2"
		if chosen {
			p.properties["&"+name] = "3"
		}
	}
	for name := range requested {
		if name != "ALL" && featureRows[name] == nil {
			return nil, fmt.Errorf("msi: unknown requested feature %s", name)
		}
	}
	for name, row := range featureRows {
		parent := text(row, "Feature_Parent")
		seen := map[string]bool{name: true}
		for depth := 1; parent != ""; depth++ {
			if depth >= 16 || seen[parent] {
				return nil, fmt.Errorf("msi: cyclic or excessive Feature tree at %s", name)
			}
			seen[parent] = true
			ancestor := featureRows[parent]
			if ancestor == nil {
				return nil, fmt.Errorf("msi: missing parent feature %s", parent)
			}
			if featureLevels[parent] == 0 {
				featureSelected[name] = false
			}
			parent = text(ancestor, "Feature_Parent")
		}
	}
	for pass := 0; pass < 16; pass++ {
		changed := false
		for name, row := range featureRows {
			parent := text(row, "Feature_Parent")
			if parent == "" {
				continue
			}
			if featureSelected[name] && !featureSelected[parent] && featureLevels[parent] > 0 {
				featureSelected[parent] = true
				changed = true
			}
			if integer(row, "Attributes")&18 == 18 && featureLevels[name] > 0 && featureSelected[parent] && !featureSelected[name] {
				featureSelected[name] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for name, selected := range featureSelected {
		p.properties["&"+name] = "2"
		if selected {
			p.properties["&"+name] = "3"
		}
	}
	for _, row := range d.Tables["FeatureComponents"] {
		if featureSelected[text(row, "Feature_")] {
			p.selected[text(row, "Component_")] = true
		}
	}
	for _, row := range d.Tables["Component"] {
		name := text(row, "Component")
		p.properties["?"+name] = "2"
		p.properties["$"+name] = "2"
	}
	for _, row := range d.Tables["Component"] {
		name := text(row, "Component")
		if p.selected[name] && p.condition(text(row, "Condition"), "Component "+name) {
			p.properties["$"+name] = "3"
		} else {
			p.selected[name] = false
		}
	}
	dirs := map[string]map[string]starlark.Value{}
	for _, row := range d.Tables["Directory"] {
		dirs[text(row, "Directory")] = row
	}
	visiting := map[string]bool{}
	var resolve func(string) error
	resolve = func(name string) error {
		if _, ok := p.directories[name]; ok {
			return nil
		}
		if visiting[name] {
			return fmt.Errorf("msi: cyclic Directory at %s", name)
		}
		visiting[name] = true
		row := dirs[name]
		if row == nil {
			return fmt.Errorf("msi: missing Directory %s", name)
		}
		parent := text(row, "Directory_Parent")
		dest, src := directoryNames(text(row, "DefaultDir"), wordCount&1 != 0)
		if parent == "" || parent == name {
			p.directories[name] = p.properties[name]
			if p.directories[name] == "" {
				p.directories[name] = p.properties["ROOTDRIVE"]
			}
			p.sourceDirs[name] = ""
		} else {
			if err := resolve(parent); err != nil {
				return err
			}
			p.directories[name] = winJoin(p.directories[parent], dest)
			p.sourceDirs[name] = strings.TrimPrefix(path.Join(strings.ReplaceAll(p.sourceDirs[parent], `\`, "/"), src), "./")
		}
		if override := p.properties[name]; override != "" {
			p.directories[name] = override
		}
		if p.unknown[name] {
			p.directories[name] = "[" + name + "]"
		}
		delete(visiting, name)
		return nil
	}
	for name := range dirs {
		if err := resolve(name); err != nil {
			return nil, err
		}
	}
	for _, row := range d.Tables["Component"] {
		name := text(row, "Component")
		p.componentDirs[name] = p.directories[text(row, "Directory_")]
	}
	for _, row := range d.Tables["File"] {
		p.filePaths[text(row, "File")] = winJoin(p.componentDirs[text(row, "Component_")], longName(text(row, "FileName")))
	}
	for _, row := range d.Tables["LaunchCondition"] {
		if !p.condition(text(row, "Condition"), "LaunchCondition") {
			p.dependency("prerequisite", text(row, "Condition"), record(row))
		}
	}
	media := map[string]starfile.File{}
	for name, file := range options.Media {
		media[strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(name, "/"), `\`, "/"))] = file
	}
	lookup := func(name string) starfile.File {
		return media[strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(name, "/"), `\`, "/"))]
	}
	cabinets := map[string]*cab.Archive{}
	mediaRows := append([]map[string]starlark.Value(nil), d.Tables["Media"]...)
	sort.Slice(mediaRows, func(i, j int) bool { return integer(mediaRows[i], "DiskId") < integer(mediaRows[j], "DiskId") })
	files := []starlark.Value{}
	plannedFiles := map[string]starfile.File{}
	for index, row := range d.Tables["File"] {
		component := text(row, "Component_")
		if !p.selected[component] {
			continue
		}
		id := text(row, "File")
		destination := p.filePaths[id]
		var source starfile.File
		cabinetName := ""
		for _, m := range mediaRows {
			if integer(row, "Sequence") <= integer(m, "LastSequence") {
				cabinetName = text(m, "Cabinet")
				break
			}
		}
		attributes := integer(row, "Attributes")
		if attributes&24576 == 24576 {
			return nil, fmt.Errorf("msi: File %s has conflicting compression flags", id)
		}
		compressed := attributes&16384 != 0 || (attributes&8192 == 0 && wordCount&2 != 0)
		if !compressed || wordCount&4 != 0 {
			cabinetName = ""
		}
		if cabinetName != "" {
			archive := cabinets[cabinetName]
			if archive == nil {
				var cabinetFile starfile.File
				if strings.HasPrefix(cabinetName, "#") {
					cabinetFile = d.streams[cabinetName[1:]]
				} else {
					cabinetFile = lookup(cabinetName)
				}
				if cabinetFile != nil {
					var err error
					archive, err = cab.Open(cabinetFile, true)
					if err != nil {
						return nil, fmt.Errorf("msi: cabinet %s: %w", cabinetName, err)
					}
					cabinets[cabinetName] = archive
				}
			}
			if archive != nil {
				entry, err := archive.LookupExact(id)
				if err == nil {
					source = entry
				}
			}
		} else {
			componentRow := map[string]starlark.Value(nil)
			for _, c := range d.Tables["Component"] {
				if text(c, "Component") == component {
					componentRow = c
					break
				}
			}
			dir := p.sourceDirs[text(componentRow, "Directory_")]
			if wordCount&2 != 0 {
				dir = ""
			}
			source = lookup(path.Join(dir, sourceName(text(row, "FileName"))))
		}
		resolved := source != nil && len(destination) >= 3 && destination[1] == ':'
		if source == nil {
			p.unresolved = append(p.unresolved, "File "+id+": missing source in "+cabinetName)
		} else if source.Size() != int64(integer(row, "FileSize")) {
			p.unresolved = append(p.unresolved, "File "+id+": source size mismatch")
			resolved = false
		}
		if len(destination) < 3 || destination[1] != ':' {
			p.dependency("destination", destination, record(map[string]starlark.Value{"table": starlark.String("File"), "key": starlark.String(id)}))
			resolved = false
		}
		value := starlark.Value(starlark.None)
		if source != nil {
			value = source
			plannedFiles[id] = source
		}
		provenance := record(map[string]starlark.Value{"table": starlark.String("File"), "row": starlark.MakeInt(index), "key": starlark.String(id)})
		fields := map[string]starlark.Value{"source": starlark.String(id), "file": value, "destination": starlark.String(destination), "component": starlark.String(component), "resolved": starlark.Bool(resolved), "attributes": row["Attributes"], "selection": starlark.String("fresh_install_with_inputs"), "version": row["Version"], "language": row["Language"], "provenance": provenance}
		files = append(files, record(fields))
	}
	componentViews := map[string]string{}
	for _, row := range d.Tables["Component"] {
		view := "32"
		if integer(row, "Attributes")&256 != 0 {
			view = "64"
		}
		componentViews[text(row, "Component")] = view
	}
	registry := []starlark.Value{}
	definitiveRegistry := []starlark.Value{}
	for index, row := range d.Tables["Registry"] {
		if !p.selected[text(row, "Component_")] {
			continue
		}
		root := map[int]string{0: "HKEY_CLASSES_ROOT", 1: "HKEY_CURRENT_USER", 2: "HKEY_LOCAL_MACHINE", 3: "HKEY_USERS"}[integer(row, "Root")]
		if integer(row, "Root") == -1 {
			root = "HKEY_CURRENT_USER"
			if p.properties["ALLUSERS"] == "1" {
				root = "HKEY_LOCAL_MACHINE"
			}
		}
		if integer(row, "Root") == -1 && p.properties["ALLUSERS"] == "2" {
			root = "[INSTALLCONTEXT]"
			p.dependency("install_context", "ALLUSERS=2", record(row))
		}
		key, name, value := p.format(text(row, "Key")), p.format(text(row, "Name")), p.format(text(row, "Value"))
		kind := "REG_SZ"
		merge := "replace"
		var data starlark.Value = starlark.String(value)
		if strings.HasPrefix(value, "#x") {
			kind = "REG_BINARY"
			decoded, err := hex.DecodeString(value[2:])
			if err != nil {
				p.unresolved = append(p.unresolved, "Registry "+text(row, "Registry")+": invalid binary value")
				continue
			}
			data = starlark.Bytes(decoded)
		} else if strings.HasPrefix(value, "#%") {
			kind = "REG_EXPAND_SZ"
			data = starlark.String(value[2:])
		} else if strings.HasPrefix(value, "##") {
			data = starlark.String(value[1:])
		} else if strings.HasPrefix(value, "#") {
			n, err := strconv.ParseInt(value[1:], 10, 64)
			if n < -2147483648 || n > 4294967295 {
				err = fmt.Errorf("DWORD out of range")
			}
			if err != nil {
				p.unresolved = append(p.unresolved, "Registry "+text(row, "Registry")+": invalid DWORD")
				continue
			}
			kind = "REG_DWORD"
			data = starlark.MakeUint(uint(uint32(n)))
		} else if strings.ContainsRune(value, 0) {
			kind = "REG_MULTI_SZ"
			if strings.HasPrefix(value, "\x00") && !strings.HasSuffix(value, "\x00") {
				merge = "append"
			}
			if strings.HasSuffix(value, "\x00") && !strings.HasPrefix(value, "\x00") {
				merge = "prepend"
			}
			parts := []starlark.Value{}
			for _, s := range strings.Split(strings.Trim(value, "\x00"), "\x00") {
				parts = append(parts, starlark.String(s))
			}
			data = starlark.NewList(parts)
		}
		operation, phase, uninstall := "set_value", "install", "remove_value"
		if row["Value"] == starlark.None && (name == "+" || name == "*" || name == "-") {
			operation, uninstall = "create_key", "keep_key"
			if name == "*" {
				uninstall = "delete_key"
			}
			if name == "-" {
				operation, phase, uninstall = "delete_key", "uninstall", "delete_key"
			}
			name = ""
		}
		entry := record(map[string]starlark.Value{"operation": starlark.String(operation), "phase": starlark.String(phase), "uninstall_policy": starlark.String(uninstall), "merge": starlark.String(merge), "component": row["Component_"], "view": starlark.String(componentViews[text(row, "Component_")]), "root": starlark.String(root), "key": starlark.String(key), "name": starlark.String(name), "type": starlark.String(kind), "data": data, "resolved": starlark.True, "provenance": record(map[string]starlark.Value{"table": starlark.String("Registry"), "row": starlark.MakeInt(index), "key": row["Registry"]})})
		resolved := !strings.Contains(root+key+name+value, "[")
		_ = entry.SetKey(starlark.String("resolved"), starlark.Bool(resolved))
		registry = append(registry, entry)
		if resolved && phase == "install" {
			definitiveRegistry = append(definitiveRegistry, entry)
		}
	}
	actions := []starlark.Value{}
	for _, row := range sequence {
		applicable, conditionKnown := p.conditionState(text(row, "Condition"), text(row, "Action"))
		applicable = applicable && integer(row, "Sequence") > 0
		name := text(row, "Action")
		action := custom[name]
		if action == nil {
			continue
		}
		kind := integer(action, "Type") & 63
		if kind == 51 && applicable && conditionKnown {
			p.properties[text(action, "Source")] = p.format(text(action, "Target"))
		}
		if kind == 19 && applicable {
			p.dependency("prerequisite", p.format(text(action, "Target")), record(action))
			continue
		}
		fields := maps.Clone(action)
		fields["applicable_with_inputs"] = starlark.Bool(applicable)
		if !conditionKnown {
			fields["applicable_with_inputs"] = starlark.None
		}
		fields["condition"] = row["Condition"]
		fields["sequence"] = row["Sequence"]
		fields["target_expanded"] = starlark.String(p.format(text(action, "Target")))
		flags := integer(action, "Type")
		phase := "immediate"
		if flags&1024 != 0 {
			phase = "deferred"
			if flags&256 != 0 {
				phase = "rollback"
			}
			if flags&512 != 0 {
				phase = "commit"
			}
		}
		fields["phase"] = starlark.String(phase)
		fields["ignore_exit_code"] = starlark.Bool(flags&64 != 0)
		fields["provenance"] = record(map[string]starlark.Value{"table": starlark.String("CustomAction"), "key": starlark.String(name)})
		if flags&48 == 0 {
			for _, binary := range d.Tables["Binary"] {
				if text(binary, "Name") == text(action, "Source") {
					fields["binary"] = binary["Data"]
				}
			}
		}
		fields["resolved"] = starlark.False
		actions = append(actions, record(fields))
		p.dependency("custom_action", name, record(fields))
	}
	folders := []starlark.Value{}
	for _, row := range d.Tables["CreateFolder"] {
		if !p.selected[text(row, "Component_")] {
			continue
		}
		destination, found := p.directories[text(row, "Directory_")]
		if !found {
			p.unresolved = append(p.unresolved, "CreateFolder: missing Directory "+text(row, "Directory_"))
			continue
		}
		folders = append(folders, record(map[string]starlark.Value{"operation": starlark.String("create_directory"), "path": starlark.String(destination), "component": row["Component_"], "provenance": record(map[string]starlark.Value{"table": starlark.String("CreateFolder"), "key": row["Directory_"]})}))
	}
	effects := p.effectPlans()
	sort.Strings(p.unresolved)
	gaps := []starlark.Value{}
	for _, g := range p.unresolved {
		gaps = append(gaps, starlark.String(g))
	}
	inputProperties := starlark.NewDict(len(options.Properties))
	keys := []string{}
	for key := range options.Properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_ = inputProperties.SetKey(starlark.String(key), starlark.String(options.Properties[key]))
	}
	featureValues := []starlark.Value{}
	keys = nil
	for name, selected := range featureSelected {
		if selected {
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	for _, name := range keys {
		featureValues = append(featureValues, starlark.String(name))
	}
	return record(map[string]starlark.Value{"format": starlark.String("msi"), "input_properties": inputProperties, "selected_features": starlark.NewList(featureValues), "files": starlark.NewList(files), "directories": starlark.NewList(folders), "effects": starlark.NewList(effects), "definitive_registry_writes": starlark.NewList(definitiveRegistry), "registry_writes": starlark.NewList(registry), "runtime_dependencies": starlark.NewList(p.runtime), "database": d, "custom_actions": starlark.NewList(actions), "unresolved": starlark.NewList(gaps)}), nil
}
