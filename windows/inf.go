package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

func infBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("inf", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	var data []byte
	switch value := value.(type) {
	case starfile.File:
		var err error
		data, err = starfile.ReadAll(value)
		if err != nil {
			return nil, err
		}
	case starlark.String:
		data = []byte(value)
	case starlark.Bytes:
		data = []byte(value)
	default:
		return nil, fmt.Errorf("inf: got %s, want file, string, or bytes", value.Type())
	}
	parsed, err := parseINF(decodeINFText(data))
	if err != nil {
		return nil, err
	}
	return &infFile{json: parsed}, nil
}

func decodeINFText(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		return decodeUTF16LE(data[2:])
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		data = data[2:]
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
		}
		return string(utf16.Decode(units))
	case bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}):
		return string(data[3:])
	default:
		return string(data)
	}
}

type infFile struct {
	json *starlark.Dict
}

type infInstallSection struct {
	name    string
	section *starlark.Dict
}

func (f *infFile) String() string       { return "<windows.inf>" }
func (f *infFile) Type() string         { return "inf" }
func (f *infFile) Freeze()              { f.json.Freeze() }
func (f *infFile) Truth() starlark.Bool { return starlark.True }
func (f *infFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *infFile) Get(key starlark.Value) (starlark.Value, bool, error) {
	return f.json.Get(key)
}
func (f *infFile) Attr(name string) (starlark.Value, error) {
	switch name {
	case "json":
		return f.json, nil
	case "section":
		return starlark.NewBuiltin("section", f.sectionBuiltin), nil
	case "install_sections":
		return starlark.NewBuiltin("install_sections", f.installSectionsBuiltin), nil
	case "section_patches":
		return starlark.NewBuiltin("section_patches", f.sectionPatchesBuiltin), nil
	case "hkr_patches":
		return starlark.NewBuiltin("hkr_patches", f.hkrPatchesBuiltin), nil
	case "hkr_keys":
		return starlark.NewBuiltin("hkr_keys", f.hkrKeysBuiltin), nil
	}
	return nil, nil
}
func (f *infFile) AttrNames() []string {
	return []string{"hkr_keys", "hkr_patches", "install_sections", "json", "section", "section_patches"}
}

// hkrKeysBuiltin returns explicit key-only AddReg targets from the referenced
// sections. Values and key structure remain separate so callers can preserve
// empty keys when constructing a registry hive.
func (f *infFile) hkrKeysBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var section *starlark.Dict
	var key string
	if err := starlark.UnpackArgs("hkr_keys", args, kwargs, "section", &section, "key", &key); err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0)
	seen := make(map[string]bool)
	for _, addRegSection := range infStringList(section, "AddReg") {
		rows, found, err := infSection(f.json, addRegSection)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		for _, item := range rows.Items() {
			for _, row := range infValueRows(item[1]) {
				if row.Len() < 4 || !strings.EqualFold(firstInfString(row.Index(0)), "HKR") {
					continue
				}
				flags, err := parseRegistryDWORD(firstInfString(row.Index(3)))
				if err != nil || uint32(flags)&infAddRegKeyOnly == 0 {
					continue
				}
				target := strings.TrimRight(strings.ReplaceAll(key, `\`, "/"), "/")
				if subkey := strings.Trim(strings.ReplaceAll(firstInfString(row.Index(1)), `\`, "/"), "/"); subkey != "" {
					target += "/" + subkey
				}
				normalized := strings.ToLower(target)
				if !seen[normalized] {
					seen[normalized] = true
					values = append(values, starlark.String(target))
				}
			}
		}
	}
	return starlark.NewList(values), nil
}

// hkrPatchesBuiltin resolves the relative HKR AddReg rows referenced by an INF
// section against a caller-provided registry hive and key. The target is policy
// supplied by Starlark; this method only implements the generic INF data rules.
func (f *infFile) hkrPatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var section *starlark.Dict
	var hive, key string
	if err := starlark.UnpackArgs("hkr_patches", args, kwargs, "section", &section, "hive", &hive, "key", &key); err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0)
	for _, addRegSection := range infStringList(section, "AddReg") {
		rows, found, err := infSection(f.json, addRegSection)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		for _, item := range rows.Items() {
			for _, row := range infValueRows(item[1]) {
				if row.Len() < 2 || !strings.EqualFold(firstInfString(row.Index(0)), "HKR") {
					continue
				}
				absolute := hive + `\` + strings.TrimLeft(strings.ReplaceAll(key, "/", `\`), `\`)
				if strings.EqualFold(hive, "SYSTEM") && strings.HasPrefix(strings.ToLower(key), "/controlset001") {
					absolute = `SYSTEM\CurrentControlSet` + strings.ReplaceAll(key[len("/ControlSet001"):], "/", `\`)
				}
				if subkey := firstInfString(row.Index(1)); subkey != "" {
					absolute += `\` + subkey
				}
				resolved := make([]starlark.Value, row.Len())
				resolved[0] = starlark.String("HKLM")
				resolved[1] = starlark.String(absolute)
				for index := 2; index < row.Len(); index++ {
					resolved[index] = row.Index(index)
				}
				resolvedHive, patch, include, err := registryPatchFromINFAddRegRow(starlark.NewList(resolved))
				if err != nil {
					return nil, err
				}
				if !include {
					continue
				}
				value, err := registryPatchStarlarkValue(resolvedHive, patch)
				if err != nil {
					return nil, err
				}
				values = append(values, value)
			}
		}
	}
	return starlark.NewList(values), nil
}

func (f *infFile) sectionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("section", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	section, found, err := infSection(f.json, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return starlark.None, nil
	}
	return section, nil
}

func (f *infFile) installSectionsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("install_sections", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	sections, err := infInstallSections(f, name)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(sections))
	for index, section := range sections {
		values[index] = starfile.NewRecord(starlark.StringDict{
			"name":    starlark.String(section.name),
			"section": section.section,
		})
	}
	return starlark.NewList(values), nil
}

func (f *infFile) sectionPatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("section_patches", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	section, found, err := infSection(f.json, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return starlark.NewList(nil), nil
	}
	values := make([]starlark.Value, 0, section.Len())
	for _, item := range section.Items() {
		for _, row := range infValueRows(item[1]) {
			if row.Len() < 2 {
				continue
			}
			hive, patch, include, err := registryPatchFromINFAddRegRow(row)
			if err != nil {
				return nil, fmt.Errorf("section_patches %q: %w", name, err)
			}
			if include {
				value, err := registryPatchStarlarkValue(hive, patch)
				if err != nil {
					return nil, err
				}
				values = append(values, value)
			}
		}
	}
	return starlark.NewList(values), nil
}

func infInstallSections(inf *infFile, sectionName string) ([]infInstallSection, error) {
	var sections []infInstallSection
	visited := make(map[string]bool)
	var visit func(string) error
	visit = func(name string) error {
		identity := strings.ToLower(name)
		if visited[identity] {
			return nil
		}
		visited[identity] = true
		section, found, err := infSection(inf.json, name)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("missing install section %q", name)
		}
		for _, dependency := range infStringList(section, "Needs") {
			if _, found, err := infSection(inf.json, dependency); err != nil {
				return err
			} else if found {
				if err := visit(dependency); err != nil {
					return err
				}
			}
		}
		sections = append(sections, infInstallSection{name: name, section: section})
		return nil
	}
	if err := visit(sectionName); err != nil {
		return nil, err
	}
	return sections, nil
}

func infValueRows(value starlark.Value) []*starlark.List {
	list, ok := value.(*starlark.List)
	if !ok {
		return nil
	}
	if list.Len() == 0 {
		return []*starlark.List{list}
	}
	if _, nested := list.Index(0).(*starlark.List); !nested {
		return []*starlark.List{list}
	}
	rows := make([]*starlark.List, 0, list.Len())
	for index := 0; index < list.Len(); index++ {
		if row, ok := list.Index(index).(*starlark.List); ok {
			rows = append(rows, row)
		}
	}
	return rows
}

func parseINF(data string) (*starlark.Dict, error) {
	root := starlark.NewDict(0)
	var section *starlark.Dict
	for _, raw := range infLogicalLines(data) {
		line := strings.TrimPrefix(strings.TrimSpace(raw), "\ufeff")
		line = stripINFComment(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			name := starlark.String(strings.TrimSpace(line[1:strings.Index(line, "]")]))
			existing, found, err := root.Get(name)
			if err != nil {
				return nil, err
			}
			if found {
				var ok bool
				section, ok = existing.(*starlark.Dict)
				if !ok {
					return nil, fmt.Errorf("inf: section %s is %s, want dict", name.GoString(), existing.Type())
				}
			} else {
				section = starlark.NewDict(0)
				if err := root.SetKey(name, section); err != nil {
					return nil, err
				}
			}
			continue
		}
		if section == nil {
			continue
		}
		key, row := parseINFLine(line)
		if key == "" {
			key = fmt.Sprintf("@%d", section.Len())
		}
		if err := appendINFRow(section, key, row); err != nil {
			return nil, err
		}
	}
	if err := expandINFStrings(root); err != nil {
		return nil, err
	}
	return root, nil
}

func expandINFStrings(root *starlark.Dict) error {
	stringsSection, ok, err := infSection(root, "Strings")
	if err != nil || !ok {
		return err
	}
	replacements := make(map[string]string)
	for _, item := range stringsSection.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok {
			continue
		}
		value := infStringValue(item[1])
		replacements[strings.ToUpper(key)] = value
	}
	if len(replacements) == 0 {
		return nil
	}
	for _, sectionItem := range root.Items() {
		section, ok := sectionItem[1].(*starlark.Dict)
		if !ok || section == stringsSection {
			continue
		}
		expandedSection := starlark.NewDict(section.Len())
		sectionChanged := false
		for _, item := range section.Items() {
			key, ok := starlark.AsString(item[0])
			if !ok {
				continue
			}
			expandedKey := expandINFString(key, replacements)
			expanded := expandINFValue(item[1], replacements)
			if expandedKey != key || expanded != item[1] {
				sectionChanged = true
			}
			for _, row := range infValueRows(expanded) {
				if err := appendINFRow(expandedSection, expandedKey, row); err != nil {
					return err
				}
			}
		}
		if sectionChanged {
			if err := root.SetKey(sectionItem[0], expandedSection); err != nil {
				return err
			}
		}
	}
	return nil
}

func infSection(root *starlark.Dict, name string) (*starlark.Dict, bool, error) {
	value, ok, err := root.Get(starlark.String(name))
	if err != nil || ok {
		if !ok {
			return nil, false, err
		}
		section, ok := value.(*starlark.Dict)
		return section, ok, err
	}
	for _, item := range root.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok || !strings.EqualFold(key, name) {
			continue
		}
		section, ok := item[1].(*starlark.Dict)
		return section, ok, nil
	}
	return nil, false, nil
}

func infStringValue(value starlark.Value) string {
	if s, ok := starlark.AsString(value); ok {
		return s
	}
	list, ok := value.(*starlark.List)
	if !ok || list.Len() == 0 {
		return ""
	}
	if s, ok := starlark.AsString(list.Index(0)); ok {
		return s
	}
	return ""
}

func expandINFValue(value starlark.Value, replacements map[string]string) starlark.Value {
	if s, ok := starlark.AsString(value); ok {
		return starlark.String(expandINFString(s, replacements))
	}
	list, ok := value.(*starlark.List)
	if !ok {
		return value
	}
	values := make([]starlark.Value, list.Len())
	changed := false
	for i := 0; i < list.Len(); i++ {
		values[i] = expandINFValue(list.Index(i), replacements)
		if values[i] != list.Index(i) {
			changed = true
		}
	}
	if !changed {
		return value
	}
	return starlark.NewList(values)
}

func expandINFString(value string, replacements map[string]string) string {
	const escapedPercent = "\x00INF_PERCENT\x00"
	value = strings.ReplaceAll(value, "%%", escapedPercent)
	for i := 0; i < 10; i++ {
		changed := false
		next := replaceINFStringRefs(value, replacements, &changed)
		value = next
		if !changed {
			return strings.ReplaceAll(value, escapedPercent, "%")
		}
	}
	return strings.ReplaceAll(value, escapedPercent, "%")
}

func replaceINFStringRefs(value string, replacements map[string]string, changed *bool) string {
	var out strings.Builder
	for {
		start := strings.IndexByte(value, '%')
		if start < 0 {
			out.WriteString(value)
			return out.String()
		}
		end := strings.IndexByte(value[start+1:], '%')
		if end < 0 {
			out.WriteString(value)
			return out.String()
		}
		end += start + 1
		name := value[start+1 : end]
		replacement, ok := replacements[strings.ToUpper(name)]
		if !ok {
			out.WriteString(value[:end+1])
		} else {
			out.WriteString(value[:start])
			out.WriteString(replacement)
			*changed = true
		}
		value = value[end+1:]
	}
}

func infLogicalLines(data string) []string {
	physical := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(physical))
	var current strings.Builder
	for index, raw := range physical {
		line := strings.TrimSpace(raw)
		continued := infLineContinues(line)
		if continued && current.Len() == 0 && !infContinuationLineFollows(physical[index+1:]) {
			continued = false
		}
		if continued {
			line = strings.TrimSpace(line[:len(line)-1])
		}
		if current.Len() > 0 && line != "" {
			current.WriteByte(' ')
		}
		current.WriteString(line)
		if continued {
			continue
		}
		lines = append(lines, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

func infContinuationLineFollows(lines []string) bool {
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
			return true
		}
		if strings.HasPrefix(trimmed, "[") || infAssignmentIndex(stripINFComment(trimmed)) >= 0 {
			return false
		}
		return true
	}
	return false
}

func infLineContinues(line string) bool {
	inQuote := false
	for i, r := range line {
		if r == '"' {
			inQuote = !inQuote
		}
		if r == ';' && !inQuote {
			line = strings.TrimSpace(line[:i])
			break
		}
	}
	return strings.HasSuffix(line, `\`)
}

func parseINFLine(line string) (string, starlark.Value) {
	idx := infAssignmentIndex(line)
	if idx < 0 {
		return "", starlark.NewList(infValues(line))
	}
	return strings.TrimSpace(line[:idx]), starlark.NewList(infValues(line[idx+1:]))
}

func infAssignmentIndex(line string) int {
	inQuote := false
	for i, r := range line {
		switch r {
		case '"':
			inQuote = !inQuote
		case '=':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

func infValues(value string) []starlark.Value {
	parts := splitINFCSV(value)
	values := make([]starlark.Value, len(parts))
	for i, part := range parts {
		values[i] = starlark.String(part)
	}
	return values
}

func appendINFRow(section *starlark.Dict, key string, row starlark.Value) error {
	existing, found, err := section.Get(starlark.String(key))
	if err != nil {
		return err
	}
	if !found {
		return section.SetKey(starlark.String(key), row)
	}
	rows, ok := existing.(*starlark.List)
	if !ok {
		return section.SetKey(starlark.String(key), starlark.NewList([]starlark.Value{existing, row}))
	}
	if rows.Len() == 0 {
		return section.SetKey(starlark.String(key), starlark.NewList([]starlark.Value{existing, row}))
	}
	if _, ok := rows.Index(0).(starlark.String); ok {
		if rowList, ok := row.(*starlark.List); ok && rowList.Len() == 1 {
			values := make([]starlark.Value, 0, rows.Len()+1)
			for i := 0; i < rows.Len(); i++ {
				values = append(values, rows.Index(i))
			}
			values = append(values, rowList.Index(0))
			return section.SetKey(starlark.String(key), starlark.NewList(values))
		}
		return section.SetKey(starlark.String(key), starlark.NewList([]starlark.Value{existing, row}))
	}
	values := make([]starlark.Value, 0, rows.Len()+1)
	for i := 0; i < rows.Len(); i++ {
		values = append(values, rows.Index(i))
	}
	values = append(values, row)
	return section.SetKey(starlark.String(key), starlark.NewList(values))
}

func stripINFComment(line string) string {
	inQuote := false
	for i, r := range line {
		if r == '"' {
			inQuote = !inQuote
		}
		if r == ';' && !inQuote {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func splitINFCSV(value string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(value); {
		switch value[i] {
		case '"':
			if inQuote && i+1 < len(value) && value[i+1] == '"' {
				current.WriteByte('"')
				i += 2
				continue
			}
			inQuote = !inQuote
			i++
		case ',':
			if !inQuote {
				parts = append(parts, strings.TrimSpace(current.String()))
				current.Reset()
				i++
				continue
			}
			current.WriteByte(value[i])
			i++
		default:
			current.WriteByte(value[i])
			i++
		}
	}
	parts = append(parts, strings.TrimSpace(current.String()))
	return parts
}
