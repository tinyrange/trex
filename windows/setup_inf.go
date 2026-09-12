package windows

import (
	"fmt"
	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"maps"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

type setupLine struct {
	text         string
	line, offset int
}
type setupINF struct {
	sections map[string][]setupLine
	names    []string
}

func setupInfBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("setup_inf", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	if file.Size() > 64<<20 {
		return nil, fmt.Errorf("setup_inf: input exceeds 64 MiB")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	text, err := binaryapi.DecodeText(data, "windows1252", false)
	if err != nil {
		return nil, err
	}
	result := &setupINF{sections: map[string][]setupLine{}}
	section := ""
	offset := 0
	for number, line := range strings.Split(text, "\n") {
		original := line
		quoted := false
		for i, c := range line {
			if c == '"' {
				quoted = !quoted
			}
			if c == ';' && !quoted {
				line = line[:i]
				break
			}
		}
		line = strings.TrimSpace(line)
		if end := strings.IndexByte(line, ']'); strings.HasPrefix(line, "[") && end > 0 {
			section = strings.TrimSpace(line[1:end]) + strings.TrimSpace(line[end+1:])
			if _, found := result.sections[strings.ToLower(section)]; found {
				return nil, fmt.Errorf("setup_inf: duplicate section %s", section)
			}
			result.sections[strings.ToLower(section)] = nil
			result.names = append(result.names, section)
		} else if line != "" {
			if section == "" {
				if _, err := strconv.Atoi(line); err != nil {
					return nil, fmt.Errorf("setup_inf: content before section at line %d", number+1)
				}
				section = "$preamble"
				result.names = append(result.names, section)
				result.sections[section] = nil
			}
			result.sections[strings.ToLower(section)] = append(result.sections[strings.ToLower(section)], setupLine{line, number + 1, offset})
		}
		offset += utf8.RuneCountInString(original) + 1
	}
	return result, nil
}
func (*setupINF) Type() string          { return "setup_inf" }
func (s *setupINF) String() string      { return fmt.Sprintf("<setup_inf sections=%d>", len(s.names)) }
func (*setupINF) Freeze()               {}
func (*setupINF) Truth() starlark.Bool  { return starlark.True }
func (*setupINF) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: setup_inf") }
func (*setupINF) AttrNames() []string {
	return []string{"sections", "section", "plan", "catalogue_plan"}
}
func (s *setupINF) Attr(name string) (starlark.Value, error) {
	switch name {
	case "sections":
		values := []starlark.Value{}
		for _, n := range s.names {
			values = append(values, starlark.String(n))
		}
		return starlark.NewList(values), nil
	case "section":
		return starlark.NewBuiltin("setup_inf.section", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("section", args, kwargs, "name", &name); err != nil {
				return nil, err
			}
			rows, found := s.sections[strings.ToLower(name)]
			if !found {
				return starlark.None, nil
			}
			out := []starlark.Value{}
			for _, r := range rows {
				out = append(out, acmeRecord(map[string]starlark.Value{"text": starlark.String(r.text), "line": starlark.MakeInt(r.line), "offset": starlark.MakeInt(r.offset)}))
			}
			return starlark.NewList(out), nil
		}), nil
	case "catalogue_plan":
		return starlark.NewBuiltin("setup_inf.catalogue_plan", s.cataloguePlan), nil
	case "plan":
		return starlark.NewBuiltin("setup_inf.plan", s.plan), nil
	}
	return nil, nil
}

func setupWords(value string) []string {
	result := []string{}
	var word strings.Builder
	quoted := false
	braces := 0
	for _, c := range value {
		if c == '"' {
			quoted = !quoted
			continue
		}
		if !quoted {
			if c == '{' {
				braces++
			}
			if c == '}' {
				braces--
			}
			if (c == ' ' || c == '\t') && braces == 0 {
				if word.Len() > 0 {
					result = append(result, word.String())
					word.Reset()
				}
				continue
			}
		}
		word.WriteRune(c)
	}
	if word.Len() > 0 {
		result = append(result, word.String())
	}
	return result
}
func expandSetup(value string, variables map[string]string) string {
	for pass := 0; pass < 16; pass++ {
		var out strings.Builder
		changed := false
		for len(value) > 0 {
			start := strings.Index(value, "$(")
			if start < 0 {
				out.WriteString(value)
				break
			}
			out.WriteString(value[:start])
			tail := value[start+2:]
			end := strings.IndexByte(tail, ')')
			if end < 0 {
				out.WriteString(value[start:])
				break
			}
			name := strings.TrimPrefix(tail[:end], "!")
			if replacement, found := variables[name]; found {
				out.WriteString(replacement)
				changed = true
			} else {
				out.WriteString("$(" + tail[:end] + ")")
			}
			value = tail[end+1:]
		}
		value = out.String()
		if !changed || !strings.Contains(value, "$(") {
			break
		}
	}
	return value
}
func setupCondition(line string, variables map[string]string) (bool, bool) {
	words := setupWords(line)
	if len(words) != 4 {
		return false, false
	}
	a, b := expandSetup(words[1], variables), expandSetup(words[3], variables)
	if strings.Contains(a, "$(") || strings.Contains(b, "$(") {
		return false, false
	}
	op := words[2]
	comparison := strings.Compare(a, b)
	if strings.EqualFold(words[0], "ifstr(i)") {
		comparison = strings.Compare(strings.ToLower(a), strings.ToLower(b))
	} else if strings.HasPrefix(strings.ToLower(words[0]), "ifint") {
		left, e1 := strconv.ParseInt(a, 0, 64)
		right, e2 := strconv.ParseInt(b, 0, 64)
		if e1 != nil || e2 != nil {
			return false, false
		}
		comparison = 0
		if left < right {
			comparison = -1
		} else if left > right {
			comparison = 1
		}
	}
	switch op {
	case "==", "=":
		return comparison == 0, true
	case "!=", "<>":
		return comparison != 0, true
	case ">":
		return comparison > 0, true
	case "<":
		return comparison < 0, true
	case ">=":
		return comparison >= 0, true
	case "<=":
		return comparison <= 0, true
	}
	return false, false
}

func (s *setupINF) plan(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var section string
	var media, provided *starlark.Dict
	var initialize *starlark.List
	if err := starlark.UnpackArgs("setup_inf.plan", args, kwargs, "section", &section, "media", &media, "variables?", &provided, "initialize?", &initialize); err != nil {
		return nil, err
	}
	variables := map[string]string{}
	sources := map[string]starfile.File{}
	if initialize != nil {
		for i := 0; i < initialize.Len(); i++ {
			name, ok := starlark.AsString(initialize.Index(i))
			if !ok {
				return nil, fmt.Errorf("setup_inf.plan: initialize must list sections")
			}
			rows, found := s.sections[strings.ToLower(name)]
			if !found {
				return nil, fmt.Errorf("setup_inf.plan: missing initialization section %s", name)
			}
			for _, row := range rows {
				key, value, found := strings.Cut(row.text, "=")
				if !found || strings.Contains(value, "?") {
					continue
				}
				variables[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
			}
		}
	}
	if provided != nil {
		for _, pair := range provided.Items() {
			key, ok := starlark.AsString(pair[0])
			value, valid := starlark.AsString(pair[1])
			if !ok || !valid {
				return nil, fmt.Errorf("setup_inf.plan: variables must map strings to strings")
			}
			variables[key] = value
		}
	}
	for key, value := range variables {
		variables[key] = expandSetup(value, variables)
	}
	for _, pair := range media.Items() {
		key, ok := starlark.AsString(pair[0])
		file, valid := pair[1].(starfile.File)
		if !ok || !valid {
			return nil, fmt.Errorf("setup_inf.plan: media must map relative names to files")
		}
		sources[strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(key, `\`, "/"), "/"))] = file
	}
	dependencies := []starlark.Value{}
	dependency := func(kind, expression string, declaration starlark.Value) {
		dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String(kind), "expression": starlark.String(expression), "declaration": declaration}))
	}
	steps := 0
	files, actions, gaps := []starlark.Value{}, []starlark.Value{}, []starlark.Value{}
	var walk func(string, []setupLine, map[string]string, []string, int) error
	walk = func(section string, rows []setupLine, vars map[string]string, conditions []string, depth int) error {
		if depth > 64 {
			return fmt.Errorf("setup_inf.plan: nesting exceeds bound")
		}
		for i := 0; i < len(rows); i++ {
			steps++
			if steps > 1000000 {
				return fmt.Errorf("setup_inf.plan: action expansion exceeds bound")
			}
			row := rows[i]
			words := setupWords(row.text)
			if len(words) == 0 {
				continue
			}
			command := strings.ToLower(words[0])
			if strings.HasPrefix(command, "ifstr") || strings.HasPrefix(command, "ifint") {
				end, alternate, nesting := -1, -1, 0
				for j := i + 1; j < len(rows); j++ {
					w := setupWords(rows[j].text)
					if len(w) == 0 {
						continue
					}
					c := strings.ToLower(w[0])
					if strings.HasPrefix(c, "ifstr") || strings.HasPrefix(c, "ifint") {
						nesting++
					} else if c == "endif" {
						if nesting == 0 {
							end = j
							break
						}
						nesting--
					} else if c == "else" && nesting == 0 {
						alternate = j
					}
				}
				if end < 0 {
					return fmt.Errorf("setup_inf.plan: unmatched condition at line %d", row.line)
				}
				split := end
				if alternate >= 0 {
					split = alternate
				}
				truth, known := setupCondition(row.text, vars)
				if known {
					if truth {
						if err := walk(section, rows[i+1:split], vars, conditions, depth+1); err != nil {
							return err
						}
					} else if alternate >= 0 {
						if err := walk(section, rows[alternate+1:end], vars, conditions, depth+1); err != nil {
							return err
						}
					}
				} else {
					condition := expandSetup(row.text, vars)
					yes, no := maps.Clone(vars), maps.Clone(vars)
					if err := walk(section, rows[i+1:split], yes, append(append([]string(nil), conditions...), condition), depth+1); err != nil {
						return err
					}
					if alternate >= 0 {
						if err := walk(section, rows[alternate+1:end], no, append(append([]string(nil), conditions...), "NOT "+condition), depth+1); err != nil {
							return err
						}
					}
					for key, value := range yes {
						if no[key] == value {
							vars[key] = value
						} else {
							delete(vars, key)
						}
					}
					for key := range no {
						if _, found := yes[key]; !found {
							delete(vars, key)
						}
					}
				}
				i = end
				continue
			}
			if command == "forlistdo" {
				end, nesting := -1, 0
				for j := i + 1; j < len(rows); j++ {
					w := setupWords(rows[j].text)
					if len(w) == 0 {
						continue
					}
					c := strings.ToLower(w[0])
					if c == "forlistdo" {
						nesting++
					} else if c == "endforlistdo" {
						if nesting == 0 {
							end = j
							break
						}
						nesting--
					}
				}
				if end < 0 {
					return fmt.Errorf("setup_inf.plan: unmatched loop at line %d", row.line)
				}
				list := strings.TrimSpace(expandSetup(strings.TrimSpace(row.text[len(words[0]):]), vars))
				if !strings.HasPrefix(list, "{") || !strings.HasSuffix(list, "}") || strings.Contains(list, "$(") {
					dependency("loop", list, acmeRecord(map[string]starlark.Value{"section": starlark.String(section), "line": starlark.MakeInt(row.line), "end_line": starlark.MakeInt(rows[end].line)}))
				} else {
					entries, err := acmeArguments(list[1 : len(list)-1])
					if err != nil {
						return err
					}
					if len(entries) > 4096 {
						return fmt.Errorf("setup_inf.plan: loop exceeds bound")
					}
					for _, entry := range entries {
						child := maps.Clone(vars)
						child["$"] = entry
						if err := walk(section, rows[i+1:end], child, conditions, depth+1); err != nil {
							return err
						}
					}
				}
				i = end
				continue
			}
			conditionValues := []starlark.Value{}
			for _, condition := range conditions {
				conditionValues = append(conditionValues, starlark.String(condition))
			}
			provenance := acmeRecord(map[string]starlark.Value{"section": starlark.String(section), "line": starlark.MakeInt(row.line), "offset": starlark.MakeInt(row.offset)})
			actions = append(actions, acmeRecord(map[string]starlark.Value{"command": starlark.String(words[0]), "text": starlark.String(expandSetup(row.text, vars)), "conditions": starlark.NewList(conditionValues), "provenance": provenance}))
			switch command {
			case "libraryprocedure", "query", "readregistry", "getenv", "goto":
				dependency("runtime_command", expandSetup(row.text, vars), provenance)
			case "exit":
				return nil
			case "set":
				key, value, found := strings.Cut(strings.TrimSpace(row.text[len(words[0]):]), "=")
				if found {
					vars[strings.TrimSpace(key)] = expandSetup(strings.Trim(strings.TrimSpace(value), `"`), vars)
				}
			case "dosection", "do":
				if len(words) == 2 {
					child := expandSetup(words[1], vars)
					if lines, found := s.sections[strings.ToLower(child)]; found {
						if err := walk(child, lines, vars, conditions, depth+1); err != nil {
							return err
						}
					} else {
						gaps = append(gaps, starlark.String("missing invoked section "+child))
					}
				}
			case "addsectionfilestocopylist":
				if len(words) != 4 {
					return fmt.Errorf("setup_inf.plan: invalid copy directive at line %d", row.line)
				}
				name, sourceDir, dest := expandSetup(words[1], vars), expandSetup(words[2], vars), expandSetup(words[3], vars)
				table, found := s.sections[strings.ToLower(name)]
				if !found {
					gaps = append(gaps, starlark.String("missing file section "+name))
					continue
				}
				for _, fileRow := range table {
					fields, err := acmeArguments(fileRow.text)
					if err != nil || len(fields) < 2 {
						return fmt.Errorf("setup_inf.plan: invalid file catalogue at line %d", fileRow.line)
					}
					filename := fields[1]
					sourceName := strings.TrimPrefix(strings.ReplaceAll(strings.TrimRight(sourceDir, `\/`)+"/"+filename, `\`, "/"), "/")
					source := sources[strings.ToLower(sourceName)]
					if source == nil {
						source = sources[strings.ToLower(sourceName+".")]
					}
					if source == nil && len(sourceName) > 0 {
						source = sources[strings.ToLower(setupCompressedName(sourceName))]
					}
					if source != nil {
						var err error
						source, err = decodeSetupFile(thread, source)
						if err != nil {
							return fmt.Errorf("setup_inf.plan: %s: %w", sourceName, err)
						}
					}
					var value starlark.Value = starlark.None
					if source != nil {
						value = source
					} else {
						gaps = append(gaps, starlark.String("missing media file "+sourceName))
					}
					destination := strings.TrimRight(dest, `\/`) + `\` + path.Base(strings.ReplaceAll(filename, `\`, "/"))
					resolved := source != nil && !strings.Contains(destination, "$(") && len(destination) > 2 && destination[1] == ':'
					if strings.Contains(destination, "$(") {
						dependency("destination", destination, provenance)
					}
					files = append(files, acmeRecord(map[string]starlark.Value{"source": starlark.String(sourceName), "file": value, "destination": starlark.String(destination), "resolved": starlark.Bool(resolved), "conditions": starlark.NewList(conditionValues), "provenance": provenance, "catalogue_line": starlark.MakeInt(fileRow.line), "catalogue": starlark.String(fileRow.text)}))
				}
			}
		}
		return nil
	}
	rows, found := s.sections[strings.ToLower(section)]
	if !found {
		return nil, fmt.Errorf("setup_inf.plan: missing section %s", section)
	}
	if err := walk(section, rows, variables, nil, 0); err != nil {
		return nil, err
	}
	return acmeRecord(map[string]starlark.Value{"format": starlark.String("microsoft_setup_inf"), "files": starlark.NewList(files), "actions": starlark.NewList(actions), "unresolved": starlark.NewList(gaps), "media": media, "runtime_dependencies": starlark.NewList(dependencies), "script": s}), nil
}
