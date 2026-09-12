package windows

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func expandBatch(value string, variables map[string]string) string {
	var out strings.Builder
	for len(value) > 0 {
		start := strings.IndexByte(value, '%')
		if start < 0 {
			out.WriteString(value)
			break
		}
		out.WriteString(value[:start])
		value = value[start:]
		end := 0
		if len(value) > 1 && value[1] >= '0' && value[1] <= '9' {
			end = 2
		} else if i := strings.IndexByte(value[1:], '%'); i >= 0 {
			end = i + 2
		}
		if end == 0 {
			out.WriteString(value)
			break
		}
		key := strings.ToLower(strings.Trim(value[:end], "%"))
		if replacement, found := variables[key]; found {
			out.WriteString(replacement)
		} else {
			out.WriteString(value[:end])
		}
		value = value[end:]
	}
	return out.String()
}

// batchPlanBuiltin is static command inspection. It retains labels, branches,
// media changes and external commands instead of running or flattening them.
func batchPlanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var script starfile.File
	var media, provided *starlark.Dict
	if err := starlark.UnpackArgs("batch_plan", args, kwargs, "script", &script, "media", &media, "variables?", &provided); err != nil {
		return nil, err
	}
	if script.Size() > 8<<20 {
		return nil, fmt.Errorf("batch_plan: script exceeds 8 MiB")
	}
	data, err := starfile.ReadAll(script)
	if err != nil {
		return nil, err
	}
	body, err := binaryapi.DecodeText(data, "windows1252", false)
	if err != nil {
		return nil, err
	}
	variables := map[string]string{}
	if provided != nil {
		for _, pair := range provided.Items() {
			key, ok := starlark.AsString(pair[0])
			value, valid := starlark.AsString(pair[1])
			if !ok || !valid {
				return nil, fmt.Errorf("batch_plan: variables must map strings to strings")
			}
			variables[strings.ToLower(key)] = value
		}
	}
	sources := map[string]starfile.File{}
	names := []string{}
	for _, pair := range media.Items() {
		name, ok := starlark.AsString(pair[0])
		f, valid := pair[1].(starfile.File)
		if !ok || !valid {
			return nil, fmt.Errorf("batch_plan: media must map relative names to files")
		}
		name = strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/"))
		if sources[name] != nil {
			return nil, fmt.Errorf("batch_plan: ambiguous media name %s", name)
		}
		sources[name] = f
		names = append(names, name)
	}
	sort.Strings(names)
	files, actions, dependencies, gaps := []starlark.Value{}, []starlark.Value{}, []starlark.Value{}, []starlark.Value{}
	offset := 0
	directory := ""
	work := 0
	for index, line := range strings.Split(body, "\n") {
		original := line
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "@"))
		provenance := acmeRecord(map[string]starlark.Value{"line": starlark.MakeInt(index + 1), "offset": starlark.MakeInt(offset)})
		offset += utf8.RuneCountInString(original) + 1
		if line == "" {
			continue
		}
		expanded := expandBatch(line, variables)
		words := setupWords(expanded)
		if len(words) == 0 {
			continue
		}
		command := strings.ToLower(words[0])
		action := acmeRecord(map[string]starlark.Value{"command": starlark.String(command), "text": starlark.String(line), "expanded": starlark.String(expanded), "provenance": provenance})
		actions = append(actions, action)
		if command == "rem" || command == "echo" || strings.HasPrefix(command, ":") {
			continue
		}
		dependencies = append(dependencies, acmeRecord(map[string]starlark.Value{"kind": starlark.String("batch_command"), "expression": starlark.String(expanded), "declaration": action}))
		if (command == "cd" || command == "chdir") && len(words) == 2 {
			value := strings.ReplaceAll(words[1], `\`, "/")
			if len(value) > 1 && value[1] == ':' {
				value = value[2:]
			}
			if strings.HasPrefix(value, "/") {
				directory = strings.TrimLeft(value, "/")
			} else {
				directory = path.Join(directory, value)
			}
		}
		if command != "copy" || len(words) != 3 {
			continue
		}
		sourceName := strings.ReplaceAll(words[1], `\`, "/")
		if len(sourceName) > 1 && sourceName[1] == ':' {
			sourceName = sourceName[2:]
		} else if !strings.HasPrefix(sourceName, "/") {
			sourceName = path.Join(directory, sourceName)
		}
		sourceName = strings.ToLower(strings.TrimLeft(sourceName, "/"))
		matched := false
		for _, name := range names {
			work++
			if work > 10000000 {
				return nil, fmt.Errorf("batch_plan: source matching exceeds bound")
			}
			relative := name
			if first, rest, found := strings.Cut(name, "/"); found && strings.Trim(first, "0123456789") == "" {
				relative = rest
			}
			ok, _ := path.Match(sourceName, relative)
			if !ok {
				continue
			}
			matched = true
			files = append(files, acmeRecord(map[string]starlark.Value{"source": starlark.String(name), "file": sources[name], "destination_expression": starlark.String(words[2]), "source_name": starlark.String(path.Base(relative)), "resolved": starlark.False, "provenance": provenance, "condition": starlark.String("batch control flow and media selection")}))
		}
		if !matched && !strings.Contains(sourceName, "%") {
			gaps = append(gaps, starlark.String("missing copy source "+words[1]))
		}
	}
	return acmeRecord(map[string]starlark.Value{"format": starlark.String("dos_batch"), "script": script, "files": starlark.NewList(files), "actions": starlark.NewList(actions), "runtime_dependencies": starlark.NewList(dependencies), "unresolved": starlark.NewList(gaps), "media": media}), nil
}
