package wise

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	windowspe "github.com/tinyrange/trex/windows/pe"
	"go.starlark.net/starlark"
)

// Plan translates decoded WiseScript records into portable image
// modifications. Runtime helpers in the temporary directory are retained in
// the archive for inspection but are intentionally absent from the final plan.
func (a *Archive) Plan(locations, supplied map[string]string) (*starlark.Dict, error) {
	evaluation := evaluateWiseScript(a.script, wiseVariables(locations, supplied))
	variables := evaluation.variables
	if target := caseFoldValue(locations, "<targetdir>"); target != "" {
		variables["MAINDIR"] = target
	}
	target := variables["MAINDIR"]
	if target == "" || !isAbsoluteWindowsPath(target) {
		return nil, fmt.Errorf("wise: script does not resolve an absolute installation directory")
	}

	type plannedFile struct {
		source      string
		destination string
		file        starfile.File
	}
	byDestination := make(map[string]plannedFile)
	unresolved := make(map[string]bool)
	for actionIndex, action := range a.script.actions {
		if action.file == nil {
			continue
		}
		entry := action.file
		if wiseTemporaryDestination(entry.destination) {
			continue
		}
		if evaluation.uncertain[actionIndex] {
			evaluation.unresolvedAction(action)
			continue
		}
		if !evaluation.active[actionIndex] {
			continue
		}
		destination, resolved := expandWiseVariables(entry.destination, variables)
		if !resolved || !isAbsoluteWindowsPath(destination) {
			unresolved[entry.destination] = true
			continue
		}
		file, err := a.Lookup(entry.member)
		if err != nil {
			return nil, err
		}
		byDestination[strings.ToLower(destination)] = plannedFile{source: entry.member, destination: destination, file: file}
	}
	keys := make([]string, 0, len(byDestination))
	for key := range byDestination {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	files := make([]starlark.Value, 0, len(keys))
	artifacts := make([]starlark.Value, 0)
	for _, key := range keys {
		entry := byDestination[key]
		files = append(files, stringDict(map[string]starlark.Value{
			"source": starlark.String(entry.source), "destination": starlark.String(entry.destination),
			"component": starlark.String(""), "resolved": starlark.True, "container": starlark.False,
		}))
		kind := ""
		lower := strings.ToLower(entry.destination)
		if strings.HasSuffix(lower, ".sys") || strings.HasSuffix(lower, ".vxd") {
			kind = "driver"
		}
		exports := make([]starlark.Value, 0)
		if entry.file.Size() > 0 && entry.file.Size() <= 64<<20 && (strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".ocx") || strings.HasSuffix(lower, ".exe")) {
			data, readErr := starfile.ReadAll(entry.file)
			if readErr == nil && len(data) >= 2 && string(data[:2]) == "MZ" {
				if parsed, exportErr := windowspe.Exports(data); exportErr == nil {
					for _, export := range parsed {
						if export.Name != "" {
							exports = append(exports, starlark.String(export.Name))
							if strings.EqualFold(export.Name, "DllRegisterServer") {
								kind = "self_registration"
							}
						}
					}
				}
			}
		}
		if kind != "" {
			artifacts = append(artifacts, stringDict(map[string]starlark.Value{
				"package_root": starlark.String("/"), "source": starlark.String(entry.source),
				"name":  starlark.String(path.Base(strings.ReplaceAll(entry.destination, `\`, "/"))),
				"group": starlark.String(""), "kind": starlark.String(kind), "exports": starlark.NewList(exports),
				"executable_registration": starlark.Bool(kind == "self_registration"),
			}))
		}
	}

	registryWrites := make([]starlark.Value, 0)
	for actionIndex, action := range a.script.actions {
		if action.opcode != 0x0a || len(action.fixed) < 2 || len(action.strings) < 3 {
			continue
		}
		if evaluation.uncertain[actionIndex] {
			evaluation.unresolvedAction(action)
			continue
		}
		if !evaluation.active[actionIndex] {
			continue
		}
		root := map[byte]string{0: "HKEY_CLASSES_ROOT", 1: "HKEY_CURRENT_USER", 2: "HKEY_LOCAL_MACHINE", 3: "HKEY_USERS"}[action.fixed[0]&0x1f]
		if root == "" {
			continue
		}
		values := action.strings
		if len(values) == 4 {
			values = values[1:]
		}
		key, keyResolved := expandWiseVariables(values[0], variables)
		value, valueResolved := expandWiseVariables(values[1], variables)
		name, nameResolved := expandWiseVariables(values[2], variables)
		if !keyResolved || !nameResolved || key == "" {
			continue
		}
		deleting := action.fixed[0]&0xc0 != 0
		if !deleting && !valueResolved {
			continue
		}
		operation := "set_value"
		if deleting {
			operation = "delete_value"
		}
		fields := map[string]starlark.Value{
			"operation": starlark.String(operation), "root": starlark.String(root), "key": starlark.String(key),
			"name": starlark.String(name), "resolved": starlark.True,
		}
		if !deleting {
			if action.fixed[1] == 3 {
				number, numberErr := strconv.ParseUint(value, 10, 32)
				if numberErr != nil {
					continue
				}
				fields["type"] = starlark.String("REG_DWORD")
				fields["data"] = starlark.MakeUint64(number)
			} else {
				fields["type"] = starlark.String("REG_SZ")
				fields["data"] = starlark.String(value)
			}
		}
		registryWrites = append(registryWrites, stringDict(fields))
	}

	shortcuts := make([]starlark.Value, 0)
	for actionIndex, action := range a.script.actions {
		if action.opcode != 0x09 || len(action.strings) < 5 || !strings.EqualFold(action.strings[1], "ShellLink") {
			continue
		}
		if evaluation.uncertain[actionIndex] {
			evaluation.unresolvedAction(action)
			continue
		}
		if !evaluation.active[actionIndex] {
			continue
		}
		parts := strings.Split(action.strings[4], "\x7f")
		if len(parts) < 6 {
			continue
		}
		targetPath, targetOK := expandWiseVariables(parts[1], variables)
		linkPath, linkOK := expandWiseVariables(parts[2], variables)
		arguments, argumentsOK := expandWiseVariables(parts[3], variables)
		working, workingOK := expandWiseVariables(parts[4], variables)
		if !targetOK || !linkOK || !argumentsOK || !workingOK || !isAbsoluteWindowsPath(targetPath) || !isAbsoluteWindowsPath(linkPath) {
			continue
		}
		linkBase := path.Base(strings.ReplaceAll(linkPath, `\`, "/"))
		display := strings.TrimSuffix(linkBase, path.Ext(linkBase))
		folder := strings.TrimSuffix(linkPath, linkBase)
		folder = strings.TrimRight(folder, `\/`)
		icon := targetPath
		if len(parts) > 7 && parts[7] != "" {
			if expanded, ok := expandWiseVariables(parts[7], variables); ok {
				icon = expanded
			}
		}
		iconIndex, _ := strconv.Atoi(parts[5])
		shortcuts = append(shortcuts, stringDict(map[string]starlark.Value{
			"name": starlark.String(display), "display": starlark.String(display), "target": starlark.String(targetPath),
			"arguments": starlark.String(arguments), "working_directory": starlark.String(working),
			"icon": starlark.String(icon), "icon_index": starlark.MakeInt(iconIndex), "destination_folder": starlark.String(folder),
			"resolved": starlark.True, "type": starlark.MakeInt(0),
		}))
	}

	unresolvedValues := make([]starlark.Value, 0, len(unresolved))
	for value := range unresolved {
		unresolvedValues = append(unresolvedValues, starlark.String("file destination: "+value))
	}
	for _, value := range evaluation.unresolved {
		unresolvedValues = append(unresolvedValues, starlark.String(value))
	}
	sort.Slice(unresolvedValues, func(i, j int) bool {
		return string(unresolvedValues[i].(starlark.String)) < string(unresolvedValues[j].(starlark.String))
	})
	defaults := starlark.NewList([]starlark.Value{stringDict(map[string]starlark.Value{
		"variable": starlark.String("TARGETDIR"), "value": starlark.String(target),
		"conditional": starlark.False, "source": starlark.String("WiseScript MAINDIR default"),
	})})
	return stringDict(map[string]starlark.Value{
		"format": starlark.String("wise"), "files": starlark.NewList(files), "registry": starlark.NewList(nil),
		"registry_writes": starlark.NewList(nil), "definitive_registry_writes": starlark.NewList(registryWrites),
		"shortcuts": starlark.NewList(shortcuts), "shortcut_calls": starlark.NewList(nil), "script": a.script.file,
		"script_evaluation": starlark.None, "custom_actions": starlark.NewList(nil), "artifacts": starlark.NewList(artifacts),
		"target_defaults": defaults, "profiles": starlark.NewDict(0), "unresolved": starlark.NewList(unresolvedValues),
	}), nil
}

func wiseVariables(locations, supplied map[string]string) map[string]string {
	variables := make(map[string]string)
	for name, value := range supplied {
		variables[strings.ToUpper(name)] = value
	}
	programFiles := caseFoldValue(locations, "<programfiles>")
	system := caseFoldValue(locations, "<winsysdir>")
	windows := strings.TrimSuffix(strings.TrimSuffix(system, `\SYSTEM`), `\system`)
	if windows == system || windows == "" {
		windows = `C:\WINDOWS`
	}
	seed := map[string]string{
		"WIN": windows, "SYS": system, "SYS32": system, "PROGRAM_FILES": programFiles,
		"TEMP": windows + `\TEMP`, "STARTUPDIR": caseFoldValue(locations, "<startup_folder>"),
		"DESKTOPDIR": caseFoldValue(locations, "<desktop_folder>"), "STARTMENUDIR": caseFoldValue(locations, "<start_menu_folder>"),
		"GROUPDIR": caseFoldValue(locations, "<shell_object_folder>"),
	}
	for name, value := range seed {
		if value != "" {
			variables[name] = value
		}
	}
	if target := caseFoldValue(locations, "<targetdir>"); target != "" {
		variables["MAINDIR"] = target
	}
	return variables
}

func wiseProtectedVariable(name string) bool {
	return name == "WIN" || name == "SYS" || name == "SYS32" || name == "PROGRAM_FILES"
}

func validWiseVariableValue(value string) bool {
	if strings.Contains(value, ":\\") && !isAbsoluteWindowsPath(value) {
		return false
	}
	return !strings.Contains(value, `\C:\`) && !strings.Contains(value, `\c:\`)
}

func isAbsoluteWindowsPath(value string) bool {
	return len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') && !strings.Contains(value[2:], ":")
}

func wiseTemporaryDestination(value string) bool {
	folded := strings.ToUpper(strings.ReplaceAll(value, "/", `\`))
	return strings.HasPrefix(folded, `%TEMP%\`) || folded == "%TEMP%"
}

func caseFoldValue(values map[string]string, name string) string {
	for key, value := range values {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func stringDict(fields map[string]starlark.Value) *starlark.Dict {
	value := starlark.NewDict(len(fields))
	for name, field := range fields {
		_ = value.SetKey(starlark.String(name), field)
	}
	return value
}
