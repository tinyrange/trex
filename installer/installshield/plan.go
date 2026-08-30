package installshield

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/tinyrange/trex/installer/installshield/installscript"
	starfile "github.com/tinyrange/trex/storage/star"
	windowspe "github.com/tinyrange/trex/windows/pe"
	"go.starlark.net/starlark"
)

// planBuiltin returns declarative package destinations and conservative script
// effects. Component locations come from the caller instead of the host OS, so
// the result is equally usable by a browser backend or an in-memory guest.
func (i *Installer) planBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	locationsValue := starlark.Value(starlark.None)
	variablesValue := starlark.Value(starlark.None)
	componentsValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("installer.plan", args, kwargs, "locations?", &locationsValue, "variables?", &variablesValue, "components?", &componentsValue); err != nil {
		return nil, err
	}
	variables, err := installPlanStringMap("variables", variablesValue)
	if err != nil {
		return nil, err
	}
	components, err := installPlanStringSet("components", componentsValue)
	if err != nil {
		return nil, err
	}
	locations := make(map[string]string)
	if locationsValue != starlark.None {
		dict, ok := locationsValue.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("installer.plan: locations is %s, want dict", locationsValue.Type())
		}
		for _, item := range dict.Items() {
			component, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("installer.plan: location key is %s, want string", item[0].Type())
			}
			destination, ok := starlark.AsString(item[1])
			if !ok {
				return nil, fmt.Errorf("installer.plan: location for %q is %s, want string", component, item[1].Type())
			}
			locations[strings.ToLower(component)] = destination
		}
	}

	files := make([]starlark.Value, 0)
	unresolvedComponents := make(map[string]bool)
	for _, pkg := range i.installShieldPackages() {
		packageArchive := pkg.payload
		groupTargets := make(map[string]string, len(packageArchive.groups))
		for _, group := range packageArchive.groups {
			groupTargets[strings.ToLower(group.name)] = group.target
		}
		for _, file := range packageArchive.files {
			if !validInstallPlanFilename(file.name) {
				continue
			}
			if components != nil && !installPlanComponentsSelected(file.components, components) {
				continue
			}
			resolved := false
			for _, component := range file.components {
				base, found := locations[strings.ToLower(component)]
				if !found {
					continue
				}
				resolved = true
				files = append(files, installPlanFileValue(pkg.root, file, component, joinInstallWindowsPath(base, file.directory, file.name), true))
			}
			if !resolved {
				if target := groupTargets[strings.ToLower(file.group)]; target != "" {
					if base, found := expandInstallPlanValue(target, locations, variables); found {
						component := ""
						if len(file.components) > 0 {
							component = file.components[0]
						}
						files = append(files, installPlanFileValue(pkg.root, file, component, joinInstallWindowsPath(base, file.directory, file.name), true))
						resolved = true
					}
				}
			}
			if !resolved {
				for _, component := range file.components {
					unresolvedComponents[component] = true
				}
				files = append(files, installPlanFileValue(pkg.root, file, "", "", false))
			}
		}
	}

	registry := starlark.Value(starlark.NewList(nil))
	registryWrites := starlark.Value(starlark.NewList(nil))
	definitiveRegistryWrites := starlark.Value(starlark.NewList(nil))
	shortcutCalls := starlark.Value(starlark.NewList(nil))
	scriptEvaluation := starlark.Value(starlark.None)
	customActions := starlark.Value(starlark.NewList(nil))
	defaults := starlark.NewList(nil)
	scriptValue := starlark.Value(starlark.None)
	profiles, err := i.installPlanProfiles()
	if err != nil {
		return nil, err
	}
	script, err := i.installScript()
	if err != nil {
		return nil, err
	}
	if script != nil {
		scriptValue = script
		seedAddresses := map[int]string{8: "<TARGETDIR>", 9: "<SUPPORTDIR>", 30: "<PROGRAMFILES>"}
		for name, address := range script.PredefinedVariables() {
			if token, found := map[string]string{"TARGETDIR": "<TARGETDIR>", "SUPPORTDIR": "<SUPPORTDIR>", "PROGRAMFILES": "<PROGRAMFILES>"}[name]; found {
				seedAddresses[address] = token
			}
		}
		// InstallShield 5's AppData folder resolver stores its result in this
		// standard shared string slot before composing per-user paths.
		if script.Format() == "legacy-ins" {
			seedAddresses[34] = "<APPDATA>"
		}
		seedStrings := starlark.NewDict(len(seedAddresses))
		for address, token := range seedAddresses {
			value := token
			if resolved, found := locations[strings.ToLower(token)]; found {
				value = resolved
			}
			_ = seedStrings.SetKey(starlark.MakeInt(address), starlark.String(value))
		}
		evalKeywords := []starlark.Tuple{{starlark.String("strings"), seedStrings}}
		if profiles.Len() > 0 {
			evalKeywords = append(evalKeywords, starlark.Tuple{starlark.String("profiles"), profiles})
		}
		evaluated, evalErr := script.Evaluate(evalKeywords)
		if evalErr != nil {
			return nil, evalErr
		}
		scriptEvaluation = evaluated
		if value, found, getErr := evaluated.(*starlark.Dict).Get(starlark.String("registry")); getErr != nil {
			return nil, getErr
		} else if found {
			registry = value
		}
		if value, found, getErr := evaluated.(*starlark.Dict).Get(starlark.String("registry_writes")); getErr != nil {
			return nil, getErr
		} else if found {
			registryWrites = value
		}
		if value, found, getErr := evaluated.(*starlark.Dict).Get(starlark.String("definitive_registry_writes")); getErr != nil {
			return nil, getErr
		} else if found {
			definitiveRegistryWrites = value
		}
		if value, found, getErr := evaluated.(*starlark.Dict).Get(starlark.String("calls")); getErr != nil {
			return nil, getErr
		} else if found {
			customActions = installPlanCustomActions(value)
		}
		defaults = installPlanTargetDefaults(evaluated, script)
		effects := script.Effects()
		if value, found, getErr := effects.Get(starlark.String("shortcuts")); getErr != nil {
			return nil, getErr
		} else if found {
			shortcutCalls = value
		}
	}
	artifacts, err := i.installPlanArtifacts(components)
	if err != nil {
		return nil, err
	}
	shortcuts := make([]starlark.Value, 0)
	for _, pkg := range i.installShieldPackages() {
		packageArchive := pkg.payload
		for _, shortcut := range packageArchive.shortcuts {
			if components != nil && shortcut.component != "" && !components[strings.ToLower(shortcut.component)] {
				continue
			}
			shortcuts = append(shortcuts, installPlanShortcutValue(pkg.root, shortcut, locations, variables))
		}
	}

	unresolved := make([]starlark.Value, 0, len(unresolvedComponents)+1)
	componentNames := make([]string, 0, len(unresolvedComponents))
	for component := range unresolvedComponents {
		componentNames = append(componentNames, component)
	}
	sort.Strings(componentNames)
	for _, component := range componentNames {
		unresolved = append(unresolved, starlark.String("component location: "+component))
	}
	if len(shortcuts) == 0 {
		if shortcutList, ok := shortcutCalls.(*starlark.List); ok && shortcutList.Len() > 0 {
			unresolved = append(unresolved, starlark.String("shortcut records unavailable; creation calls found in InstallScript"))
		}
	} else {
		for _, value := range shortcuts {
			entry := value.(*starlark.Dict)
			resolved, found, _ := entry.Get(starlark.String("resolved"))
			if found && resolved == starlark.False {
				unresolved = append(unresolved, starlark.String("shortcut locations or variables"))
				break
			}
		}
	}
	return starlarkStringDict(map[string]starlark.Value{
		"format": starlark.String(i.format), "files": starlark.NewList(files),
		"registry": registry, "registry_writes": registryWrites, "definitive_registry_writes": definitiveRegistryWrites,
		"shortcuts": starlark.NewList(shortcuts), "shortcut_calls": shortcutCalls, "script": scriptValue,
		"script_evaluation": scriptEvaluation, "custom_actions": customActions, "artifacts": artifacts, "target_defaults": defaults,
		"profiles":   profiles,
		"unresolved": starlark.NewList(unresolved),
	}), nil
}

func (i *Installer) installPlanProfiles() (*starlark.Dict, error) {
	profiles := starlark.NewDict(0)
	for _, member := range i.container.Files() {
		if !strings.HasSuffix(strings.ToLower(member.Name), ".ini") {
			continue
		}
		value, err := i.container.Lookup(member.Name)
		if err != nil {
			return nil, err
		}
		file := starfile.File(value)
		if file.Size() < 0 || file.Size() > 1<<20 {
			continue
		}
		data, err := starfile.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("installer.plan: read profile %q: %w", member.Name, err)
		}
		sections := parseInstallPlanINI(data)
		sectionDict := starlark.NewDict(len(sections))
		for section, entries := range sections {
			entryDict := starlark.NewDict(len(entries))
			for key, entry := range entries {
				_ = entryDict.SetKey(starlark.String(key), starlark.String(entry))
			}
			_ = sectionDict.SetKey(starlark.String(section), entryDict)
		}
		_ = profiles.SetKey(starlark.String(path.Base(strings.ReplaceAll(member.Name, `\`, "/"))), sectionDict)
	}
	return profiles, nil
}

func parseInstallPlanINI(data []byte) map[string]map[string]string {
	sections := make(map[string]map[string]string)
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, found := sections[section]; !found {
				sections[section] = make(map[string]string)
			}
			continue
		}
		if equals := strings.IndexByte(line, '='); equals >= 0 {
			if _, found := sections[section]; !found {
				sections[section] = make(map[string]string)
			}
			sections[section][strings.TrimSpace(line[:equals])] = strings.TrimSpace(line[equals+1:])
		}
	}
	return sections
}

func installPlanTargetDefaults(evaluated starlark.Value, script *installscript.Script) *starlark.List {
	dict, ok := evaluated.(*starlark.Dict)
	if !ok {
		return script.TargetDefaults()
	}
	value, found, _ := dict.Get(starlark.String("final_globals"))
	list, ok := value.(*starlark.List)
	if !found || !ok {
		return script.TargetDefaults()
	}
	static := script.TargetDefaults()
	type targetDefault struct {
		value       string
		conditional bool
	}
	values := make(map[string]targetDefault)
	for index := 0; index < list.Len(); index++ {
		entry, ok := list.Index(index).(*starlark.Dict)
		if !ok {
			continue
		}
		kindValue, _, _ := entry.Get(starlark.String("kind"))
		addressValue, _, _ := entry.Get(starlark.String("address"))
		resolvedValue, _, _ := entry.Get(starlark.String("value"))
		kind, kindErr := starlark.AsInt32(kindValue)
		address, addressErr := starlark.AsInt32(addressValue)
		resolved, resolvedOK := starlark.AsString(resolvedValue)
		if kindErr != nil || addressErr != nil || !resolvedOK || kind != 4 || address != 14 || resolved == "" || strings.EqualFold(resolved, "<TARGETDIR>") {
			continue
		}
		// A system-directory accessor may preserve only the relative suffix in
		// stripped bytecode. Reattach a uniquely matching statically proved base.
		matches := make([]string, 0)
		for staticIndex := 0; staticIndex < static.Len(); staticIndex++ {
			candidateValue, _, _ := static.Index(staticIndex).(*starlark.Dict).Get(starlark.String("value"))
			candidate, _ := starlark.AsString(candidateValue)
			if strings.HasSuffix(strings.ToLower(candidate), `\`+strings.ToLower(resolved)) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 1 {
			resolved = matches[0]
		}
		conditionalValue, _, _ := entry.Get(starlark.String("conditional"))
		conditional, _ := conditionalValue.(starlark.Bool)
		key := strings.ToLower(resolved)
		if previous, found := values[key]; !found || (previous.conditional && !bool(conditional)) {
			values[key] = targetDefault{value: resolved, conditional: bool(conditional)}
		}
	}
	if len(values) == 0 {
		return static
	}
	names := make([]string, 0, len(values))
	for value := range values {
		names = append(names, value)
	}
	sort.Strings(names)
	output := make([]starlark.Value, 0, len(names))
	for _, key := range names {
		candidate := values[key]
		output = append(output, starlarkStringDict(map[string]starlark.Value{
			"variable": starlark.String("TARGETDIR"), "value": starlark.String(candidate.value),
			"conditional": starlark.Bool(candidate.conditional), "source": starlark.String("evaluated InstallScript final global"),
		}))
	}
	return starlark.NewList(output)
}

func installPlanCustomActions(value starlark.Value) *starlark.List {
	list, ok := value.(*starlark.List)
	if !ok {
		return starlark.NewList(nil)
	}
	standard := map[string]bool{"isrt": true, "kernel": true, "kernel32": true, "user": true, "user32": true, "gdi": true, "gdi32": true, "advapi32": true, "shell32": true, "ole32": true, "oleaut32": true, "sfc": true, "ismif32": true}
	output := make([]starlark.Value, 0)
	for index := 0; index < list.Len(); index++ {
		entry, ok := list.Index(index).(*starlark.Dict)
		if !ok {
			continue
		}
		if safe, found, _ := entry.Get(starlark.String("construction_safe")); found && safe == starlark.False {
			continue
		}
		dllValue, found, _ := entry.Get(starlark.String("dll"))
		if !found {
			continue
		}
		dll, ok := starlark.AsString(dllValue)
		if !ok || dll == "" || standard[strings.ToLower(dll)] {
			continue
		}
		calleeValue, _, _ := entry.Get(starlark.String("callee"))
		callee, _ := starlark.AsString(calleeValue)
		if strings.HasPrefix(strings.ToLower(callee), "uninstall") {
			continue
		}
		output = append(output, entry)
	}
	return starlark.NewList(output)
}

func (i *Installer) installPlanArtifacts(components map[string]bool) (*starlark.List, error) {
	output := make([]starlark.Value, 0)
	for _, pkg := range i.installShieldPackages() {
		packageArchive := pkg.payload
		for index, record := range packageArchive.files {
			if components != nil && !installPlanComponentsSelected(record.components, components) {
				continue
			}
			extension := strings.ToLower(record.name)
			kind := ""
			if strings.HasSuffix(extension, ".sys") || strings.HasSuffix(extension, ".vxd") {
				kind = "driver"
			}
			file := &Entry{archive: packageArchive, index: index}
			exports := make([]starlark.Value, 0)
			selfRegistering := false
			isPE := false
			if record.expandedSize > 0 && record.expandedSize <= 64<<20 && installPlanExecutableArtifact(extension, kind) {
				data, readErr := starfile.ReadAll(file)
				if readErr != nil {
					continue
				}
				if len(data) >= 2 && string(data[:2]) == "MZ" {
					isPE = true
					if parsed, parseErr := windowspe.Exports(data); parseErr == nil {
						for _, export := range parsed {
							if export.Name != "" {
								exports = append(exports, starlark.String(export.Name))
								if strings.EqualFold(export.Name, "DllRegisterServer") {
									selfRegistering = true
								}
							}
						}
					}
				}
			}
			if selfRegistering {
				kind = "self_registration"
			}
			groupSelfRegistration := strings.Contains(strings.ToLower(record.group), "selfregister") && !strings.Contains(strings.ToLower(record.group), "non-selfregister")
			if kind == "" && (!groupSelfRegistration || !isPE) {
				continue
			}
			if kind == "" {
				kind = "self_registration_metadata"
			}
			output = append(output, starlarkStringDict(map[string]starlark.Value{"package_root": starlark.String(pkg.root), "source": starlark.String(record.path), "name": starlark.String(record.name), "group": starlark.String(record.group), "kind": starlark.String(kind), "exports": starlark.NewList(exports), "executable_registration": starlark.Bool(selfRegistering)}))
		}
	}
	return starlark.NewList(output), nil
}

func installPlanExecutableArtifact(name, kind string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".dll") || strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".ocx") || kind == "driver"
}
func installPlanStringMap(name string, value starlark.Value) (map[string]string, error) {
	result := make(map[string]string)
	if value == starlark.None {
		return result, nil
	}
	dict, ok := value.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("installer.plan: %s is %s, want dict", name, value.Type())
	}
	for _, item := range dict.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("installer.plan: %s key is %s, want string", name, item[0].Type())
		}
		text, ok := starlark.AsString(item[1])
		if !ok {
			return nil, fmt.Errorf("installer.plan: %s value for %q is %s, want string", name, key, item[1].Type())
		}
		result[strings.ToLower(key)] = text
	}
	return result, nil
}

func installPlanStringSet(name string, value starlark.Value) (map[string]bool, error) {
	if value == starlark.None {
		return nil, nil
	}
	if _, ok := starlark.AsString(value); ok {
		return nil, fmt.Errorf("installer.plan: %s is string, want iterable of strings", name)
	}
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("installer.plan: %s is %s, want iterable of strings", name, value.Type())
	}
	result := make(map[string]bool)
	iterator := iterable.Iterate()
	defer iterator.Done()
	var item starlark.Value
	for iterator.Next(&item) {
		text, ok := starlark.AsString(item)
		if !ok {
			return nil, fmt.Errorf("installer.plan: %s item is %s, want string", name, item.Type())
		}
		result[strings.ToLower(text)] = true
	}
	return result, nil
}

func installPlanComponentsSelected(components []string, selected map[string]bool) bool {
	for _, component := range components {
		if selected[strings.ToLower(component)] {
			return true
		}
	}
	return false
}

func validInstallPlanFilename(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if character < 0x20 || strings.ContainsRune(`<>:"/\|?*`, character) {
			return false
		}
	}
	return true
}

func installPlanShortcutValue(packageRoot string, shortcut shortcut, locations, variables map[string]string) *starlark.Dict {
	display, displayResolved := expandInstallPlanValue(shortcut.display, locations, variables)
	target, targetResolved := expandInstallPlanValue(shortcut.target, locations, variables)
	arguments, argumentsResolved := expandInstallPlanValue(shortcut.arguments, locations, variables)
	working, workingResolved := expandInstallPlanValue(shortcut.workingDir, locations, variables)
	icon, iconResolved := expandInstallPlanValue(shortcut.icon, locations, variables)
	folderRoot, folderResolved := expandInstallPlanValue(shortcut.folderRoot, locations, variables)
	folder := ""
	if folderResolved {
		folder = joinInstallWindowsPath(folderRoot, shortcut.folder)
	}
	resolved := displayResolved && targetResolved && argumentsResolved && workingResolved && iconResolved && folderResolved
	return starlarkStringDict(map[string]starlark.Value{
		"package_root": starlark.String(packageRoot), "component": starlark.String(shortcut.component),
		"name": starlark.String(shortcut.name), "display": starlark.String(display),
		"folder": starlark.String(shortcut.folder), "folder_root": starlark.String(shortcut.folderRoot),
		"destination_folder": starlark.String(folder), "target": starlark.String(target),
		"arguments": starlark.String(arguments), "working_directory": starlark.String(working),
		"icon": starlark.String(icon), "icon_index": starlark.MakeInt64(int64(shortcut.iconIndex)),
		"type": starlark.MakeInt(int(shortcut.shortcutType)), "resolved": starlark.Bool(resolved),
		"source": starlark.String("InstallShield media database"),
	})
}

func expandInstallPlanValue(value string, locations, variables map[string]string) (string, bool) {
	if value == "" {
		return "", true
	}
	if replacement, ok := variables[strings.ToLower(value)]; ok {
		return replacement, true
	}
	if strings.HasPrefix(value, "<") {
		end := strings.IndexByte(value, '>')
		if end < 0 {
			return value, false
		}
		if replacement, ok := locations[strings.ToLower(value[:end+1])]; ok {
			return joinInstallWindowsPath(replacement, value[end+1:]), true
		}
		return value, false
	}
	return value, true
}

func installPlanFileValue(packageRoot string, file fileRecord, component, destination string, resolved bool) *starlark.Dict {
	components := make([]starlark.Value, len(file.components))
	for index, name := range file.components {
		components[index] = starlark.String(name)
	}
	return starlarkStringDict(map[string]starlark.Value{
		"package_root": starlark.String(packageRoot), "source": starlark.String(file.path), "name": starlark.String(file.name),
		"directory": starlark.String(file.directory), "group": starlark.String(file.group),
		"components": starlark.NewList(components), "component": starlark.String(component),
		"destination": starlark.String(destination), "resolved": starlark.Bool(resolved),
		"size": starlark.MakeUint64(file.expandedSize),
	})
}

func joinInstallWindowsPath(parts ...string) string {
	unc := len(parts) > 0 && strings.HasPrefix(parts[0], `\\`)
	result := ""
	for _, part := range parts {
		part = strings.Trim(strings.ReplaceAll(part, "/", `\`), `\`)
		if part == "" {
			continue
		}
		if result == "" {
			result = part
		} else {
			result += `\` + part
		}
	}
	if unc {
		return `\\` + result
	}
	if len(parts) > 0 && strings.HasPrefix(parts[0], `\`) {
		return `\` + result
	}
	return result
}
