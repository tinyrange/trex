package installscript

import (
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

var installScriptRegistryAPIs = map[string]string{
	"_regcreatekey":           "create_key",
	"_regdeletekey":           "delete_key",
	"_regdeletevalue":         "delete_value",
	"_regsetkeyvalue":         "set_value",
	"_regsetkeybinaryvalue":   "set_binary_value",
	"_regquerykeyvalue":       "query_value",
	"_regquerykeybinaryvalue": "query_binary_value",
}

type installScriptReach struct {
	registry map[string]bool
	shortcut bool
}

func (s *Script) effectsValue() *starlark.Dict {
	reach := s.effectReachability()
	shortcutWrappers := make(map[int]bool)
	rootVariables := make(map[int16]bool)
	for _, block := range s.blocks {
		for _, action := range block.actions {
			if action.opcode != 32 || int(action.functionID) >= len(s.prototypes) {
				continue
			}
			if _, ok := installScriptRegistryAPIs[strings.ToLower(s.prototypes[action.functionID].name)]; ok && len(action.operands) > 1 {
				root := action.operands[1]
				if root.kind == 5 && root.address >= 0 {
					rootVariables[root.address] = true
				}
			}
			if strings.EqualFold(s.prototypes[action.functionID].name, "_CreateShellObjects") && block.functionID >= 0 {
				shortcutWrappers[block.functionID] = true
			}
		}
	}
	rootSetters := s.registryRootSetters(rootVariables)

	registry := make([]starlark.Value, 0)
	shortcuts := make([]starlark.Value, 0)
	for functionID := range s.prototypes {
		root := installScriptArgument{}
		rootKnown := false
		for _, block := range s.blocks {
			if block.functionID != functionID {
				continue
			}
			for _, action := range block.actions {
				if (action.opcode != 32 && action.opcode != 33) || int(action.functionID) >= len(s.prototypes) {
					continue
				}
				callee := int(action.functionID)
				if action.opcode == 32 {
					calleeName := strings.ToLower(s.prototypes[callee].name)
					if operation, ok := installScriptRegistryAPIs[calleeName]; ok && hasLiteralInstallScriptString(action.operands) {
						directReach := installScriptReach{registry: map[string]bool{operation: true}}
						directRoot, directRootKnown := root, rootKnown
						if len(action.operands) > 1 && action.operands[1].kind == 7 {
							directRoot, directRootKnown = action.operands[1], true
						}
						registry = append(registry, s.registryEffectValue(functionID, callee, action, directReach, directRoot, directRootKnown))
					}
					if calleeName == "_createshellobjects" && len(shortcutWrappers) == 0 {
						shortcuts = append(shortcuts, s.shortcutEffectValue(functionID, callee, action))
					}
					continue
				}
				if rootSetters[callee] && len(action.operands) > 0 && action.operands[0].kind == 7 {
					root, rootKnown = action.operands[0], true
					continue
				}
				calleeReach := reach[callee]
				effectRoot, effectRootKnown := installScriptHKEYArgument(action.operands)
				if !effectRootKnown {
					effectRoot, effectRootKnown = root, rootKnown
				}
				if len(calleeReach.registry) != 0 && hasLiteralInstallScriptString(action.operands) && (effectRootKnown || registryMutationWithKey(calleeReach, action.operands)) {
					registry = append(registry, s.registryEffectValue(functionID, callee, action, calleeReach, effectRoot, effectRootKnown))
				}
				if shortcutWrappers[callee] {
					shortcuts = append(shortcuts, s.shortcutEffectValue(functionID, callee, action))
				}
			}
		}
	}
	return starlarkStringDict(map[string]starlark.Value{
		"registry":  starlark.NewList(registry),
		"shortcuts": starlark.NewList(shortcuts),
	})
}

// Effects returns the statically discovered filesystem, registry, shortcut,
// and external-call effects.
func (s *Script) Effects() *starlark.Dict { return s.effectsValue() }

func installScriptHKEYArgument(arguments []installScriptArgument) (installScriptArgument, bool) {
	for _, argument := range arguments {
		if argument.kind == 7 && strings.HasPrefix(installScriptRegistryRoot(argument.number), "HKEY_") {
			return argument, true
		}
	}
	return installScriptArgument{}, false
}

func registryMutationWithKey(reach installScriptReach, arguments []installScriptArgument) bool {
	mutation := reach.registry["create_key"] || reach.registry["delete_key"] || reach.registry["delete_value"] || reach.registry["set_value"] || reach.registry["set_binary_value"]
	if !mutation {
		return false
	}
	for _, argument := range arguments {
		if argument.kind == 6 && strings.Contains(argument.text, `\`) {
			return true
		}
	}
	return false
}

func (s *Script) effectReachability() []installScriptReach {
	reach := make([]installScriptReach, len(s.prototypes))
	for index := range reach {
		reach[index].registry = make(map[string]bool)
	}
	changed := true
	for changed {
		changed = false
		for _, block := range s.blocks {
			if block.functionID < 0 || block.functionID >= len(reach) {
				continue
			}
			for _, action := range block.actions {
				if (action.opcode != 32 && action.opcode != 33) || int(action.functionID) >= len(s.prototypes) {
					continue
				}
				caller := &reach[block.functionID]
				calleeID := int(action.functionID)
				calleeName := strings.ToLower(s.prototypes[calleeID].name)
				if operation, ok := installScriptRegistryAPIs[calleeName]; ok && !caller.registry[operation] {
					caller.registry[operation], changed = true, true
				}
				if calleeName == "_createshellobjects" && !caller.shortcut {
					caller.shortcut, changed = true, true
				}
				if action.opcode == 33 {
					for operation := range reach[calleeID].registry {
						if !caller.registry[operation] {
							caller.registry[operation], changed = true, true
						}
					}
					if reach[calleeID].shortcut && !caller.shortcut {
						caller.shortcut, changed = true, true
					}
				}
			}
		}
	}
	return reach
}

func (s *Script) registryRootSetters(rootVariables map[int16]bool) map[int]bool {
	setters := make(map[int]bool)
	for _, block := range s.blocks {
		for _, action := range block.actions {
			if action.opcode != 6 || len(action.operands) != 2 {
				continue
			}
			destination, source := action.operands[0], action.operands[1]
			if destination.kind == 5 && rootVariables[destination.address] && source.kind == 5 && source.address < 0 {
				setters[block.functionID] = true
			}
		}
	}
	return setters
}

func hasLiteralInstallScriptString(arguments []installScriptArgument) bool {
	for _, argument := range arguments {
		if argument.kind == 6 && argument.text != "" {
			return true
		}
	}
	return false
}

func (s *Script) registryEffectValue(callerID, calleeID int, action installScriptAction, reach installScriptReach, root installScriptArgument, rootKnown bool) *starlark.Dict {
	if reach.registry["set_value"] && reach.registry["set_binary_value"] && len(action.operands) > 2 && action.operands[2].kind == 7 {
		if action.operands[2].number == 3 {
			reach.registry = map[string]bool{"set_binary_value": true}
		} else {
			reach.registry = map[string]bool{"set_value": true}
		}
	}
	operations := make([]string, 0, len(reach.registry))
	for operation := range reach.registry {
		operations = append(operations, operation)
	}
	sort.Strings(operations)
	operationValues := make([]starlark.Value, len(operations))
	for index, operation := range operations {
		operationValues[index] = starlark.String(operation)
	}
	arguments := make([]starlark.Value, len(action.operands))
	literals := make([]string, 0)
	for index, argument := range action.operands {
		arguments[index] = installScriptArgumentValue(argument)
		if argument.kind == 6 && argument.text != "" {
			literals = append(literals, argument.text)
		}
	}
	values := map[string]starlark.Value{
		"kind": starlark.String("registry"), "operations": starlark.NewList(operationValues),
		"caller": starlark.String(s.prototypes[callerID].name), "callee": starlark.String(s.prototypes[calleeID].name),
		"offset": starlark.MakeUint64(uint64(action.offset)), "conditional": starlark.True,
		"arguments": starlark.NewList(arguments), "root": starlark.String("unknown"),
	}
	if len(literals) > 0 {
		values["key"] = starlark.String(literals[0])
	}
	if len(literals) > 1 {
		values["name"] = starlark.String(literals[1])
	}
	if len(literals) > 2 {
		values["literal_data"] = starlark.String(literals[2])
	}
	if rootKnown {
		values["root"] = starlark.String(installScriptRegistryRoot(root.number))
		values["root_value"] = starlark.MakeInt64(int64(root.number))
	}
	return starlarkStringDict(values)
}

func installScriptRegistryRoot(value int32) string {
	switch uint32(value) {
	case 0x80000000:
		return "HKEY_CLASSES_ROOT"
	case 0x80000001:
		return "HKEY_CURRENT_USER"
	case 0x80000002:
		return "HKEY_LOCAL_MACHINE"
	case 0x80000003:
		return "HKEY_USERS"
	case 0x80000005:
		return "HKEY_CURRENT_CONFIG"
	default:
		return "unknown"
	}
}

func (s *Script) shortcutEffectValue(callerID, calleeID int, action installScriptAction) *starlark.Dict {
	arguments := make([]starlark.Value, len(action.operands))
	for index, argument := range action.operands {
		arguments[index] = installScriptArgumentValue(argument)
	}
	return starlarkStringDict(map[string]starlark.Value{
		"kind": starlark.String("shortcuts"), "operation": starlark.String("create_shell_objects"),
		"caller": starlark.String(s.prototypes[callerID].name), "callee": starlark.String(s.prototypes[calleeID].name),
		"offset": starlark.MakeUint64(uint64(action.offset)), "conditional": starlark.True,
		"resolved": starlark.False, "source": starlark.String("InstallShield media database"),
		"arguments": starlark.NewList(arguments),
	})
}
