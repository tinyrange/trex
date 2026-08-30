package installscript

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// installScriptValue is deliberately small: this evaluator proves constants
// and otherwise preserves uncertainty. It never invents a Windows machine
// state to force an installer branch.
type installScriptValue struct {
	kind       byte
	text       string
	num        int32
	known      bool
	reference  bool
	refKind    byte
	refAddress int16
	object     string
}

type installScriptVariable struct {
	kind    byte
	address int16
}

type installScriptEvalState struct {
	vars        map[installScriptVariable]installScriptValue
	sizes       map[installScriptVariable]int32
	properties  map[string]installScriptValue
	handlers    map[int]int
	conditional bool
	depth       int
}

type installScriptEvaluation struct {
	registry          []starlark.Value
	calls             []starlark.Value
	reached           map[int]bool
	steps             int
	entrySteps        int
	incomplete        bool
	incompleteReasons map[string]bool
	profiles          installScriptProfiles
	maximumSteps      int
	maximumDepth      int
	invocations       map[string][]installScriptFunctionResult
	registrySeen      map[string]bool
	callSeen          map[string]bool
	currentEntry      int
	incompleteEntries map[int]map[string]bool
	semanticGaps      map[int]map[uint16]bool
}

type installScriptProfiles map[string]map[string]map[string]string

type installScriptFunctionResult struct {
	state installScriptEvalState
	value installScriptValue
}

func (s *Script) evaluateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if s.legacy != nil {
		return s.evaluateLegacyInstallScript(args, kwargs)
	}
	entry := "application"
	maximumSteps, maximumDepth := 200000, 64
	stringsValue, numbersValue, profilesValue := starlark.Value(starlark.None), starlark.Value(starlark.None), starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("installscript.evaluate", args, kwargs,
		"entry?", &entry, "strings?", &stringsValue, "numbers?", &numbersValue,
		"profiles?", &profilesValue,
		"maximum_steps?", &maximumSteps, "maximum_depth?", &maximumDepth); err != nil {
		return nil, err
	}
	if maximumSteps < 1 || maximumSteps > 10000000 {
		return nil, fmt.Errorf("installscript.evaluate: maximum_steps must be between 1 and 10000000")
	}
	if maximumDepth < 1 || maximumDepth > 1024 {
		return nil, fmt.Errorf("installscript.evaluate: maximum_depth must be between 1 and 1024")
	}
	entryIDs := make([]int, 0)
	if strings.EqualFold(entry, "application") {
		entryIDs = s.installScriptCallbackEntries()
	} else {
		for index, prototype := range s.prototypes {
			if strings.EqualFold(prototype.name, entry) {
				entryIDs = append(entryIDs, index)
				break
			}
		}
	}
	if len(entryIDs) == 0 {
		return nil, fmt.Errorf("installscript.evaluate: entry function %q not found", entry)
	}
	state := installScriptEvalState{vars: make(map[installScriptVariable]installScriptValue)}
	if err := installScriptSeedValues("strings", stringsValue, 4, state.vars); err != nil {
		return nil, err
	}
	if err := installScriptSeedValues("numbers", numbersValue, 5, state.vars); err != nil {
		return nil, err
	}
	profiles, err := installScriptProfileValues(profilesValue)
	if err != nil {
		return nil, err
	}
	evaluation := &installScriptEvaluation{reached: make(map[int]bool), maximumSteps: maximumSteps, maximumDepth: maximumDepth, profiles: profiles, incompleteReasons: make(map[string]bool), incompleteEntries: make(map[int]map[string]bool), semanticGaps: make(map[int]map[uint16]bool), currentEntry: -1}
	evaluation.invocations = make(map[string][]installScriptFunctionResult)
	evaluation.registrySeen = make(map[string]bool)
	evaluation.callSeen = make(map[string]bool)
	finals := make([]starlark.Value, 0)
	finalSeen := make(map[string]bool)
	for _, entryID := range entryIDs {
		// Memoization is per independent engine callback. Sharing it between
		// callbacks would incorrectly reuse a helper's state from another entry.
		evaluation.invocations = make(map[string][]installScriptFunctionResult)
		evaluation.currentEntry = entryID
		evaluation.entrySteps = 0
		for _, result := range s.evaluateFunction(entryID, nil, state, evaluation, make(map[int]bool)) {
			for variable, value := range result.state.vars {
				if variable.address < 0 || !value.known {
					continue
				}
				if seeded, found := state.vars[variable]; found && seeded == value {
					continue
				}
				key := fmt.Sprintf("%d:%d:%d:%s:%t", entryID, variable.kind, variable.address, installScriptValueKey(value), result.state.conditional)
				if finalSeen[key] {
					continue
				}
				finalSeen[key] = true
				finals = append(finals, starlarkStringDict(map[string]starlark.Value{
					"function": starlark.String(s.prototypes[entryID].name), "kind": starlark.MakeInt(int(variable.kind)),
					"address": starlark.MakeInt(int(variable.address)), "value": installScriptEvaluatedValue(value),
					"conditional": starlark.Bool(result.state.conditional),
				}))
			}
		}
	}
	reached := make([]string, 0, len(evaluation.reached))
	for id := range evaluation.reached {
		reached = append(reached, s.prototypes[id].name)
	}
	sort.Slice(reached, func(i, j int) bool { return strings.ToLower(reached[i]) < strings.ToLower(reached[j]) })
	reachedValues := make([]starlark.Value, len(reached))
	for i, name := range reached {
		reachedValues[i] = starlark.String(name)
	}
	reasons := make([]string, 0, len(evaluation.incompleteReasons))
	for reason := range evaluation.incompleteReasons {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	reasonValues := make([]starlark.Value, len(reasons))
	for index, reason := range reasons {
		reasonValues[index] = starlark.String(reason)
	}
	entryValues := make([]starlark.Value, len(entryIDs))
	for index, id := range entryIDs {
		entryReasons := make([]string, 0, len(evaluation.incompleteEntries[id]))
		for reason := range evaluation.incompleteEntries[id] {
			entryReasons = append(entryReasons, reason)
		}
		sort.Strings(entryReasons)
		values := make([]starlark.Value, len(entryReasons))
		for reasonIndex, reason := range entryReasons {
			values[reasonIndex] = starlark.String(reason)
		}
		gapValues := make([]starlark.Value, 0, len(evaluation.semanticGaps[id]))
		gaps := make([]int, 0, len(evaluation.semanticGaps[id]))
		for opcode := range evaluation.semanticGaps[id] {
			gaps = append(gaps, int(opcode))
		}
		sort.Ints(gaps)
		for _, opcode := range gaps {
			gapValues = append(gapValues, starlarkStringDict(map[string]starlark.Value{"opcode": starlark.MakeInt(opcode), "name": starlark.String(installScriptOpcodeName(uint16(opcode)))}))
		}
		entryValues[index] = starlarkStringDict(map[string]starlark.Value{
			"id": starlark.MakeInt(id), "function": starlark.String(s.prototypes[id].name),
			"incomplete": starlark.Bool(len(entryReasons) != 0), "incomplete_reasons": starlark.NewList(values),
			"semantic_gaps": starlark.NewList(gapValues), "semantically_complete": starlark.Bool(len(gapValues) == 0),
		})
	}
	registryWrites := make([]starlark.Value, 0)
	definitiveWrites := make([]starlark.Value, 0)
	for _, value := range evaluation.registry {
		entry := value.(*starlark.Dict)
		resolvedValue, _, _ := entry.Get(starlark.String("resolved"))
		conditionalValue, _, _ := entry.Get(starlark.String("conditional"))
		entryIDValue, _, _ := entry.Get(starlark.String("entry_id"))
		entryID, entryErr := starlark.AsInt32(entryIDValue)
		entryIncomplete := entryErr != nil || len(evaluation.incompleteEntries[int(entryID)]) != 0 || len(evaluation.semanticGaps[int(entryID)]) != 0
		definitive := resolvedValue == starlark.True && conditionalValue == starlark.False && !entryIncomplete
		_ = entry.SetKey(starlark.String("definitive"), starlark.Bool(definitive))
		mutationValue, _, _ := entry.Get(starlark.String("mutation"))
		if mutationValue == starlark.True {
			registryWrites = append(registryWrites, entry)
			if definitive {
				definitiveWrites = append(definitiveWrites, entry)
			}
		}
	}
	return starlarkStringDict(map[string]starlark.Value{
		"entry": starlark.String(entry), "registry": starlark.NewList(evaluation.registry),
		"registry_writes": starlark.NewList(registryWrites), "definitive_registry_writes": starlark.NewList(definitiveWrites),
		"calls": starlark.NewList(evaluation.calls), "reached_functions": starlark.NewList(reachedValues),
		"entries":       starlark.NewList(entryValues),
		"final_globals": starlark.NewList(finals), "steps": starlark.MakeInt(evaluation.steps),
		"incomplete": starlark.Bool(evaluation.incomplete), "incomplete_reasons": starlark.NewList(reasonValues),
	}), nil
}

// Evaluate symbolically evaluates the requested InstallScript entry point.
func (s *Script) Evaluate(kwargs []starlark.Tuple) (starlark.Value, error) {
	return s.evaluateBuiltin(nil, nil, nil, kwargs)
}

func (s *Script) installScriptCallbackEntries() []int {
	project := make(map[int]bool)
	for index, prototype := range s.prototypes {
		if prototype.flags&1 != 0 {
			break
		}
		if prototype.flags&2 != 0 && prototype.blockIndex != 0xffff {
			project[index] = true
		}
	}
	incoming := make(map[int]bool)
	for _, block := range s.blocks {
		if !project[block.functionID] {
			continue
		}
		for _, action := range block.actions {
			if action.opcode == 33 && project[int(action.functionID)] {
				incoming[int(action.functionID)] = true
			}
		}
	}
	entries := make([]int, 0)
	for id := range project {
		if !incoming[id] {
			entries = append(entries, id)
		}
	}
	sort.Ints(entries)
	if len(entries) == 0 {
		for id := range project {
			entries = append(entries, id)
		}
		sort.Ints(entries)
	}
	return entries
}

func installScriptValueKey(value installScriptValue) string {
	return fmt.Sprintf("%t:%d:%d:%s:%t:%d:%d:%s", value.known, value.kind, value.num, value.text, value.reference, value.refKind, value.refAddress, value.object)
}

func installScriptSeedValues(name string, value starlark.Value, kind byte, output map[installScriptVariable]installScriptValue) error {
	if value == starlark.None {
		return nil
	}
	dict, ok := value.(*starlark.Dict)
	if !ok {
		return fmt.Errorf("installscript.evaluate: %s is %s, want dict", name, value.Type())
	}
	for _, item := range dict.Items() {
		var address int
		switch key := item[0].(type) {
		case starlark.Int:
			parsed, ok := key.Int64()
			if !ok {
				return fmt.Errorf("installscript.evaluate: %s address is out of range", name)
			}
			address = int(parsed)
		case starlark.String:
			parsed, err := strconv.Atoi(string(key))
			if err != nil {
				return fmt.Errorf("installscript.evaluate: invalid %s address %q", name, key)
			}
			address = parsed
		default:
			return fmt.Errorf("installscript.evaluate: %s key is %s, want int or decimal string", name, item[0].Type())
		}
		if address < -32768 || address > 32767 {
			return fmt.Errorf("installscript.evaluate: %s address %d is out of range", name, address)
		}
		if kind == 4 {
			text, ok := starlark.AsString(item[1])
			if !ok {
				return fmt.Errorf("installscript.evaluate: string %d is %s", address, item[1].Type())
			}
			output[installScriptVariable{kind, int16(address)}] = installScriptValue{kind: 4, text: text, known: true}
		} else {
			integer, ok := item[1].(starlark.Int)
			if !ok {
				return fmt.Errorf("installscript.evaluate: number %d is %s", address, item[1].Type())
			}
			number, ok := integer.Int64()
			if !ok || number < -2147483648 || number > 2147483647 {
				return fmt.Errorf("installscript.evaluate: number %d is out of range", address)
			}
			output[installScriptVariable{kind, int16(address)}] = installScriptValue{kind: 5, num: int32(number), known: true}
		}
	}
	return nil
}

func installScriptProfileValues(value starlark.Value) (installScriptProfiles, error) {
	profiles := make(installScriptProfiles)
	if value == starlark.None {
		return profiles, nil
	}
	files, ok := value.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("installscript.evaluate: profiles is %s, want dict", value.Type())
	}
	for _, fileItem := range files.Items() {
		fileName, ok := starlark.AsString(fileItem[0])
		if !ok {
			return nil, fmt.Errorf("installscript.evaluate: profile filename is %s, want string", fileItem[0].Type())
		}
		sectionsValue, ok := fileItem[1].(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("installscript.evaluate: profile %q is %s, want dict", fileName, fileItem[1].Type())
		}
		sections := make(map[string]map[string]string)
		for _, sectionItem := range sectionsValue.Items() {
			sectionName, ok := starlark.AsString(sectionItem[0])
			if !ok {
				return nil, fmt.Errorf("installscript.evaluate: profile section is %s, want string", sectionItem[0].Type())
			}
			valuesValue, ok := sectionItem[1].(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("installscript.evaluate: profile section %q is %s, want dict", sectionName, sectionItem[1].Type())
			}
			values := make(map[string]string)
			for _, item := range valuesValue.Items() {
				key, keyOK := starlark.AsString(item[0])
				entry, valueOK := starlark.AsString(item[1])
				if !keyOK || !valueOK {
					return nil, fmt.Errorf("installscript.evaluate: profile %q section %q must contain string keys and values", fileName, sectionName)
				}
				values[strings.ToLower(key)] = entry
			}
			sections[strings.ToLower(sectionName)] = values
		}
		profiles[strings.ToLower(pathBaseWindows(fileName))] = sections
	}
	return profiles, nil
}

func pathBaseWindows(value string) string {
	value = strings.ReplaceAll(value, "/", `\`)
	if index := strings.LastIndexByte(value, '\\'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func joinInstallWindowsPath(parts ...string) string {
	var result string
	for _, part := range parts {
		part = strings.ReplaceAll(part, "/", `\`)
		if part == "" {
			continue
		}
		if result == "" {
			result = strings.TrimRight(part, `\`)
			continue
		}
		result = strings.TrimRight(result, `\`) + `\` + strings.Trim(part, `\`)
	}
	return result
}

func cloneInstallScriptState(state installScriptEvalState) installScriptEvalState {
	copy := installScriptEvalState{vars: make(map[installScriptVariable]installScriptValue, len(state.vars)), sizes: make(map[installScriptVariable]int32, len(state.sizes)), properties: make(map[string]installScriptValue, len(state.properties)), handlers: make(map[int]int, len(state.handlers)), conditional: state.conditional, depth: state.depth}
	for key, value := range state.vars {
		copy.vars[key] = value
	}
	for key, value := range state.sizes {
		copy.sizes[key] = value
	}
	for key, value := range state.properties {
		copy.properties[key] = value
	}
	for key, value := range state.handlers {
		copy.handlers[key] = value
	}
	return copy
}

func installScriptRead(argument installScriptArgument, state installScriptEvalState) installScriptValue {
	switch argument.kind {
	case 4, 5, 8:
		if value, ok := state.vars[installScriptVariable{argument.kind, argument.address}]; ok {
			return value
		}
		return installScriptValue{kind: argument.kind}
	case 6:
		return installScriptValue{kind: 4, text: argument.text, known: true}
	case 7:
		return installScriptValue{kind: 5, num: argument.number, known: true}
	}
	return installScriptValue{}
}

func installScriptWrite(argument installScriptArgument, value installScriptValue, state *installScriptEvalState) {
	if argument.kind == 4 || argument.kind == 5 || argument.kind == 8 {
		value.kind = argument.kind
		state.vars[installScriptVariable{argument.kind, argument.address}] = value
	}
}

func (s *Script) evaluateFunction(functionID int, arguments []installScriptValue, initial installScriptEvalState, evaluation *installScriptEvaluation, active map[int]bool) []installScriptFunctionResult {
	if functionID < 0 || functionID >= len(s.prototypes) || initial.depth >= evaluation.maximumDepth || active[functionID] {
		evaluation.markIncomplete("recursion or call-depth bound")
		return nil
	}
	prototype := s.prototypes[functionID]
	if prototype.blockIndex == 0xffff || int(prototype.blockIndex) >= len(s.blocks) {
		return nil
	}
	invocationKey := installScriptInvocationKey(functionID, arguments, initial)
	if cached, found := evaluation.invocations[invocationKey]; found {
		return cloneInstallScriptResults(cached)
	}
	state := cloneInstallScriptState(initial)
	state.depth++
	counts := map[byte]int16{4: -101, 5: -101, 8: -101}
	for index, typ := range prototype.arguments {
		if index >= len(arguments) {
			break
		}
		kind := installScriptConcreteKind(typ.concreteType)
		if kind == 0 {
			continue
		}
		address := counts[kind]
		counts[kind]--
		value := arguments[index]
		value.kind = kind
		state.vars[installScriptVariable{kind, address}] = value
	}
	evaluation.reached[functionID] = true
	active = cloneInstallScriptActive(active)
	active[functionID] = true
	type cursor struct {
		block, action int
		state         installScriptEvalState
	}
	queue := []cursor{{block: int(prototype.blockIndex), state: state}}
	results := make([]installScriptFunctionResult, 0)
	visits := make(map[string]installScriptEvalState)
	for len(queue) > 0 && evaluation.entrySteps < evaluation.maximumSteps {
		current := queue[0]
		queue = queue[1:]
		if current.block < 0 || current.block >= len(s.blocks) {
			continue
		}
		key := fmt.Sprintf("%d:%d", current.block, current.action)
		if previous, found := visits[key]; found {
			joined := joinInstallScriptStates(previous, current.state)
			if installScriptStateKey(joined) == installScriptStateKey(previous) {
				// The instruction has reached an abstract fixed point.
				continue
			}
			visits[key] = cloneInstallScriptState(joined)
			current.state = joined
		} else {
			visits[key] = cloneInstallScriptState(current.state)
		}
		block := s.blocks[current.block]
		if current.action >= len(block.actions) {
			queue = append(queue, cursor{block: current.block + 1, state: current.state})
			continue
		}
		action := block.actions[current.action]
		evaluation.steps++
		evaluation.entrySteps++
		next := cursor{block: current.block, action: current.action + 1, state: current.state}
		switch action.opcode {
		case 2, 3:
			continue
		case 35, 36, 37:
			returned := installScriptValue{}
			if len(action.operands) > 0 {
				returned = installScriptRead(action.operands[0], current.state)
			}
			results = append(results, installScriptFunctionResult{state: current.state, value: returned})
			continue
		case 38:
			results = append(results, installScriptFunctionResult{state: current.state})
			continue
		case 4:
			condition := installScriptValue{}
			if len(action.operands) > 1 {
				condition = installScriptRead(action.operands[1], current.state)
			}
			if condition.known && condition.kind == 5 {
				if condition.num != 0 {
					queue = append(queue, next)
				} else {
					queue = append(queue, cursor{block: current.block + int(action.target), state: current.state})
				}
				continue
			}
			thenState, elseState := cloneInstallScriptState(current.state), cloneInstallScriptState(current.state)
			thenState.conditional, elseState.conditional = true, true
			queue = append(queue, cursor{block: current.block, action: current.action + 1, state: thenState}, cursor{block: current.block + int(action.target), state: elseState})
			continue
		case 5:
			queue = append(queue, cursor{block: current.block + int(action.target), state: current.state})
			continue
		case 6:
			if len(action.operands) == 2 {
				installScriptWrite(action.operands[0], installScriptRead(action.operands[1], current.state), &next.state)
			}
		case 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 23, 24, 25:
			if len(action.operands) >= 3 {
				installScriptWrite(action.operands[0], installScriptBinary(action.opcode, installScriptRead(action.operands[1], current.state), installScriptRead(action.operands[2], current.state)), &next.state)
			}
		case 21:
			if len(action.operands) >= 2 {
				value := installScriptRead(action.operands[1], current.state)
				if value.known {
					value.num = ^value.num
				}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 26, 60:
			if len(action.operands) >= 2 {
				source := action.operands[1]
				value := installScriptValue{kind: action.operands[0].kind, known: true, reference: true, refKind: source.kind, refAddress: source.address}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 29:
			if len(action.operands) >= 3 {
				target := installScriptRead(action.operands[0], current.state)
				index := installScriptRead(action.operands[1], current.state)
				byteValue := installScriptRead(action.operands[2], current.state)
				value := installScriptValue{kind: 4}
				if target.known && index.known && byteValue.known && index.num >= 0 && byteValue.num >= 0 && byteValue.num <= 255 {
					position := int(index.num)
					switch {
					case position < len(target.text) && byteValue.num == 0:
						value.known, value.text = true, target.text[:position]
					case position < len(target.text):
						bytes := []byte(target.text)
						bytes[position] = byte(byteValue.num)
						value.known, value.text = true, string(bytes)
					case position == len(target.text) && byteValue.num == 0:
						value.known, value.text = true, target.text
					case position == len(target.text):
						value.known, value.text = true, target.text+string(byte(byteValue.num))
					}
				}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 30:
			if len(action.operands) >= 3 {
				source := installScriptRead(action.operands[1], current.state)
				index := installScriptRead(action.operands[2], current.state)
				value := installScriptValue{kind: 5}
				if source.known && index.known && index.num >= 0 && int64(index.num) < int64(len(source.text)) {
					value.known, value.num = true, int32(source.text[index.num])
				}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 32:
			s.evaluateExternal(functionID, action, &next.state, evaluation)
		case 33:
			values := make([]installScriptValue, len(action.operands))
			for i, operand := range action.operands {
				values[i] = installScriptRead(operand, current.state)
			}
			calleeState := cloneInstallScriptState(current.state)
			calleeState.conditional = current.state.conditional
			s.applyInstallScriptGlobalSetter(int(action.functionID), values, &next.state)
			calleeResults := s.evaluateFunction(int(action.functionID), values, calleeState, evaluation, active)
			if len(calleeResults) != 0 {
				for _, result := range calleeResults {
					returned := cloneInstallScriptState(next.state)
					s.propagateInstallScriptResult(int(action.functionID), action.operands, result, &returned)
					s.applyInstallScriptProfileWrapper(int(action.functionID), action.operands, values, &returned, evaluation.profiles)
					queue = append(queue, cursor{block: next.block, action: next.action, state: returned})
				}
				continue
			}
		case 40:
			if len(action.operands) >= 2 {
				source := installScriptRead(action.operands[1], current.state)
				value := installScriptValue{kind: 5}
				if source.known {
					value.known, value.num = true, int32(len(source.text))
				}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 41:
			if len(action.operands) >= 4 {
				source := installScriptRead(action.operands[1], current.state)
				start := installScriptRead(action.operands[2], current.state)
				length := installScriptRead(action.operands[3], current.state)
				value := installScriptValue{kind: 4}
				if source.known && start.known && length.known && start.num >= 0 && length.num >= 0 {
					begin, end := int64(start.num), int64(start.num)+int64(length.num)
					if begin <= int64(len(source.text)) {
						if end > int64(len(source.text)) {
							end = int64(len(source.text))
						}
						value.known, value.text = true, source.text[begin:end]
					}
				}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 42:
			value := installScriptValue{kind: 5}
			if len(action.operands) >= 2 {
				haystack := installScriptRead(action.operands[0], current.state)
				needle := installScriptRead(action.operands[1], current.state)
				if haystack.known && needle.known {
					value.known, value.num = true, int32(strings.Index(haystack.text, needle.text))
				}
			}
			next.state.vars[installScriptVariable{kind: 8, address: 0}] = value
		case 44:
			if len(action.operands) >= 2 {
				source := installScriptRead(action.operands[1], current.state)
				value := installScriptValue{kind: 5}
				if source.known {
					if number, err := strconv.ParseInt(strings.TrimSpace(source.text), 10, 32); err == nil {
						value.known, value.num = true, int32(number)
					}
				}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 45:
			if len(action.operands) >= 2 {
				source := installScriptRead(action.operands[1], current.state)
				value := installScriptValue{kind: 4}
				if source.known {
					value.known, value.text = true, strconv.FormatInt(int64(source.num), 10)
				}
				installScriptWrite(action.operands[0], value, &next.state)
			}
		case 49:
			if len(action.operands) >= 2 && (action.operands[0].kind == 4 || action.operands[0].kind == 8) {
				size := installScriptRead(action.operands[1], current.state)
				if size.known && size.num >= 0 {
					next.state.sizes[installScriptVariable{kind: action.operands[0].kind, address: action.operands[0].address}] = size.num
				}
			}
		case 50:
			value := installScriptValue{kind: 5}
			if len(action.operands) >= 1 {
				variable := installScriptVariable{kind: action.operands[0].kind, address: action.operands[0].address}
				if size, found := current.state.sizes[variable]; found {
					value.known, value.num = true, size
				} else if source := installScriptRead(action.operands[0], current.state); source.known {
					value.known, value.num = true, int32(len(source.text)+1)
				}
			}
			next.state.vars[installScriptVariable{kind: 8, address: 0}] = value
		case 46, 47:
			if len(action.operands) >= 2 {
				handler := installScriptRead(action.operands[0], current.state)
				function := installScriptRead(action.operands[1], current.state)
				if handler.known && function.known && function.num >= 0 && int(function.num) < len(s.prototypes) {
					next.state.handlers[int(handler.num)] = int(function.num)
				}
			}
		case 48:
			if len(action.operands) >= 1 {
				handler := installScriptRead(action.operands[0], current.state)
				callees := make([]int, 0, 1)
				if handler.known {
					if callee, found := next.state.handlers[int(handler.num)]; found {
						callees = append(callees, callee)
					} else {
						callees = s.installScriptHandlerCandidates(int(handler.num))
					}
				}
				queued := false
				for _, callee := range callees {
					calleeState := cloneInstallScriptState(current.state)
					if len(callees) > 1 {
						calleeState.conditional = true
					}
					for _, result := range s.evaluateFunction(callee, nil, calleeState, evaluation, active) {
						returned := cloneInstallScriptState(next.state)
						s.propagateInstallScriptResult(callee, nil, result, &returned)
						queue = append(queue, cursor{block: next.block, action: next.action, state: returned})
						queued = true
					}
				}
				if queued {
					continue
				}
				if len(callees) == 0 {
					evaluation.markSemanticGap(action.opcode)
				} else {
					// A handler with no return terminates this execution path.
					continue
				}
			}
		case 51, 52:
			s.evaluatePropertyPut(action, current.state, &next.state)
		case 53:
			s.evaluatePropertyGet(action, current.state, &next.state)
		case 1, 34, 39, 54, 55, 56, 57, 58:
			// Metadata, statement boundaries, protected-region boundaries, and
			// DLL lifetime annotations do not alter the successful path's scalar
			// state. Exceptions leave that path and cannot add successful-install
			// registry effects.
		default:
			evaluation.markSemanticGap(action.opcode)
		}
		queue = append(queue, next)
	}
	if evaluation.entrySteps >= evaluation.maximumSteps {
		evaluation.markIncomplete("instruction bound")
	} else {
		evaluation.invocations[invocationKey] = cloneInstallScriptResults(results)
	}
	return results
}

func cloneInstallScriptResults(input []installScriptFunctionResult) []installScriptFunctionResult {
	output := make([]installScriptFunctionResult, len(input))
	for index, result := range input {
		output[index] = installScriptFunctionResult{state: cloneInstallScriptState(result.state), value: result.value}
	}
	return output
}

// joinInstallScriptStates is the least upper bound for the evaluator's
// constant domain. A value remains known only when every path agrees on it;
// disagreement widens it to unknown. This makes loops converge without an
// arbitrary visit count while retaining every fact used for definitive output.
func joinInstallScriptStates(left, right installScriptEvalState) installScriptEvalState {
	joined := cloneInstallScriptState(left)
	for key, value := range joined.vars {
		if other, found := right.vars[key]; !found || other != value {
			delete(joined.vars, key)
		}
	}
	for key, value := range joined.sizes {
		if other, found := right.sizes[key]; !found || other != value {
			delete(joined.sizes, key)
		}
	}
	for key, value := range joined.properties {
		if other, found := right.properties[key]; !found || other != value {
			delete(joined.properties, key)
		}
	}
	for key, value := range joined.handlers {
		if other, found := right.handlers[key]; !found || other != value {
			delete(joined.handlers, key)
		}
	}
	joined.conditional = left.conditional || right.conditional
	if right.depth > joined.depth {
		joined.depth = right.depth
	}
	return joined
}

func (s *Script) installScriptHandlerCandidates(handler int) []int {
	candidates := make(map[int]bool)
	for _, block := range s.blocks {
		for _, action := range block.actions {
			if (action.opcode != 46 && action.opcode != 47) || len(action.operands) < 2 || action.operands[0].kind != 7 || int(action.operands[0].number) != handler || action.operands[1].kind != 7 {
				continue
			}
			function := int(action.operands[1].number)
			if function >= 0 && function < len(s.prototypes) {
				candidates[function] = true
			}
		}
	}
	output := make([]int, 0, len(candidates))
	for function := range candidates {
		output = append(output, function)
	}
	sort.Ints(output)
	return output
}

func (e *installScriptEvaluation) markSemanticGap(opcode uint16) {
	if e.currentEntry < 0 {
		return
	}
	if e.semanticGaps[e.currentEntry] == nil {
		e.semanticGaps[e.currentEntry] = make(map[uint16]bool)
	}
	e.semanticGaps[e.currentEntry][opcode] = true
}

func (s *Script) applyInstallScriptProfileWrapper(functionID int, operands []installScriptArgument, values []installScriptValue, state *installScriptEvalState, profiles installScriptProfiles) {
	if functionID < 0 || functionID >= len(s.prototypes) || len(values) < 4 || len(operands) < 4 {
		return
	}
	kind := byte(0)
	for _, block := range s.blocks {
		if block.functionID != functionID {
			continue
		}
		for _, action := range block.actions {
			if action.opcode != 32 || int(action.functionID) >= len(s.prototypes) {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(s.prototypes[action.functionID].name, "A"))
			if name == "getprivateprofileint" {
				kind = 5
			}
			if name == "getprivateprofilestring" {
				kind = 4
			}
		}
	}
	if kind == 0 {
		return
	}
	entry, found := profiles.lookup(values[0], values[1], values[2])
	if !found {
		return
	}
	value := installScriptValue{kind: kind, text: entry, known: true}
	if kind == 5 {
		number, err := strconv.ParseInt(strings.TrimSpace(entry), 0, 32)
		if err != nil {
			return
		}
		value.num = int32(number)
	}
	installScriptWrite(operands[3], value, state)
}

func (s *Script) evaluatePropertyPut(action installScriptAction, current installScriptEvalState, next *installScriptEvalState) {
	if len(action.operands) < 3 {
		return
	}
	key, known := installScriptPropertyKey(action.operands[:len(action.operands)-1], current)
	value := installScriptRead(action.operands[len(action.operands)-1], current)
	if known {
		next.properties[key] = value
	}
	if len(action.operands) == 4 {
		property := installScriptRead(action.operands[1], current)
		name := installScriptRead(action.operands[2], current)
		if property.known && name.known && strings.EqualFold(property.text, "Value") {
			if address, found := installScriptSystemStringAddress(name.text); found {
				value.kind = 4
				next.vars[installScriptVariable{kind: 4, address: address}] = value
			}
		}
	}
}

func (s *Script) evaluatePropertyGet(action installScriptAction, current installScriptEvalState, next *installScriptEvalState) {
	value := installScriptValue{kind: 8}
	key, known := installScriptPropertyKey(action.operands, current)
	if known {
		if stored, found := current.properties[key]; found {
			value = stored
		} else if len(action.operands) == 3 {
			property := installScriptRead(action.operands[1], current)
			name := installScriptRead(action.operands[2], current)
			if property.known && name.known && strings.EqualFold(property.text, "Value") {
				if address, found := installScriptSystemStringAddress(name.text); found {
					value = current.vars[installScriptVariable{kind: 4, address: address}]
				}
			}
		}
		if !value.known && value.object == "" {
			// A property read returns an object with a stable identity. Using the
			// complete property path here lets cycles grow that path forever, even
			// though every traversal denotes the same abstract result object.
			value.object = fmt.Sprintf("property@%d", action.offset)
		}
	}
	next.vars[installScriptVariable{kind: 8, address: 0}] = value
}

func installScriptPropertyKey(operands []installScriptArgument, state installScriptEvalState) (string, bool) {
	if len(operands) < 2 {
		return "", false
	}
	base := installScriptRead(operands[0], state)
	identity := base.object
	if identity == "" && (operands[0].kind == 4 || operands[0].kind == 5 || operands[0].kind == 8) {
		identity = fmt.Sprintf("%d:%d", operands[0].kind, operands[0].address)
	}
	if identity == "" {
		return "", false
	}
	var builder strings.Builder
	builder.WriteString(identity)
	for _, operand := range operands[1:] {
		value := installScriptRead(operand, state)
		if !value.known {
			return "", false
		}
		if value.kind == 4 {
			fmt.Fprintf(&builder, ".s:%s", strings.ToLower(value.text))
		} else {
			fmt.Fprintf(&builder, ".n:%d", value.num)
		}
	}
	return builder.String(), true
}

func installScriptSystemStringAddress(name string) (int16, bool) {
	addresses := map[string]int16{
		"TARGETDIR": 8, "SUPPORTDIR": 9, "PROGRAMFILES": 30,
	}
	address, found := addresses[strings.ToUpper(name)]
	return address, found
}

func installScriptStateKey(state installScriptEvalState) string {
	keys := make([]installScriptVariable, 0, len(state.vars))
	for variable := range state.vars {
		keys = append(keys, variable)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].address < keys[j].address
	})
	var builder strings.Builder
	fmt.Fprintf(&builder, "%t", state.conditional)
	for _, variable := range keys {
		value := state.vars[variable]
		fmt.Fprintf(&builder, ":%d:%d:%s", variable.kind, variable.address, installScriptValueKey(value))
	}
	sizeKeys := make([]installScriptVariable, 0, len(state.sizes))
	for variable := range state.sizes {
		sizeKeys = append(sizeKeys, variable)
	}
	sort.Slice(sizeKeys, func(i, j int) bool {
		if sizeKeys[i].kind != sizeKeys[j].kind {
			return sizeKeys[i].kind < sizeKeys[j].kind
		}
		return sizeKeys[i].address < sizeKeys[j].address
	})
	for _, variable := range sizeKeys {
		fmt.Fprintf(&builder, ":size:%d:%d:%d", variable.kind, variable.address, state.sizes[variable])
	}
	handlerKeys := make([]int, 0, len(state.handlers))
	for handler := range state.handlers {
		handlerKeys = append(handlerKeys, handler)
	}
	sort.Ints(handlerKeys)
	for _, handler := range handlerKeys {
		fmt.Fprintf(&builder, ":handler:%d:%d", handler, state.handlers[handler])
	}
	propertyKeys := make([]string, 0, len(state.properties))
	for key := range state.properties {
		propertyKeys = append(propertyKeys, key)
	}
	sort.Strings(propertyKeys)
	for _, key := range propertyKeys {
		fmt.Fprintf(&builder, ":property:%s:%s", key, installScriptValueKey(state.properties[key]))
	}
	return builder.String()
}

func (e *installScriptEvaluation) markIncomplete(reason string) {
	e.incomplete = true
	e.incompleteReasons[reason] = true
	if e.currentEntry >= 0 {
		if e.incompleteEntries[e.currentEntry] == nil {
			e.incompleteEntries[e.currentEntry] = make(map[string]bool)
		}
		e.incompleteEntries[e.currentEntry][reason] = true
	}
}

func (s *Script) propagateInstallScriptResult(functionID int, operands []installScriptArgument, result installScriptFunctionResult, state *installScriptEvalState) {
	prototype := s.prototypes[functionID]
	counts := map[byte]int16{4: -101, 5: -101, 8: -101}
	for index, typ := range prototype.arguments {
		kind := installScriptConcreteKind(typ.concreteType)
		if kind == 0 {
			continue
		}
		address := counts[kind]
		counts[kind]--
		if index >= len(operands) || (typ.concreteType != 2 && typ.concreteType != 3 && typ.concreteType != 4) {
			continue
		}
		if value, found := result.state.vars[installScriptVariable{kind: kind, address: address}]; found {
			installScriptWrite(operands[index], value, state)
		}
	}
	for variable, value := range result.state.vars {
		if variable.address >= 0 {
			state.vars[variable] = value
		}
	}
	for key, value := range result.state.properties {
		state.properties[key] = value
	}
	for key, value := range result.state.handlers {
		state.handlers[key] = value
	}
	if result.value.known {
		state.vars[installScriptVariable{kind: 8, address: 0}] = result.value
	}
	state.conditional = state.conditional || result.state.conditional
}

func installScriptInvocationKey(functionID int, arguments []installScriptValue, state installScriptEvalState) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%d:%s", functionID, installScriptStateKey(state))
	for _, value := range arguments {
		fmt.Fprintf(&builder, ":%d:%t:%d:%s", value.kind, value.known, value.num, value.text)
	}
	return builder.String()
}

func (s *Script) applyInstallScriptGlobalSetter(functionID int, arguments []installScriptValue, state *installScriptEvalState) {
	if functionID < 0 || functionID >= len(s.prototypes) || len(arguments) == 0 {
		return
	}
	for blockIndex := int(s.prototypes[functionID].blockIndex); blockIndex >= 0 && blockIndex < len(s.blocks); blockIndex++ {
		for _, action := range s.blocks[blockIndex].actions {
			if action.opcode == 6 && len(action.operands) == 2 && action.operands[0].kind == 5 && action.operands[0].address >= 0 && action.operands[1].kind == 5 && action.operands[1].address == -101 {
				installScriptWrite(action.operands[0], arguments[0], state)
			}
			if action.opcode >= 35 && action.opcode <= 38 {
				return
			}
		}
	}
}

func cloneInstallScriptActive(input map[int]bool) map[int]bool {
	output := make(map[int]bool, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func installScriptConcreteKind(value byte) byte {
	switch value {
	case 2, 5:
		return 4
	case 3, 6:
		return 5
	case 4, 7:
		return 8
	}
	return 0
}

func installScriptBinary(opcode uint16, left, right installScriptValue) installScriptValue {
	result := installScriptValue{kind: 5}
	if !left.known || !right.known {
		return result
	}
	result.known = true
	if opcode == 7 && (left.kind == 4 || right.kind == 4) {
		result.kind, result.text = 4, left.text+right.text
		return result
	}
	if opcode == 20 && left.kind == 4 && right.kind == 4 {
		result.kind = 4
		result.known = left.known && right.known
		result.text = joinInstallWindowsPath(left.text, right.text)
		return result
	}
	a, b := left.num, right.num
	switch opcode {
	case 7:
		result.num = a + b
	case 8:
		if b == 0 {
			result.known = false
		} else {
			result.num = a % b
		}
	case 9:
		result.num = boolInstallScriptNumber(a < b)
	case 10:
		result.num = boolInstallScriptNumber(a > b)
	case 11:
		result.num = boolInstallScriptNumber(a <= b)
	case 12:
		result.num = boolInstallScriptNumber(a >= b)
	case 13:
		if left.kind == 4 || right.kind == 4 {
			result.num = boolInstallScriptNumber(left.text == right.text)
		} else {
			result.num = boolInstallScriptNumber(a == b)
		}
	case 14:
		if left.kind == 4 || right.kind == 4 {
			result.num = boolInstallScriptNumber(left.text != right.text)
		} else {
			result.num = boolInstallScriptNumber(a != b)
		}
	case 15:
		result.num = a - b
	case 16:
		result.num = a * b
	case 17:
		if b == 0 {
			result.known = false
		} else {
			result.num = a / b
		}
	case 18:
		result.num = a & b
	case 19:
		result.num = a | b
	case 20:
		result.num = a ^ b
	case 22:
		result.num = a << uint32(b)
	case 23:
		result.num = a >> uint32(b)
	case 24:
		result.num = boolInstallScriptNumber(a != 0 || b != 0)
	case 25:
		result.num = boolInstallScriptNumber(a != 0 && b != 0)
	}
	return result
}
func boolInstallScriptNumber(value bool) int32 {
	if value {
		return 1
	}
	return 0
}

func (s *Script) evaluateExternal(caller int, action installScriptAction, state *installScriptEvalState, evaluation *installScriptEvaluation) {
	if int(action.functionID) >= len(s.prototypes) {
		return
	}
	prototype := s.prototypes[action.functionID]
	values := make([]installScriptValue, len(action.operands))
	display := make([]starlark.Value, len(values))
	allKnown := true
	for i, operand := range action.operands {
		values[i] = installScriptRead(operand, *state)
		display[i] = installScriptEvaluatedValue(values[i])
		allKnown = allKnown && values[i].known
	}
	types := make([]starlark.Value, len(prototype.arguments))
	for index, typ := range prototype.arguments {
		types[index] = starlarkStringDict(map[string]starlark.Value{"script_type": starlark.MakeInt(int(typ.scriptType)), "concrete_type": starlark.MakeInt(int(typ.concreteType))})
	}
	modeled, modeledResult := s.evaluateProfileExternal(prototype.name, action.operands, values, state, evaluation.profiles)
	entryName := ""
	if evaluation.currentEntry >= 0 && evaluation.currentEntry < len(s.prototypes) {
		entryName = s.prototypes[evaluation.currentEntry].name
	}
	callValues := map[string]starlark.Value{"entry_id": starlark.MakeInt(evaluation.currentEntry), "entry_function": starlark.String(entryName), "caller": starlark.String(s.prototypes[caller].name), "callee": starlark.String(prototype.name), "dll": starlark.String(prototype.dll), "offset": starlark.MakeUint64(uint64(action.offset)), "arguments": starlark.NewList(display), "argument_types": starlark.NewList(types), "resolved": starlark.Bool(allKnown), "conditional": starlark.Bool(state.conditional), "modeled": starlark.Bool(modeled)}
	if modeledResult.known {
		callValues["result"] = installScriptEvaluatedValue(modeledResult)
	}
	call := starlarkStringDict(callValues)
	callKey := fmt.Sprintf("%d:%d:%d:%t:%v", evaluation.currentEntry, caller, action.offset, state.conditional, display)
	if !evaluation.callSeen[callKey] {
		evaluation.callSeen[callKey] = true
		evaluation.calls = append(evaluation.calls, call)
	}
	operation, registryCall := installScriptRegistryAPIs[strings.ToLower(prototype.name)]
	if !registryCall {
		return
	}
	// InstallShield runtime calls carry LAST_RESULT first, followed by the
	// documented API parameters: root, key, value name, type/data/size.
	root, key, name, data := installScriptValue{}, installScriptValue{}, installScriptValue{}, installScriptValue{}
	if len(values) > 1 {
		root = values[1]
	}
	if len(values) > 2 {
		key = values[2]
	}
	if len(values) > 3 {
		name = values[3]
	}
	if len(values) > 5 {
		data = values[5]
	}
	resolved := root.known && key.known
	entry := map[string]starlark.Value{"entry_id": starlark.MakeInt(evaluation.currentEntry), "entry_function": starlark.String(entryName), "operation": starlark.String(operation), "caller": starlark.String(s.prototypes[caller].name), "callee": starlark.String(prototype.name), "offset": starlark.MakeUint64(uint64(action.offset)), "conditional": starlark.Bool(state.conditional), "resolved": starlark.Bool(resolved), "root": starlark.String("unknown")}
	if root.known {
		entry["root"] = starlark.String(installScriptRegistryRoot(root.num))
		entry["root_value"] = starlark.MakeInt64(int64(root.num))
	}
	if key.known {
		entry["key"] = starlark.String(key.text)
	}
	if name.known {
		entry["name"] = starlark.String(name.text)
	}
	if data.known {
		entry["data"] = installScriptEvaluatedValue(data)
	}
	entry["mutation"] = starlark.Bool(operation != "query_value" && operation != "query_binary_value")
	entry["definitive"] = starlark.False
	registryKey := fmt.Sprintf("%d:%s:%v:%v:%v:%v:%t", evaluation.currentEntry, operation, entry["root"], entry["key"], entry["name"], entry["data"], state.conditional)
	if !evaluation.registrySeen[registryKey] {
		evaluation.registrySeen[registryKey] = true
		evaluation.registry = append(evaluation.registry, starlarkStringDict(entry))
	}
}

func (s *Script) evaluateProfileExternal(name string, operands []installScriptArgument, values []installScriptValue, state *installScriptEvalState, profiles installScriptProfiles) (bool, installScriptValue) {
	base := strings.ToLower(strings.TrimSuffix(name, "A"))
	if base == "getprivateprofileint" && len(values) >= 4 {
		result := values[2]
		if value, found := profiles.lookup(values[3], values[0], values[1]); found {
			if number, err := strconv.ParseInt(strings.TrimSpace(value), 0, 32); err == nil {
				result = installScriptValue{kind: 5, num: int32(number), known: true}
			}
		}
		result.kind = 5
		state.vars[installScriptVariable{kind: 8, address: 0}] = result
		return true, result
	}
	if base == "getprivateprofilestring" && len(values) >= 6 {
		result := values[2]
		if value, found := profiles.lookup(values[5], values[0], values[1]); found {
			result = installScriptValue{kind: 4, text: value, known: true}
		}
		if result.known {
			installScriptWrite(operands[3], result, state)
			state.vars[installScriptVariable{kind: 8, address: 0}] = installScriptValue{kind: 5, num: int32(len(result.text)), known: true}
		}
		return true, result
	}
	return false, installScriptValue{}
}

func (p installScriptProfiles) lookup(file, section, key installScriptValue) (string, bool) {
	if !file.known || !section.known || !key.known {
		return "", false
	}
	name := strings.ToLower(strings.ReplaceAll(file.text, "/", `\`))
	if index := strings.LastIndexByte(name, '\\'); index >= 0 {
		name = name[index+1:]
	}
	sections, found := p[name]
	if !found {
		return "", false
	}
	values, found := sections[strings.ToLower(section.text)]
	if !found {
		return "", false
	}
	value, found := values[strings.ToLower(key.text)]
	return value, found
}

func installScriptEvaluatedValue(value installScriptValue) starlark.Value {
	if !value.known || value.reference || value.object != "" {
		return starlark.None
	}
	if value.kind == 4 {
		return starlark.String(value.text)
	}
	return starlark.MakeInt64(int64(value.num))
}
