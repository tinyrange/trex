package installscript

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

// This decoder is a clean-room implementation derived from observing the
// legacy compiler's byte records through TinyRangeX's own binary REPL. It does
// not incorporate legacy decompiler source code.

type legacyInstallScript struct {
	codeOffset    uint32
	prototypeBase uint16
	predefined    []string
	instructions  []legacyInstallScriptInstruction
	blocks        []installScriptBlock
	strings       []string
}

type legacyInstallScriptInstruction struct {
	offset     uint32
	opcode     uint16
	functionID uint16
	operands   []installScriptArgument
}

type legacyInstallScriptPrototypeRecord struct {
	offset     uint64
	external   bool
	flags      uint16
	returnType uint16
	dll        string
	name       string
	arguments  []installScriptArgumentType
}

type legacyInstallScriptPrototypePath struct {
	end     uint64
	records []legacyInstallScriptPrototypeRecord
	padding int
}

type legacyInstallScriptLayout struct {
	prototypeBase uint16
	predefined    []string
	path          legacyInstallScriptPrototypePath
}

type legacyInstallScriptEvaluation struct {
	maximumSteps int
	maximumDepth int
	steps        int
	reached      map[int]bool
	writes       []starlark.Value
	writeSeen    map[string]bool
	calls        []starlark.Value
	callSeen     map[string]bool
}

func openLegacyInstallScript(file File, data []byte) (*Script, error) {
	if len(data) < 64 ||
		(!bytes.Contains(data[12:min(len(data), 512)], []byte("InstallSHIELD Software Coporation")) &&
			!bytes.Contains(data[12:min(len(data), 512)], []byte("InstallSHIELD Software Corporation"))) {
		return nil, fmt.Errorf("installscript: unsupported signature")
	}
	layout, ok := findLegacyInstallScriptLayout(data)
	if !ok {
		return nil, fmt.Errorf("installscript: legacy tables are invalid")
	}
	prototypeBase := layout.prototypeBase
	path := layout.path
	codeOffset := path.end

	prototypeCount := int(prototypeBase) + len(path.records)
	prototypes := make([]installScriptPrototype, prototypeCount)
	for index := range prototypes {
		prototypes[index] = installScriptPrototype{index: index, flags: 4, name: fmt.Sprintf("predefined_%d", index), blockIndex: 0xffff}
	}
	for index, record := range path.records {
		id := int(prototypeBase) + index
		prototype := &prototypes[id]
		prototype.returnType = byte(record.returnType)
		prototype.arguments = record.arguments
		if record.external {
			prototype.flags = 1
			prototype.dll = record.dll
			prototype.name = record.name
		}
	}

	legacy := &legacyInstallScript{codeOffset: uint32(codeOffset), prototypeBase: prototypeBase, predefined: layout.predefined}
	legacy.instructions, legacy.blocks = decodeLegacyInstallScriptInstructions(data, codeOffset, prototypes)
	legacy.strings = scanLegacyInstallScriptStrings(data, codeOffset)
	for index := range legacy.blocks {
		functionID := legacy.blocks[index].functionID
		if functionID <= 0 || functionID >= len(prototypes) || prototypes[functionID].flags&1 != 0 {
			continue
		}
		prototypes[functionID].flags = 2
		prototypes[functionID].blockIndex = uint16(index)
		prototypes[functionID].name = fmt.Sprintf("legacy_function_%d", functionID)
		if functionID == 1 {
			prototypes[functionID].name = "application"
		}
	}
	return &Script{
		file: file, data: data, prototypes: prototypes,
		blocks: legacy.blocks,
		format: "legacy-ins", legacy: legacy,
	}, nil
}

func scanLegacyInstallScriptStrings(data []byte, offset uint64) []string {
	seen := make(map[string]bool)
	values := make([]string, 0)
	for current := offset; current+3 <= uint64(len(data)); current++ {
		if data[current] != 0x61 {
			continue
		}
		size := uint64(binary.LittleEndian.Uint16(data[current+1:]))
		if size == 0 || size > 4096 || current+3+size > uint64(len(data)) {
			continue
		}
		raw := data[current+3 : current+3+size]
		printable := true
		for _, value := range raw {
			if value != '\t' && value != '\r' && value != '\n' && (value < 0x20 || value > 0x7e) {
				printable = false
				break
			}
		}
		text := string(raw)
		if printable && !seen[text] {
			seen[text] = true
			values = append(values, text)
		}
	}
	sort.SliceStable(values, func(i, j int) bool { return strings.ToLower(values[i]) < strings.ToLower(values[j]) })
	return values
}

func findLegacyInstallScriptLayout(data []byte) (legacyInstallScriptLayout, bool) {
	marker := []byte("InstallSHIELD Software")
	markerOffset := bytes.Index(data[12:min(len(data), 512)], marker)
	if markerOffset < 0 {
		return legacyInstallScriptLayout{}, false
	}
	start := uint64(12 + markerOffset + len(marker))
	limit := min(uint64(len(data)), start+4096)
	for offset := start; offset < limit; offset++ {
		if layout, ok := parseLegacyInstallScriptLayout(data, offset); ok {
			return layout, true
		}
	}
	return legacyInstallScriptLayout{}, false
}

func parseLegacyInstallScriptLayout(data []byte, offset uint64) (legacyInstallScriptLayout, bool) {
	r := installScriptReader{data: data, off: offset}
	predefinedCount, err := r.u16()
	if err != nil || predefinedCount == 0 || int(predefinedCount) > installScriptMaximumTableEntries {
		return legacyInstallScriptLayout{}, false
	}
	predefined := make([]string, predefinedCount)
	for index := 0; index < int(predefinedCount); index++ {
		identifier, err := r.u16()
		if err != nil || identifier != uint16(index) {
			return legacyInstallScriptLayout{}, false
		}
		name, err := legacyInstallScriptIdentifier(&r)
		if err != nil {
			return legacyInstallScriptLayout{}, false
		}
		predefined[index] = name
	}
	if _, err := r.u16(); err != nil { // highest allocated global slot
		return legacyInstallScriptLayout{}, false
	}
	namedGlobals, err := r.u16()
	if err != nil || int(namedGlobals) > installScriptMaximumTableEntries {
		return legacyInstallScriptLayout{}, false
	}
	for index := 0; index < int(namedGlobals); index++ {
		if _, err := r.u16(); err != nil {
			return legacyInstallScriptLayout{}, false
		}
		if _, err := legacyInstallScriptIdentifier(&r); err != nil {
			return legacyInstallScriptLayout{}, false
		}
	}
	if err := skipLegacyInstallScriptTypes(&r); err != nil {
		return legacyInstallScriptLayout{}, false
	}

	prototypeBase, err := r.u16()
	if err != nil {
		return legacyInstallScriptLayout{}, false
	}
	// The legacy compiler places five 16-bit table-control fields between the
	// first dynamically allocated function ID and its compact signature table.
	for index := 0; index < 5; index++ {
		if _, err := r.u16(); err != nil {
			return legacyInstallScriptLayout{}, false
		}
	}
	prototypeOffset := r.off
	prologue := bytes.Index(data[prototypeOffset:], []byte{0xb6, 0x00, 0x10, 0x00})
	if prologue < 0 {
		return legacyInstallScriptLayout{}, false
	}
	prototypeLimit := prototypeOffset + uint64(prologue)
	path := parseLegacyInstallScriptPrototypePath(data, prototypeOffset, prototypeLimit)
	if len(path.records) == 0 || path.end >= prototypeLimit {
		return legacyInstallScriptLayout{}, false
	}
	return legacyInstallScriptLayout{prototypeBase: prototypeBase, predefined: predefined, path: path}, true
}

// PredefinedVariables returns the compiler-defined scalar slots by name.
func (s *Script) PredefinedVariables() map[string]int {
	output := make(map[string]int)
	if s.legacy == nil {
		return output
	}
	for address, name := range s.legacy.predefined {
		output[strings.ToUpper(name)] = address
	}
	return output
}

func legacyInstallScriptString(r *installScriptReader) (string, error) {
	value, err := r.string()
	if err != nil {
		return "", err
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("string contains NUL")
	}
	return value, nil
}

func skipLegacyInstallScriptTypes(r *installScriptReader) error {
	count, err := r.u16()
	if err != nil || int(count) > installScriptMaximumTableEntries {
		return fmt.Errorf("installscript: legacy types: invalid count")
	}
	for index := 0; index < int(count); index++ {
		if _, err := r.u16(); err != nil {
			return fmt.Errorf("installscript: legacy type %d ID: %w", index, err)
		}
		if _, err := legacyInstallScriptString(r); err != nil {
			return fmt.Errorf("installscript: legacy type %d name: %w", index, err)
		}
		members, err := r.u16()
		if err != nil || int(members) > installScriptMaximumTableEntries {
			return fmt.Errorf("installscript: legacy type %d: invalid member count", index)
		}
		for member := 0; member < int(members); member++ {
			if _, err := r.u16(); err != nil {
				return fmt.Errorf("installscript: legacy type %d member %d type: %w", index, member, err)
			}
			if _, err := r.u16(); err != nil {
				return fmt.Errorf("installscript: legacy type %d member %d size: %w", index, member, err)
			}
			if _, err := legacyInstallScriptString(r); err != nil {
				return fmt.Errorf("installscript: legacy type %d member %d name: %w", index, member, err)
			}
		}
	}
	return nil
}

func parseLegacyInstallScriptPrototypePath(data []byte, start, limit uint64) legacyInstallScriptPrototypePath {
	type node struct {
		previous uint64
		record   *legacyInstallScriptPrototypeRecord
		padding  int
		set      bool
	}
	nodes := make(map[uint64]node)
	nodes[start] = node{set: true}
	bestEnd := start
	for offset := start; offset <= limit; offset++ {
		current, found := nodes[offset]
		if !found || !current.set {
			continue
		}
		if offset > bestEnd {
			bestEnd = offset
		}
		consider := func(record *legacyInstallScriptPrototypeRecord, end uint64, padding int) {
			if end <= offset || end > limit {
				return
			}
			candidate := node{previous: offset, record: record, padding: current.padding + padding, set: true}
			if existing, ok := nodes[end]; !ok || !existing.set || candidate.padding < existing.padding {
				nodes[end] = candidate
			}
		}
		if record, end, ok := parseLegacyInstallScriptExternalPrototype(data, offset, limit); ok {
			recordCopy := record
			consider(&recordCopy, end, 0)
		}
		if record, end, ok := parseLegacyInstallScriptCommonPrototype(data, offset, limit); ok {
			recordCopy := record
			consider(&recordCopy, end, 0)
		}
		if offset+2 <= limit && binary.LittleEndian.Uint16(data[offset:]) == 0 {
			consider(nil, offset+2, 1)
		}
	}
	best := nodes[bestEnd]
	path := legacyInstallScriptPrototypePath{end: bestEnd, padding: best.padding}
	for offset := bestEnd; offset != start; {
		current := nodes[offset]
		if current.record != nil {
			path.records = append(path.records, *current.record)
		}
		offset = current.previous
	}
	for left, right := 0, len(path.records)-1; left < right; left, right = left+1, right-1 {
		path.records[left], path.records[right] = path.records[right], path.records[left]
	}
	return path
}

func parseLegacyInstallScriptCommonPrototype(data []byte, offset, limit uint64) (legacyInstallScriptPrototypeRecord, uint64, bool) {
	r := installScriptReader{data: data, off: offset}
	flags, err := r.u16()
	if err != nil || flags > 7 {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	count, err := r.u16()
	if err != nil || count > 64 {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	returnType, err := r.u16()
	if err != nil || returnType > 7 {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	arguments := make([]installScriptArgumentType, count)
	for index := range arguments {
		scriptType, err := r.u16()
		if err != nil || scriptType > 7 {
			return legacyInstallScriptPrototypeRecord{}, offset, false
		}
		concreteType, err := r.u16()
		if err != nil || concreteType > 7 {
			return legacyInstallScriptPrototypeRecord{}, offset, false
		}
		arguments[index] = installScriptArgumentType{scriptType: byte(scriptType), concreteType: byte(concreteType)}
	}
	if r.off > limit {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	return legacyInstallScriptPrototypeRecord{offset: offset, flags: flags, returnType: returnType, arguments: arguments}, r.off, true
}

func parseLegacyInstallScriptExternalPrototype(data []byte, offset, limit uint64) (legacyInstallScriptPrototypeRecord, uint64, bool) {
	if record, end, ok := parseLegacyInstallScriptExternalPrototypeRecord(data, offset, limit, true); ok {
		return record, end, true
	}
	return parseLegacyInstallScriptExternalPrototypeRecord(data, offset, limit, false)
}

func parseLegacyInstallScriptExternalPrototypeRecord(data []byte, offset, limit uint64, leadingMarker bool) (legacyInstallScriptPrototypeRecord, uint64, bool) {
	r := installScriptReader{data: data, off: offset}
	if leadingMarker {
		marker, err := r.u16()
		if err != nil || marker != 1 {
			return legacyInstallScriptPrototypeRecord{}, offset, false
		}
	}
	callingConvention, err := r.u16()
	if err != nil || callingConvention > 7 {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	dll, err := legacyInstallScriptIdentifier(&r)
	if err != nil {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	name, err := legacyInstallScriptIdentifier(&r)
	if err != nil {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	count, err := r.u16()
	if err != nil || count > 64 {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	returnType, err := r.u16()
	if err != nil || returnType > 7 {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	arguments := make([]installScriptArgumentType, count)
	for index := range arguments {
		scriptType, err := r.u16()
		if err != nil || scriptType > 7 {
			return legacyInstallScriptPrototypeRecord{}, offset, false
		}
		concreteType, err := r.u16()
		if err != nil || concreteType > 7 {
			return legacyInstallScriptPrototypeRecord{}, offset, false
		}
		arguments[index] = installScriptArgumentType{scriptType: byte(scriptType), concreteType: byte(concreteType)}
	}
	if r.off > limit {
		return legacyInstallScriptPrototypeRecord{}, offset, false
	}
	return legacyInstallScriptPrototypeRecord{offset: offset, external: true, flags: callingConvention, returnType: returnType, dll: dll, name: name, arguments: arguments}, r.off, true
}

func legacyInstallScriptIdentifier(r *installScriptReader) (string, error) {
	value, err := legacyInstallScriptString(r)
	if err != nil || len(value) == 0 || len(value) > 128 {
		return "", fmt.Errorf("invalid identifier")
	}
	for _, ch := range []byte(value) {
		if ch < 0x20 || ch > 0x7e {
			return "", fmt.Errorf("invalid identifier")
		}
	}
	return value, nil
}

func decodeLegacyInstallScriptInstructions(data []byte, offset uint64, prototypes []installScriptPrototype) ([]legacyInstallScriptInstruction, []installScriptBlock) {
	prologues := make([]uint64, 0)
	for current := offset; current+4 <= uint64(len(data)); current++ {
		if bytes.Equal(data[current:current+4], []byte{0xb6, 0x00, 0x10, 0x00}) {
			prologues = append(prologues, current)
		}
	}
	output := make([]legacyInstallScriptInstruction, 0)
	blocks := make([]installScriptBlock, len(prologues))
	for index, start := range prologues {
		end := uint64(len(data))
		if index+1 < len(prologues) {
			end = prologues[index+1]
		}
		functionID := index + 1
		actions := make([]installScriptAction, 0)
		for current := start; current+6 <= end; current++ {
			if data[current] != 0x22 || data[current+1] != 0x00 || data[current+2] != 0x70 || data[current+5] != 0x95 {
				continue
			}
			callee := binary.LittleEndian.Uint16(data[current+3:])
			opcode := uint16(0)
			operands := []installScriptArgument(nil)
			if int(callee) < len(prototypes) && prototypes[callee].flags&1 != 0 {
				opcode = 32
				operands = decodeLegacyInstallScriptCallOperands(data, start, current, len(prototypes[callee].arguments))
			} else if callee > 0 && int(callee) <= len(prologues) {
				opcode = 33
			}
			if opcode == 0 {
				continue
			}
			instruction := legacyInstallScriptInstruction{offset: uint32(current), opcode: opcode, functionID: callee, operands: operands}
			output = append(output, instruction)
			actions = append(actions, installScriptAction{offset: instruction.offset, opcode: opcode, functionID: callee, operands: operands})
		}
		blocks[index] = installScriptBlock{index: index, offset: uint32(start), functionID: functionID, actions: actions}
	}
	return output, blocks
}

func decodeLegacyInstallScriptCallOperands(data []byte, codeOffset, callOffset uint64, count int) []installScriptArgument {
	if count == 0 {
		return nil
	}
	start := callOffset
	if start > codeOffset+512 {
		start -= 512
	} else {
		start = codeOffset
	}
	var best []installScriptArgument
	for candidate := start; candidate < callOffset; candidate++ {
		r := installScriptReader{data: data, off: candidate}
		arguments := make([]installScriptArgument, count)
		valid := true
		for index := range arguments {
			argument, err := parseLegacyInstallScriptValue(&r)
			if err != nil {
				valid = false
				break
			}
			arguments[index] = argument
		}
		if valid && r.off == callOffset {
			best = arguments
		}
	}
	return best
}

func parseLegacyInstallScriptValue(r *installScriptReader) (installScriptArgument, error) {
	opcode, err := r.u8()
	if err != nil {
		return installScriptArgument{}, err
	}
	switch opcode {
	case 0x41:
		value, err := r.i32()
		return installScriptArgument{kind: 7, number: value}, err
	case 0x42:
		value, err := r.i16()
		return installScriptArgument{kind: 5, address: value}, err
	case 0x61:
		value, err := r.string()
		return installScriptArgument{kind: 6, text: value}, err
	case 0x62:
		value, err := r.i16()
		return installScriptArgument{kind: 4, address: value}, err
	default:
		return installScriptArgument{}, fmt.Errorf("unsupported legacy value opcode %#x", opcode)
	}
}

func (l *legacyInstallScript) instructionsValue() *starlark.List {
	values := make([]starlark.Value, len(l.instructions))
	for index, instruction := range l.instructions {
		operands := make([]starlark.Value, len(instruction.operands))
		for operand := range instruction.operands {
			operands[operand] = installScriptArgumentValue(instruction.operands[operand])
		}
		values[index] = starlarkStringDict(map[string]starlark.Value{
			"offset": starlark.MakeUint64(uint64(instruction.offset)), "opcode": starlark.MakeInt(int(instruction.opcode)),
			"name": starlark.String(installScriptOpcodeName(instruction.opcode)), "function_id": starlark.MakeInt(int(instruction.functionID)),
			"operands": starlark.NewList(operands),
		})
	}
	return starlark.NewList(values)
}

func (s *Script) evaluateLegacyInstallScript(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	entry := "application"
	maximumSteps, maximumDepth := 200000, 64
	stringsValue, numbersValue, profilesValue := starlark.Value(starlark.None), starlark.Value(starlark.None), starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("installscript.evaluate", args, kwargs,
		"entry?", &entry, "strings?", &stringsValue, "numbers?", &numbersValue,
		"profiles?", &profilesValue, "maximum_steps?", &maximumSteps, "maximum_depth?", &maximumDepth); err != nil {
		return nil, err
	}
	if !strings.EqualFold(entry, "application") {
		return nil, fmt.Errorf("installscript.evaluate: legacy entry function %q not found", entry)
	}
	if maximumSteps < 1 || maximumSteps > 10000000 || maximumDepth < 1 || maximumDepth > 1024 {
		return nil, fmt.Errorf("installscript.evaluate: invalid evaluation bound")
	}
	seed := installScriptEvalState{vars: make(map[installScriptVariable]installScriptValue)}
	if err := installScriptSeedValues("strings", stringsValue, 4, seed.vars); err != nil {
		return nil, err
	}
	if err := installScriptSeedValues("numbers", numbersValue, 5, seed.vars); err != nil {
		return nil, err
	}
	if _, err := installScriptProfileValues(profilesValue); err != nil {
		return nil, err
	}
	evaluation := &legacyInstallScriptEvaluation{
		maximumSteps: maximumSteps, maximumDepth: maximumDepth,
		reached: make(map[int]bool), writeSeen: make(map[string]bool), callSeen: make(map[string]bool),
	}
	entryIDs := s.installScriptCallbackEntries()
	entries := make([]starlark.Value, 0, len(entryIDs))
	for _, entryID := range entryIDs {
		state := cloneInstallScriptState(seed)
		root := installScriptValue{}
		entryReached := make(map[int]bool)
		s.evaluateLegacyFunction(entryID, entryID, &state, &root, evaluation, entryReached, make(map[int]bool), 0)
		entries = append(entries, starlarkStringDict(map[string]starlark.Value{
			"id": starlark.MakeInt(entryID), "function": starlark.String(s.prototypes[entryID].name),
			"reached_functions": legacyInstallScriptReachedFunctions(s, entryReached),
		}))
		if evaluation.steps >= maximumSteps {
			break
		}
	}
	registryWrites, _ := legacyInstallScriptClassifyRegistryWrites(evaluation.writes)
	definitiveRegistryWrites := []starlark.Value(nil)
	incomplete := true
	reasons := make([]starlark.Value, 0, 1)
	if evaluation.steps >= maximumSteps {
		reasons = append(reasons, starlark.String("legacy evaluation step limit reached"))
	} else {
		// The callback call graph is now reconstructed, but legacy conditional
		// branches are not. Keep the resolved mutations visible to analysis
		// without applying one side of an unproved branch during construction.
		reasons = append(reasons, starlark.String("legacy callback control flow is not decoded"))
	}
	return starlarkStringDict(map[string]starlark.Value{
		"entry": starlark.String("application"), "registry": starlark.NewList(registryWrites),
		"registry_writes": starlark.NewList(registryWrites), "definitive_registry_writes": starlark.NewList(definitiveRegistryWrites),
		"calls": starlark.NewList(evaluation.calls), "reached_functions": legacyInstallScriptReachedFunctions(s, evaluation.reached),
		"entries": starlark.NewList(entries), "final_globals": starlark.NewList(nil), "steps": starlark.MakeInt(evaluation.steps),
		"incomplete": starlark.Bool(incomplete), "incomplete_reasons": starlark.NewList(reasons),
	}), nil
}

func (s *Script) evaluateLegacyFunction(entryID, functionID int, state *installScriptEvalState, root *installScriptValue, evaluation *legacyInstallScriptEvaluation, entryReached, active map[int]bool, depth int) {
	if functionID <= 0 || functionID >= len(s.prototypes) || depth >= evaluation.maximumDepth || active[functionID] || evaluation.steps >= evaluation.maximumSteps {
		return
	}
	blockIndex := int(s.prototypes[functionID].blockIndex)
	if blockIndex < 0 || blockIndex >= len(s.legacy.blocks) {
		return
	}
	block := s.legacy.blocks[blockIndex]
	evaluation.reached[functionID], entryReached[functionID] = true, true
	active[functionID] = true
	defer delete(active, functionID)

	cursor := uint64(block.offset)
	end := uint64(len(s.data))
	if block.index+1 < len(s.legacy.blocks) {
		end = uint64(s.legacy.blocks[block.index+1].offset)
	}
	advanceStatements := func(limit uint64) {
		for cursor < limit && evaluation.steps < evaluation.maximumSteps {
			next, handled := s.evaluateLegacyStatement(cursor, limit, state, root, entryID, functionID, &evaluation.writes, evaluation.writeSeen)
			evaluation.steps++
			if handled {
				cursor = next
			} else {
				cursor++
			}
		}
	}
	for _, action := range block.actions {
		advanceStatements(uint64(action.offset))
		if evaluation.steps >= evaluation.maximumSteps {
			return
		}
		evaluation.steps++
		switch action.opcode {
		case 32:
			s.evaluateLegacyExternal(entryID, functionID, action, *state, evaluation)
		case 33:
			calleeState := cloneInstallScriptState(*state)
			calleeRoot := *root
			s.evaluateLegacyFunction(entryID, int(action.functionID), &calleeState, &calleeRoot, evaluation, entryReached, active, depth+1)
			for variable, value := range calleeState.vars {
				if variable.address >= 0 {
					state.vars[variable] = value
				}
			}
			*root = calleeRoot
		}
		cursor = min(uint64(action.offset)+6, end)
	}
	advanceStatements(end)
}

func (s *Script) evaluateLegacyExternal(entryID, callerID int, action installScriptAction, state installScriptEvalState, evaluation *legacyInstallScriptEvaluation) {
	if int(action.functionID) >= len(s.prototypes) {
		return
	}
	prototype := s.prototypes[action.functionID]
	arguments := make([]starlark.Value, len(action.operands))
	resolved := len(action.operands) == len(prototype.arguments)
	for index, operand := range action.operands {
		value := installScriptRead(operand, state)
		arguments[index] = installScriptEvaluatedValue(value)
		resolved = resolved && value.known
	}
	types := make([]starlark.Value, len(prototype.arguments))
	for index, typ := range prototype.arguments {
		types[index] = starlarkStringDict(map[string]starlark.Value{
			"script_type": starlark.MakeInt(int(typ.scriptType)), "concrete_type": starlark.MakeInt(int(typ.concreteType)),
		})
	}
	key := fmt.Sprintf("%d:%d:%d:%v", entryID, callerID, action.offset, arguments)
	if evaluation.callSeen[key] {
		return
	}
	evaluation.callSeen[key] = true
	evaluation.calls = append(evaluation.calls, starlarkStringDict(map[string]starlark.Value{
		"entry_id": starlark.MakeInt(entryID), "entry_function": starlark.String(s.prototypes[entryID].name),
		"caller": starlark.String(s.prototypes[callerID].name), "callee": starlark.String(prototype.name),
		"dll": starlark.String(prototype.dll), "offset": starlark.MakeUint64(uint64(action.offset)),
		"arguments": starlark.NewList(arguments), "argument_types": starlark.NewList(types),
		"resolved": starlark.Bool(resolved), "conditional": starlark.True, "modeled": starlark.False,
		"construction_safe": starlark.False,
	}))
}

func (s *Script) evaluateLegacyStatement(offset, end uint64, state *installScriptEvalState, root *installScriptValue, entryID, functionID int, writes *[]starlark.Value, seen map[string]bool) (uint64, bool) {
	if offset+2 > end {
		return offset, false
	}
	opcode := binary.LittleEndian.Uint16(s.data[offset:])
	r := installScriptReader{data: s.data, off: offset + 2}
	switch opcode {
	case 0x0013, 0x0021: // string and numeric assignment
		destination, ok := parseLegacyInstallScriptLValue(&r)
		if !ok {
			return offset, false
		}
		source, err := parseLegacyInstallScriptValue(&r)
		if err != nil || r.off > end {
			return offset, false
		}
		installScriptWrite(destination, installScriptRead(source, *state), state)
		return r.off, true
	case 0x0124, 0x0125: // string concatenation and Windows path concatenation
		destination, ok := parseLegacyInstallScriptLValue(&r)
		if !ok || destination.kind != 4 {
			return offset, false
		}
		left, leftErr := parseLegacyInstallScriptValue(&r)
		right, rightErr := parseLegacyInstallScriptValue(&r)
		if leftErr != nil || rightErr != nil || r.off > end {
			return offset, false
		}
		leftValue, rightValue := installScriptRead(left, *state), installScriptRead(right, *state)
		value := installScriptValue{kind: 4}
		if leftValue.known && rightValue.known {
			value.known = true
			if opcode == 0x0125 {
				value.text = legacyInstallScriptJoinPath(leftValue.text, rightValue.text)
			} else {
				value.text = leftValue.text + rightValue.text
			}
		}
		installScriptWrite(destination, value, state)
		return r.off, true
	case 0x0110: // RegDBSetDefaultRoot
		argument, err := parseLegacyInstallScriptValue(&r)
		if err != nil || r.off > end {
			return offset, false
		}
		*root = installScriptRead(argument, *state)
		return r.off, true
	case 0x0151: // RegDBSetKeyValueEx
		arguments := make([]installScriptValue, 5)
		for index := range arguments {
			argument, err := parseLegacyInstallScriptValue(&r)
			if err != nil {
				return offset, false
			}
			arguments[index] = installScriptRead(argument, *state)
		}
		if r.off > end {
			return offset, false
		}
		resolved := root.known && arguments[0].known && arguments[1].known && arguments[3].known
		entryRoot := "unknown"
		if root.known {
			entryRoot = installScriptRegistryRoot(root.num)
		}
		key := fmt.Sprintf("%d:%d:%d:%s:%s:%s:%s", entryID, functionID, offset, entryRoot, arguments[0].text, arguments[1].text, arguments[3].text)
		if resolved && strings.HasPrefix(entryRoot, "HKEY_") && !seen[key] {
			seen[key] = true
			entry := map[string]starlark.Value{
				"entry_id": starlark.MakeInt(entryID), "entry_function": starlark.String(s.prototypes[entryID].name),
				"operation": starlark.String("set_value"), "caller": starlark.String(s.prototypes[functionID].name),
				"callee": starlark.String("RegDBSetKeyValueEx"), "offset": starlark.MakeUint64(offset),
				"conditional": starlark.False, "resolved": starlark.True, "root": starlark.String(entryRoot),
				"root_value": starlark.MakeInt64(int64(root.num)), "key": starlark.String(arguments[0].text),
				"name": starlark.String(arguments[1].text), "data": installScriptEvaluatedValue(arguments[3]),
				"mutation": starlark.True, "definitive": starlark.True,
			}
			*writes = append(*writes, starlarkStringDict(entry))
		}
		return r.off, true
	}
	return offset, false
}

func legacyInstallScriptClassifyRegistryWrites(input []starlark.Value) ([]starlark.Value, []starlark.Value) {
	values := make(map[string]map[string]bool)
	identities := make([]string, len(input))
	for index, value := range input {
		entry := value.(*starlark.Dict)
		operation, _, _ := entry.Get(starlark.String("operation"))
		root, _, _ := entry.Get(starlark.String("root"))
		key, _, _ := entry.Get(starlark.String("key"))
		name, _, _ := entry.Get(starlark.String("name"))
		data, _, _ := entry.Get(starlark.String("data"))
		identity := fmt.Sprintf("%s:%s:%s:%s", operation, root, key, name)
		identities[index] = strings.ToLower(identity)
		if values[identities[index]] == nil {
			values[identities[index]] = make(map[string]bool)
		}
		values[identities[index]][fmt.Sprint(data)] = true
	}
	all := make([]starlark.Value, 0, len(input))
	definitive := make([]starlark.Value, 0, len(input))
	definitiveSeen := make(map[string]bool)
	for index, value := range input {
		entry := value.(*starlark.Dict)
		proved := len(values[identities[index]]) == 1
		_ = entry.SetKey(starlark.String("conditional"), starlark.Bool(!proved))
		_ = entry.SetKey(starlark.String("definitive"), starlark.Bool(proved))
		all = append(all, entry)
		if proved && !definitiveSeen[identities[index]] {
			definitiveSeen[identities[index]] = true
			definitive = append(definitive, entry)
		}
	}
	return all, definitive
}

func parseLegacyInstallScriptLValue(r *installScriptReader) (installScriptArgument, bool) {
	opcode, err := r.u8()
	if err != nil || (opcode != 0x32 && opcode != 0x52) {
		return installScriptArgument{}, false
	}
	address, err := r.i16()
	if err != nil {
		return installScriptArgument{}, false
	}
	kind := byte(5)
	if opcode == 0x52 {
		kind = 4
	}
	return installScriptArgument{kind: kind, address: address}, true
}

func legacyInstallScriptJoinPath(left, right string) string {
	left = strings.TrimRight(left, `\\/`)
	right = strings.TrimLeft(right, `\\/`)
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	return left + `\` + right
}

func legacyInstallScriptReachedFunctions(s *Script, reached map[int]bool) *starlark.List {
	values := make([]starlark.Value, 0, len(reached))
	for functionID := 1; functionID < len(s.prototypes); functionID++ {
		if reached[functionID] {
			values = append(values, starlark.String(s.prototypes[functionID].name))
		}
	}
	return starlark.NewList(values)
}
