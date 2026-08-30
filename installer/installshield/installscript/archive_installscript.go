package installscript

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

// The aLuZ format interpretation is independently implemented from the binary
// layout documented by the MIT-licensed installscript-decompiler project:
// https://github.com/jte/installscript-decompiler

const (
	installScriptSignature           = uint32(0x5a754c61)
	installScriptHeaderSize          = 124
	installScriptMaximumSize         = int64(64 << 20)
	installScriptMaximumTableEntries = 1 << 20
)

type installScriptArgument struct {
	kind    byte
	address int16
	number  int32
	text    string
}

func (a installScriptArgument) String() string {
	switch a.kind {
	case 4:
		return fmt.Sprintf("string[%d]", a.address)
	case 5:
		return fmt.Sprintf("number[%d]", a.address)
	case 6:
		return fmt.Sprintf("%q", a.text)
	case 7:
		return fmt.Sprintf("%d", a.number)
	case 8:
		return fmt.Sprintf("variant[%d]", a.address)
	default:
		return "<?>"
	}
}

type installScriptPrototype struct {
	index      int
	flags      byte
	returnType byte
	name       string
	dll        string
	blockIndex uint16
	arguments  []installScriptArgumentType
}

type installScriptArgumentType struct {
	scriptType   byte
	concreteType byte
}

type installScriptDeclarations struct {
	numbers uint16
	objects uint16
	strings uint16
}

type installScriptAction struct {
	offset     uint32
	opcode     uint16
	functionID uint16
	operands   []installScriptArgument
	target     int32
}

type installScriptBlock struct {
	index      int
	offset     uint32
	functionID int
	actions    []installScriptAction
}

type Script struct {
	file       File
	data       []byte
	prototypes []installScriptPrototype
	blocks     []installScriptBlock
	globalDecl installScriptDeclarations
	format     string
	legacy     *legacyInstallScript
}

type installScriptReader struct {
	data []byte
	off  uint64
}

func (r *installScriptReader) remaining() uint64 {
	if r.off >= uint64(len(r.data)) {
		return 0
	}
	return uint64(len(r.data)) - r.off
}
func (r *installScriptReader) u8() (byte, error) {
	if r.remaining() < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	value := r.data[r.off]
	r.off++
	return value, nil
}
func (r *installScriptReader) u16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.LittleEndian.Uint16(r.data[r.off:])
	r.off += 2
	return value, nil
}
func (r *installScriptReader) i16() (int16, error) { value, err := r.u16(); return int16(value), err }
func (r *installScriptReader) u32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.LittleEndian.Uint32(r.data[r.off:])
	r.off += 4
	return value, nil
}
func (r *installScriptReader) i32() (int32, error) { value, err := r.u32(); return int32(value), err }
func (r *installScriptReader) string() (string, error) {
	size, err := r.u16()
	if err != nil {
		return "", err
	}
	if uint64(size) > r.remaining() {
		return "", io.ErrUnexpectedEOF
	}
	value := string(r.data[r.off : r.off+uint64(size)])
	r.off += uint64(size)
	return value, nil
}

// Builtin implements the archive.installscript Starlark constructor.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("installscript", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(File)
	if !ok {
		return nil, fmt.Errorf("installscript: file is %s, want file", value.Type())
	}
	return Open(file)
}

func Open(file File) (*Script, error) {
	if file.Size() < installScriptHeaderSize || file.Size() > installScriptMaximumSize {
		return nil, fmt.Errorf("installscript: invalid file size %d", file.Size())
	}
	data := make([]byte, int(file.Size()))
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, file.Size()), data); err != nil {
		return nil, fmt.Errorf("installscript: read: %w", err)
	}
	if binary.LittleEndian.Uint32(data[:4]) != installScriptSignature {
		return openLegacyInstallScript(file, data)
	}
	variablesOffset := binary.LittleEndian.Uint32(data[104:108])
	prototypesOffset := binary.LittleEndian.Uint32(data[108:112])
	typesOffset := binary.LittleEndian.Uint32(data[112:116])
	blocksOffset := binary.LittleEndian.Uint32(data[116:120])
	for name, offset := range map[string]uint32{"variables": variablesOffset, "prototypes": prototypesOffset, "types": typesOffset, "blocks": blocksOffset} {
		if uint64(offset) >= uint64(len(data)) {
			return nil, fmt.Errorf("installscript: %s table offset %#x is out of bounds", name, offset)
		}
	}
	if err := skipInstallScriptTypes(data, uint64(typesOffset)); err != nil {
		return nil, err
	}
	globalDecl, _, err := parseInstallScriptDeclarations(data, uint64(variablesOffset))
	if err != nil {
		return nil, fmt.Errorf("installscript: global declarations: %w", err)
	}
	prototypes, err := parseInstallScriptPrototypes(data, uint64(prototypesOffset))
	if err != nil {
		return nil, err
	}
	blocks, err := parseInstallScriptBlocks(data, uint64(blocksOffset), prototypes)
	if err != nil {
		return nil, err
	}
	return &Script{file: file, data: data, prototypes: prototypes, blocks: blocks, globalDecl: globalDecl, format: "aluz"}, nil
}

func skipInstallScriptTypes(data []byte, offset uint64) error {
	r := installScriptReader{data: data, off: offset}
	count, err := r.u16()
	if err != nil {
		return fmt.Errorf("installscript: types: %w", err)
	}
	if int(count) > installScriptMaximumTableEntries {
		return fmt.Errorf("installscript: too many types")
	}
	for index := 0; index < int(count); index++ {
		members, err := r.u16()
		if err != nil {
			return fmt.Errorf("installscript: type %d: %w", index, err)
		}
		for member := 0; member < int(members); member++ {
			if _, err := r.u8(); err != nil {
				return fmt.Errorf("installscript: type %d member %d: %w", index, member, err)
			}
			if _, err := r.u16(); err != nil {
				return fmt.Errorf("installscript: type %d member %d: %w", index, member, err)
			}
			if _, err := r.string(); err != nil {
				return fmt.Errorf("installscript: type %d member %d: %w", index, member, err)
			}
		}
	}
	return nil
}

func parseInstallScriptDeclarations(data []byte, offset uint64) (installScriptDeclarations, uint64, error) {
	r := installScriptReader{data: data, off: offset}
	numbers, err := r.u16()
	if err != nil {
		return installScriptDeclarations{}, offset, err
	}
	objects, err := r.u16()
	if err != nil {
		return installScriptDeclarations{}, offset, err
	}
	for index := 0; index < int(objects); index++ {
		if _, err := r.u16(); err != nil {
			return installScriptDeclarations{}, offset, err
		}
		if _, err := r.u16(); err != nil {
			return installScriptDeclarations{}, offset, err
		}
	}
	stringsCount, err := r.u16()
	if err != nil {
		return installScriptDeclarations{}, offset, err
	}
	stringRecords, err := r.u16()
	if err != nil {
		return installScriptDeclarations{}, offset, err
	}
	for index := 0; index < int(stringRecords); index++ {
		if _, err := r.u16(); err != nil {
			return installScriptDeclarations{}, offset, err
		}
		if _, err := r.u16(); err != nil {
			return installScriptDeclarations{}, offset, err
		}
	}
	return installScriptDeclarations{numbers: numbers, objects: objects, strings: stringsCount}, r.off, nil
}

func parseInstallScriptPrototypes(data []byte, offset uint64) ([]installScriptPrototype, error) {
	r := installScriptReader{data: data, off: offset}
	count, err := r.u16()
	if err != nil {
		return nil, fmt.Errorf("installscript: prototypes: %w", err)
	}
	prototypes := make([]installScriptPrototype, count)
	for index := range prototypes {
		flags, err := r.u8()
		if err != nil {
			return nil, fmt.Errorf("installscript: prototype %d: %w", index, err)
		}
		prototype := installScriptPrototype{index: index, flags: flags, blockIndex: 0xffff}
		if flags&4 != 0 {
			prototype.name = fmt.Sprintf("predefined_%d", index)
			prototypes[index] = prototype
			continue
		}
		prototype.returnType, err = r.u8()
		if err != nil {
			return nil, fmt.Errorf("installscript: prototype %d return type: %w", index, err)
		}
		if flags&1 != 0 {
			prototype.dll, err = r.string()
			if err != nil {
				return nil, fmt.Errorf("installscript: prototype %d DLL: %w", index, err)
			}
			prototype.name, err = r.string()
			if err != nil {
				return nil, fmt.Errorf("installscript: prototype %d name: %w", index, err)
			}
		} else if flags&2 != 0 {
			if _, err := r.u16(); err != nil {
				return nil, fmt.Errorf("installscript: prototype %d alignment: %w", index, err)
			}
			prototype.name, err = r.string()
			if err != nil {
				return nil, fmt.Errorf("installscript: prototype %d name: %w", index, err)
			}
		} else {
			return nil, fmt.Errorf("installscript: prototype %d has unsupported flags %#x", index, flags)
		}
		prototype.blockIndex, err = r.u16()
		if err != nil {
			return nil, fmt.Errorf("installscript: prototype %d block: %w", index, err)
		}
		argumentCount, err := r.u16()
		if err != nil {
			return nil, fmt.Errorf("installscript: prototype %d arguments: %w", index, err)
		}
		prototype.arguments = make([]installScriptArgumentType, argumentCount)
		for argument := range prototype.arguments {
			prototype.arguments[argument].scriptType, err = r.u8()
			if err != nil {
				return nil, fmt.Errorf("installscript: prototype %d argument %d: %w", index, argument, err)
			}
			prototype.arguments[argument].concreteType, err = r.u8()
			if err != nil {
				return nil, fmt.Errorf("installscript: prototype %d argument %d: %w", index, argument, err)
			}
		}
		if prototype.name == "" {
			prototype.name = fmt.Sprintf("function_%d", prototype.blockIndex)
		}
		prototypes[index] = prototype
	}
	return prototypes, nil
}

func parseInstallScriptBlocks(data []byte, offset uint64, prototypes []installScriptPrototype) ([]installScriptBlock, error) {
	r := installScriptReader{data: data, off: offset}
	count, err := r.u16()
	if err != nil {
		return nil, fmt.Errorf("installscript: blocks: %w", err)
	}
	blockOffsets := make([]uint32, count)
	for index := range blockOffsets {
		blockOffsets[index], err = r.u32()
		if err != nil {
			return nil, fmt.Errorf("installscript: block offset %d: %w", index, err)
		}
		if uint64(blockOffsets[index]) >= uint64(len(data)) {
			return nil, fmt.Errorf("installscript: block %d offset %#x is out of bounds", index, blockOffsets[index])
		}
	}
	prototypeByBlock := make(map[int]int)
	for index, prototype := range prototypes {
		if prototype.flags&2 != 0 && prototype.blockIndex != 0xffff {
			prototypeByBlock[int(prototype.blockIndex)] = index
		}
	}
	blocks := make([]installScriptBlock, count)
	currentFunction := -1
	for index, offset := range blockOffsets {
		br := installScriptReader{data: data, off: uint64(offset)}
		actionCount, err := br.u16()
		if err != nil {
			return nil, fmt.Errorf("installscript: block %d: %w", index, err)
		}
		if int(actionCount) > installScriptMaximumTableEntries {
			return nil, fmt.Errorf("installscript: block %d has too many actions", index)
		}
		block := installScriptBlock{index: index, offset: offset, functionID: currentFunction, actions: make([]installScriptAction, 0, actionCount)}
		for actionIndex := 0; actionIndex < int(actionCount); actionIndex++ {
			action, declarations, err := parseInstallScriptAction(data, &br)
			if err != nil {
				return nil, fmt.Errorf("installscript: block %d action %d at %#x: %w", index, actionIndex, br.off, err)
			}
			if action.opcode == 34 {
				functionID, ok := prototypeByBlock[index]
				if !ok {
					return nil, fmt.Errorf("installscript: function prologue in block %d has no prototype", index)
				}
				_ = declarations
				currentFunction = functionID
				block.functionID = functionID
				continue
			}
			block.actions = append(block.actions, action)
		}
		blocks[index] = block
	}
	return blocks, nil
}

func parseInstallScriptAction(data []byte, r *installScriptReader) (installScriptAction, installScriptDeclarations, error) {
	start := r.off
	opcode, err := r.u16()
	if err != nil {
		return installScriptAction{}, installScriptDeclarations{}, err
	}
	action := installScriptAction{offset: uint32(start), opcode: opcode}
	if opcode == 32 || opcode == 33 {
		action.functionID, err = r.u16()
		if err != nil {
			return action, installScriptDeclarations{}, err
		}
		count, err := r.u16()
		if err != nil {
			return action, installScriptDeclarations{}, err
		}
		action.operands, err = parseInstallScriptArguments(r, count)
		return action, installScriptDeclarations{}, err
	}
	if opcode == 28 {
		if _, err := r.u16(); err != nil {
			return action, installScriptDeclarations{}, err
		}
		action.operands, err = parseInstallScriptArguments(r, 1)
		return action, installScriptDeclarations{}, err
	}
	count, err := r.u16()
	if err != nil {
		return action, installScriptDeclarations{}, err
	}
	if opcode == 34 {
		marker, err := r.u8()
		if err != nil {
			return action, installScriptDeclarations{}, err
		}
		if marker != 7 {
			return action, installScriptDeclarations{}, fmt.Errorf("invalid declaration marker %d", marker)
		}
		relativeBase := r.off
		relative, err := r.u32()
		if err != nil {
			return action, installScriptDeclarations{}, err
		}
		target := relativeBase + uint64(relative)
		decl, _, err := parseInstallScriptDeclarations(data, target)
		return action, decl, err
	}
	if opcode == 38 {
		decl, end, err := parseInstallScriptDeclarations(data, r.off)
		if err == nil {
			r.off = end
		}
		return action, decl, err
	}
	if opcode == 1 || opcode == 2 || opcode == 3 || opcode == 39 {
		if count != 0 {
			return action, installScriptDeclarations{}, fmt.Errorf("opcode %d has unexpected operand count %d", opcode, count)
		}
		return action, installScriptDeclarations{}, nil
	}
	action.operands, err = parseInstallScriptArguments(r, count)
	if err != nil {
		return action, installScriptDeclarations{}, err
	}
	if (opcode == 4 || opcode == 5) && len(action.operands) > 0 && action.operands[0].kind == 7 {
		action.target = action.operands[0].number
	}
	if opcode > 60 || opcode == 0 || opcode == 31 {
		return action, installScriptDeclarations{}, fmt.Errorf("unsupported opcode %d", opcode)
	}
	return action, installScriptDeclarations{}, nil
}

func parseInstallScriptArguments(r *installScriptReader, count uint16) ([]installScriptArgument, error) {
	arguments := make([]installScriptArgument, count)
	for index := range arguments {
		kind, err := r.u8()
		if err != nil {
			return nil, err
		}
		argument := installScriptArgument{kind: kind}
		switch kind {
		case 4, 5, 8:
			argument.address, err = r.i16()
		case 6:
			argument.text, err = r.string()
		case 7:
			argument.number, err = r.i32()
		default:
			return nil, fmt.Errorf("unsupported argument kind %d", kind)
		}
		if err != nil {
			return nil, err
		}
		arguments[index] = argument
	}
	return arguments, nil
}

func (s *Script) String() string {
	return fmt.Sprintf("<installscript functions=%d blocks=%d>", len(s.prototypes), len(s.blocks))
}
func (s *Script) Type() string          { return "installscript" }
func (s *Script) Freeze()               {}
func (s *Script) Truth() starlark.Bool  { return starlark.True }
func (s *Script) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", s.Type()) }
func (s *Script) Format() string        { return s.format }
func (s *Script) AttrNames() []string {
	return []string{"blocks", "callbacks", "calls", "effects", "evaluate", "find_function", "format", "functions", "instructions", "predefined_variables", "source", "strings"}
}
func (s *Script) Attr(name string) (starlark.Value, error) {
	switch name {
	case "functions":
		return s.functionsValue(), nil
	case "blocks":
		return s.blocksValue(), nil
	case "callbacks":
		return s.callbacksValue(), nil
	case "calls":
		return s.callsValue(), nil
	case "effects":
		return s.effectsValue(), nil
	case "evaluate":
		return starlark.NewBuiltin("installscript.evaluate", s.evaluateBuiltin), nil
	case "find_function":
		return starlark.NewBuiltin("installscript.find_function", s.findFunctionBuiltin), nil
	case "format":
		return starlark.String(s.format), nil
	case "instructions":
		if s.legacy != nil {
			return s.legacy.instructionsValue(), nil
		}
		return starlark.NewList(nil), nil
	case "predefined_variables":
		values := starlark.NewDict(len(s.PredefinedVariables()))
		for name, address := range s.PredefinedVariables() {
			if err := values.SetKey(starlark.String(name), starlark.MakeInt(address)); err != nil {
				return nil, err
			}
		}
		return values, nil
	case "source":
		return s.file, nil
	case "strings":
		return s.stringsValue(), nil
	}
	return nil, nil
}

func (s *Script) callbacksValue() *starlark.List {
	entries := s.installScriptCallbackEntries()
	entrySet := make(map[int]bool, len(entries))
	for _, id := range entries {
		entrySet[id] = true
	}
	project := make(map[int]bool)
	for index, prototype := range s.prototypes {
		if prototype.flags&1 != 0 {
			break
		}
		if prototype.flags&2 != 0 && prototype.blockIndex != 0xffff {
			project[index] = true
		}
	}
	callers := make(map[int]map[int]bool)
	callees := make(map[int]map[int]bool)
	for _, block := range s.blocks {
		if !project[block.functionID] {
			continue
		}
		for _, action := range block.actions {
			callee := int(action.functionID)
			if action.opcode != 33 || !project[callee] {
				continue
			}
			if callers[callee] == nil {
				callers[callee] = make(map[int]bool)
			}
			if callees[block.functionID] == nil {
				callees[block.functionID] = make(map[int]bool)
			}
			callers[callee][block.functionID] = true
			callees[block.functionID][callee] = true
		}
	}
	output := make([]starlark.Value, 0, len(project))
	for id := range project {
		callerValues := installScriptFunctionNames(s, callers[id])
		calleeValues := installScriptFunctionNames(s, callees[id])
		output = append(output, starlarkStringDict(map[string]starlark.Value{
			"id": starlark.MakeInt(id), "function": starlark.String(s.prototypes[id].name),
			"entry_candidate": starlark.Bool(entrySet[id]), "callers": starlark.NewList(callerValues),
			"callees": starlark.NewList(calleeValues),
		}))
	}
	sort.Slice(output, func(i, j int) bool {
		left, _, _ := output[i].(*starlark.Dict).Get(starlark.String("id"))
		right, _, _ := output[j].(*starlark.Dict).Get(starlark.String("id"))
		leftID, _ := starlark.AsInt32(left)
		rightID, _ := starlark.AsInt32(right)
		return leftID < rightID
	})
	return starlark.NewList(output)
}

func installScriptFunctionNames(s *Script, ids map[int]bool) []starlark.Value {
	values := make([]string, 0, len(ids))
	for id := range ids {
		values = append(values, s.prototypes[id].name)
	}
	sort.Slice(values, func(i, j int) bool { return strings.ToLower(values[i]) < strings.ToLower(values[j]) })
	output := make([]starlark.Value, len(values))
	for index, value := range values {
		output[index] = starlark.String(value)
	}
	return output
}

func installScriptOpcodeName(opcode uint16) string {
	// The aLuZ encoding uses 24 for || and 25 for &&. This is validated by
	// package control-flow patterns (for example, copy when source is absent OR
	// replacement is requested), rather than inherited from a decompiler enum.
	names := map[uint16]string{
		1: "nop", 2: "abort", 3: "exit", 4: "if", 5: "goto", 6: "assign",
		7: "add", 8: "mod", 9: "less", 10: "greater", 11: "less_equal",
		12: "greater_equal", 13: "equal", 14: "not_equal", 15: "subtract",
		16: "multiply", 17: "divide", 18: "bit_and", 19: "bit_or", 20: "bit_xor",
		21: "bit_not", 22: "shift_left", 23: "shift_right", 24: "logical_or",
		25: "logical_and", 26: "address_of", 27: "dereference", 28: "indirect_struct",
		29: "set_byte", 30: "get_byte", 32: "external_call", 33: "internal_call",
		34: "prologue", 35: "return", 36: "return_number", 37: "return_string",
		38: "end_function", 39: "statement", 40: "string_length", 41: "substring",
		42: "string_find", 43: "string_compare", 44: "string_to_number",
		45: "number_to_string", 46: "handler", 47: "handler_ex", 48: "do_handler",
		49: "resize", 50: "sizeof", 51: "property_put", 52: "property_put_ref",
		53: "property_get", 54: "try", 55: "end_try", 56: "end_catch",
		57: "use_dll", 58: "unuse_dll", 59: "bind_variable", 60: "address_of_wide",
	}
	if name := names[opcode]; name != "" {
		return name
	}
	return fmt.Sprintf("opcode_%d", opcode)
}

func (s *Script) functionsValue() *starlark.List {
	values := make([]starlark.Value, len(s.prototypes))
	for index := range s.prototypes {
		values[index] = s.functionValue(index)
	}
	return starlark.NewList(values)
}

func (s *Script) blocksValue() *starlark.List {
	values := make([]starlark.Value, len(s.blocks))
	for index, block := range s.blocks {
		actions := make([]starlark.Value, len(block.actions))
		for actionIndex, action := range block.actions {
			actions[actionIndex] = s.actionValue(action, block.functionID)
		}
		function := ""
		if block.functionID >= 0 && block.functionID < len(s.prototypes) {
			function = s.prototypes[block.functionID].name
		}
		values[index] = starlarkStringDict(map[string]starlark.Value{"index": starlark.MakeInt(block.index), "offset": starlark.MakeUint64(uint64(block.offset)), "function": starlark.String(function), "actions": starlark.NewList(actions)})
	}
	return starlark.NewList(values)
}

func (s *Script) callsValue() *starlark.List {
	values := make([]starlark.Value, 0)
	for _, block := range s.blocks {
		for _, action := range block.actions {
			if action.opcode == 32 || action.opcode == 33 {
				values = append(values, s.actionValue(action, block.functionID))
			}
		}
	}
	return starlark.NewList(values)
}

func (s *Script) actionValue(action installScriptAction, callerID int) *starlark.Dict {
	operands := make([]starlark.Value, len(action.operands))
	for index, operand := range action.operands {
		operands[index] = installScriptArgumentValue(operand)
	}
	callee := ""
	if int(action.functionID) < len(s.prototypes) {
		callee = s.prototypes[action.functionID].name
	}
	caller := ""
	if callerID >= 0 && callerID < len(s.prototypes) {
		caller = s.prototypes[callerID].name
	}
	return starlarkStringDict(map[string]starlark.Value{"offset": starlark.MakeUint64(uint64(action.offset)), "opcode": starlark.MakeInt(int(action.opcode)), "name": starlark.String(installScriptOpcodeName(action.opcode)), "caller": starlark.String(caller), "callee": starlark.String(callee), "function_id": starlark.MakeInt(int(action.functionID)), "target": starlark.MakeInt(int(action.target)), "operands": starlark.NewList(operands)})
}

func (s *Script) findFunctionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("installscript.find_function", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	for index, prototype := range s.prototypes {
		if strings.EqualFold(prototype.name, name) {
			return s.functionValue(index), nil
		}
	}
	return starlark.None, nil
}

func (s *Script) functionValue(index int) *starlark.Dict {
	prototype := s.prototypes[index]
	argumentTypes := make([]starlark.Value, len(prototype.arguments))
	for argument, typ := range prototype.arguments {
		argumentTypes[argument] = starlarkStringDict(map[string]starlark.Value{
			"script_type":   starlark.MakeInt(int(typ.scriptType)),
			"concrete_type": starlark.MakeInt(int(typ.concreteType)),
		})
	}
	return starlarkStringDict(map[string]starlark.Value{
		"id": starlark.MakeInt(index), "name": starlark.String(prototype.name),
		"dll": starlark.String(prototype.dll), "flags": starlark.MakeInt(int(prototype.flags)),
		"block": starlark.MakeInt(int(prototype.blockIndex)), "arguments": starlark.NewList(argumentTypes),
	})
}

func installScriptArgumentValue(argument installScriptArgument) *starlark.Dict {
	values := map[string]starlark.Value{"kind": starlark.MakeInt(int(argument.kind)), "display": starlark.String(argument.String())}
	switch argument.kind {
	case 4, 5, 8:
		values["address"] = starlark.MakeInt(int(argument.address))
	case 6:
		values["value"] = starlark.String(argument.text)
	case 7:
		values["value"] = starlark.MakeInt64(int64(argument.number))
	}
	return starlarkStringDict(values)
}

func (s *Script) stringsValue() *starlark.List {
	if s.legacy != nil {
		result := make([]starlark.Value, len(s.legacy.strings))
		for index, value := range s.legacy.strings {
			result[index] = starlark.String(value)
		}
		return starlark.NewList(result)
	}
	seen := make(map[string]bool)
	values := make([]string, 0)
	for _, block := range s.blocks {
		for _, action := range block.actions {
			for _, argument := range action.operands {
				if argument.kind == 6 && !seen[argument.text] {
					seen[argument.text] = true
					values = append(values, argument.text)
				}
			}
		}
	}
	sort.SliceStable(values, func(i, j int) bool { return strings.ToLower(values[i]) < strings.ToLower(values[j]) })
	result := make([]starlark.Value, len(values))
	for index, value := range values {
		result[index] = starlark.String(value)
	}
	return starlark.NewList(result)
}

// TargetDefaults returns statically proved TARGETDIR defaults.
func (s *Script) TargetDefaults() *starlark.List {
	output := make([]starlark.Value, 0)
	seen := make(map[string]bool)
	for blockIndex, block := range s.blocks {
		for actionIndex := 0; actionIndex+1 < len(block.actions); actionIndex++ {
			first, second := block.actions[actionIndex], block.actions[actionIndex+1]
			if first.opcode != 20 || second.opcode != 20 || len(first.operands) != 3 || len(second.operands) != 3 {
				continue
			}
			if first.operands[2].kind != 6 || second.operands[2].kind != 6 || second.operands[0].kind != 4 || second.operands[0].address < 0 {
				continue
			}
			if first.operands[0].kind != 4 || second.operands[1].kind != 4 || first.operands[0].address != second.operands[1].address {
				continue
			}
			value := `<PROGRAMFILES>\` + first.operands[2].text + `\` + second.operands[2].text
			if seen[strings.ToLower(value)] {
				continue
			}
			seen[strings.ToLower(value)] = true
			output = append(output, starlarkStringDict(map[string]starlark.Value{
				"variable": starlark.String("TARGETDIR"), "value": starlark.String(value),
				"base": starlark.String("<PROGRAMFILES>"), "block": starlark.MakeInt(blockIndex),
				"offset": starlark.MakeUint64(uint64(second.offset)), "conditional": starlark.True,
				"source": starlark.String("InstallScript path expression"),
			}))
		}
	}
	return starlark.NewList(output)
}
