package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"

	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
)

const (
	cspMaximumFunctionBytes = 4096
	cspMaximumStringBytes   = 512
	cspMaximumSignature     = 1 << 20
)

type cspRegistration struct {
	provider        string
	imagePath       string
	signatureData   []byte
	providerType    uint32
	typeKey         string
	typeName        string
	signatureInFile bool
	makeDefault     bool
}

type x86Constant struct {
	value uint32
	ok    bool
}

type cspCodeCall struct {
	target uint32
	pushes []x86Constant
}

type cspPESection struct {
	rvaStart uint32
	rvaEnd   uint32
	rawStart uint32
	rawSize  uint32
	writable bool
}

type cspPEContext struct {
	data     []byte
	image    *pe.File
	optional *pe.OptionalHeader32
	sections []cspPESection
}

type cspImagePathSource interface {
	directDLL(uint32) (string, bool)
	writableAddress(uint32) bool
	exportDLLName() (string, error)
}

var errUnrecognizedCSPRegistration = errors.New("DllRegisterServer contains no recognizable CSP registrations")

// cspRegistrationsBuiltin extracts CryptoAPI provider-registration arguments
// from a 32-bit provider DLL without assigning registry paths or defaults.
func cspRegistrationsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	strict := true
	if err := starlark.UnpackArgs("csp_registrations", args, kwargs, "file", &value, "strict?", &strict); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("csp_registrations: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	registrations, err := cspRegistrations(data)
	if err != nil {
		if !strict && errors.Is(err, errUnrecognizedCSPRegistration) {
			return starlark.NewList(nil), nil
		}
		return nil, fmt.Errorf("csp_registrations: %w", err)
	}
	values := make([]starlark.Value, len(registrations))
	for index, registration := range registrations {
		fields := starlark.StringDict{
			"provider":          starlark.String(registration.provider),
			"image_path":        starlark.String(registration.imagePath),
			"provider_type":     starlark.MakeUint(uint(registration.providerType)),
			"type_key":          starlark.String(registration.typeKey),
			"type_name":         starlark.String(registration.typeName),
			"signature_in_file": starlark.Bool(registration.signatureInFile),
			"make_default":      starlark.Bool(registration.makeDefault),
		}
		if !registration.signatureInFile {
			fields["signature_data"] = starlark.Bytes(registration.signatureData)
		}
		values[index] = starfile.NewRecord(fields)
	}
	return starlark.NewList(values), nil
}

func newCSPPEContext(data []byte, image *pe.File, optional *pe.OptionalHeader32) (*cspPEContext, error) {
	context := &cspPEContext{data: data, image: image, optional: optional}
	for _, section := range image.Sections {
		mappedSize := section.VirtualSize
		if mappedSize < section.Size {
			mappedSize = section.Size
		}
		end := uint64(section.VirtualAddress) + uint64(mappedSize)
		rawEnd := uint64(section.Offset) + uint64(section.Size)
		if end > uint64(optional.SizeOfImage) || rawEnd > uint64(len(data)) {
			return nil, fmt.Errorf("invalid PE section bounds")
		}
		context.sections = append(context.sections, cspPESection{
			rvaStart: section.VirtualAddress,
			rvaEnd:   uint32(end),
			rawStart: section.Offset,
			rawSize:  section.Size,
			writable: section.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0,
		})
	}
	for left := 0; left < len(context.sections); left++ {
		for right := left + 1; right < len(context.sections); right++ {
			if context.sections[left].rvaStart < context.sections[right].rvaEnd &&
				context.sections[right].rvaStart < context.sections[left].rvaEnd {
				return nil, fmt.Errorf("overlapping PE section mappings")
			}
		}
	}
	return context, nil
}

func (context *cspPEContext) addressRVA(address uint32) (uint32, bool) {
	if address < context.optional.ImageBase {
		return 0, false
	}
	rva := address - context.optional.ImageBase
	if rva >= context.optional.SizeOfImage {
		return 0, false
	}
	return rva, true
}

func (context *cspPEContext) sectionForRVA(rva uint32, size uint32) (cspPESection, bool) {
	end := uint64(rva) + uint64(size)
	for _, section := range context.sections {
		if rva >= section.rvaStart && end <= uint64(section.rvaEnd) {
			return section, true
		}
	}
	return cspPESection{}, false
}

func (context *cspPEContext) rawRange(rva uint32, size uint32) ([]byte, bool) {
	section, ok := context.sectionForRVA(rva, size)
	if !ok {
		return nil, false
	}
	delta := rva - section.rvaStart
	if uint64(delta)+uint64(size) > uint64(section.rawSize) {
		return nil, false
	}
	start := uint64(section.rawStart) + uint64(delta)
	end := start + uint64(size)
	if end > uint64(len(context.data)) {
		return nil, false
	}
	return context.data[start:end], true
}

func (context *cspPEContext) printableCStringRVA(rva uint32) (string, bool) {
	section, ok := context.sectionForRVA(rva, 1)
	if !ok {
		return "", false
	}
	delta := rva - section.rvaStart
	if delta >= section.rawSize {
		return "", false
	}
	start := uint64(section.rawStart) + uint64(delta)
	limit := uint64(section.rawStart) + uint64(section.rawSize)
	if maximum := start + cspMaximumStringBytes + 1; limit > maximum {
		limit = maximum
	}
	if limit > uint64(len(context.data)) {
		limit = uint64(len(context.data))
	}
	end := start
	for end < limit && context.data[end] != 0 {
		if context.data[end] < 0x20 || context.data[end] > 0x7e {
			return "", false
		}
		end++
	}
	if end == limit || context.data[end] != 0 {
		return "", false
	}
	return string(context.data[start:end]), true
}

func (context *cspPEContext) printableCStringVA(address uint32) (string, bool) {
	rva, ok := context.addressRVA(address)
	if !ok {
		return "", false
	}
	return context.printableCStringRVA(rva)
}

func (context *cspPEContext) directDLL(address uint32) (string, bool) {
	value, ok := context.printableCStringVA(address)
	return value, ok && value != "" && strings.HasSuffix(strings.ToLower(value), ".dll")
}

func (context *cspPEContext) writableAddress(address uint32) bool {
	rva, ok := context.addressRVA(address)
	if !ok {
		return false
	}
	section, ok := context.sectionForRVA(rva, 1)
	return ok && section.writable
}

func validCSPExportDLLName(value string) bool {
	if value == "" || value == "." || value == ".." ||
		strings.ContainsAny(value, `/\:`) || !strings.HasSuffix(strings.ToLower(value), ".dll") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func (context *cspPEContext) exportDLLName() (string, error) {
	if len(context.optional.DataDirectory) <= pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
		return "", fmt.Errorf("PE image has no export data directory")
	}
	directory := context.optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if directory.VirtualAddress == 0 || directory.Size < 40 {
		return "", fmt.Errorf("PE image has no valid export directory")
	}
	raw, ok := context.rawRange(directory.VirtualAddress, 40)
	if !ok {
		return "", fmt.Errorf("PE export directory is outside mapped file data")
	}
	nameRVA := binary.LittleEndian.Uint32(raw[12:16])
	name, ok := context.printableCStringRVA(nameRVA)
	if !ok || !validCSPExportDLLName(name) {
		return "", fmt.Errorf("PE export directory has an invalid DLL name")
	}
	return name, nil
}

func resolveCSPImagePath(source cspImagePathSource, address uint32) (string, error) {
	if direct, ok := source.directDLL(address); ok {
		return direct, nil
	}
	if !source.writableAddress(address) {
		return "", fmt.Errorf("image-path argument is neither a direct DLL string nor a writable mapped address")
	}
	name, err := source.exportDLLName()
	if err != nil {
		return "", err
	}
	return name, nil
}

func cspRegistrations(data []byte) ([]cspRegistration, error) {
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	optional, ok := image.OptionalHeader.(*pe.OptionalHeader32)
	if !ok || image.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_I386 {
		return nil, fmt.Errorf("CSP registration analysis requires a 32-bit x86 PE image")
	}
	context, err := newCSPPEContext(data, image, optional)
	if err != nil {
		return nil, err
	}
	exports, err := peExports(data)
	if err != nil {
		return nil, err
	}
	var registerRVA uint32
	for _, export := range exports {
		if export.name == "DllRegisterServer" {
			if registerRVA != 0 && registerRVA != export.rva {
				return nil, fmt.Errorf("multiple DllRegisterServer exports")
			}
			registerRVA = export.rva
		}
	}
	if registerRVA == 0 {
		return nil, errUnrecognizedCSPRegistration
	}
	code, err := context.functionBytes(registerRVA)
	if err != nil {
		return nil, fmt.Errorf("DllRegisterServer: %w", err)
	}
	calls, err := analyzeCSPRegistrationCode(code, registerRVA)
	if err != nil {
		return nil, err
	}
	imports, err := peImports(data)
	if err != nil {
		return nil, err
	}
	helperTargets := make(map[uint32]bool)
	for _, call := range calls {
		if call.target == 0 || helperTargets[call.target] {
			continue
		}
		valid, err := validateCSPRegistrationHelper(context, call.target, imports)
		if err != nil {
			return nil, err
		}
		if valid {
			helperTargets[call.target] = true
		}
	}
	if len(helperTargets) == 0 {
		return nil, errUnrecognizedCSPRegistration
	}
	if len(helperTargets) != 1 {
		return nil, fmt.Errorf("DllRegisterServer contains %d CSP registration helpers", len(helperTargets))
	}
	helperTarget := uint32(0)
	for target := range helperTargets {
		helperTarget = target
	}
	var registrations []cspRegistration
	for _, call := range calls {
		if call.target != helperTarget {
			continue
		}
		registration, err := cspRegistrationFromPushes(call.pushes, context)
		if err != nil {
			return nil, fmt.Errorf("partially recoverable CSP registration call: %w", err)
		}
		registrations = append(registrations, registration)
	}
	if len(registrations) == 0 {
		return nil, errUnrecognizedCSPRegistration
	}
	if err := validateCSPRegistrationConflicts(registrations); err != nil {
		return nil, err
	}
	return registrations, nil
}

func (context *cspPEContext) functionBytes(rva uint32) ([]byte, error) {
	section, ok := context.sectionForRVA(rva, 1)
	if !ok {
		return nil, fmt.Errorf("function RVA %#x is outside mapped sections", rva)
	}
	delta := rva - section.rvaStart
	if delta >= section.rawSize {
		return nil, fmt.Errorf("function RVA %#x is outside file-backed section data", rva)
	}
	size := section.rawSize - delta
	if size > cspMaximumFunctionBytes {
		size = cspMaximumFunctionBytes
	}
	code, ok := context.rawRange(rva, size)
	if !ok {
		return nil, fmt.Errorf("function RVA %#x cannot be read", rva)
	}
	return code, nil
}

func analyzeCSPRegistrationCode(code []byte, startRVA uint32) ([]cspCodeCall, error) {
	registers := make(map[x86asm.Reg]x86Constant)
	var pushes []x86Constant
	var calls []cspCodeCall
	var zeroOnFallthrough x86asm.Reg
	for off := 0; off < len(code); {
		instruction, err := x86asm.Decode(code[off:], 32)
		if err != nil || instruction.Len <= 0 {
			return nil, fmt.Errorf("malformed DllRegisterServer instruction at RVA %#x", startRVA+uint32(off))
		}
		conditionRegister := zeroOnFallthrough
		zeroOnFallthrough = 0
		switch instruction.Op {
		case x86asm.MOV:
			if destination, ok := instruction.Args[0].(x86asm.Reg); ok {
				registers[destination] = x86ArgumentConstant(instruction.Args[1], registers)
			}
		case x86asm.XOR, x86asm.SUB:
			left, leftOK := instruction.Args[0].(x86asm.Reg)
			right, rightOK := instruction.Args[1].(x86asm.Reg)
			if leftOK {
				if rightOK && left == right {
					registers[left] = x86Constant{ok: true}
				} else {
					registers[left] = x86Constant{}
				}
			}
		case x86asm.ADD:
			if target, ok := instruction.Args[0].(x86asm.Reg); ok {
				left := registers[target]
				right := x86ArgumentConstant(instruction.Args[1], registers)
				if left.ok && right.ok {
					left.value += right.value
				} else {
					left.ok = false
				}
				registers[target] = left
			}
		case x86asm.INC, x86asm.DEC:
			if target, ok := instruction.Args[0].(x86asm.Reg); ok {
				value := registers[target]
				if value.ok {
					if instruction.Op == x86asm.INC {
						value.value++
					} else {
						value.value--
					}
				}
				registers[target] = value
			}
		case x86asm.PUSH:
			pushes = append(pushes, x86ArgumentConstant(instruction.Args[0], registers))
		case x86asm.TEST:
			left, leftOK := instruction.Args[0].(x86asm.Reg)
			right, rightOK := instruction.Args[1].(x86asm.Reg)
			if leftOK && rightOK && left == right {
				zeroOnFallthrough = left
			}
		case x86asm.CMP:
			if left, ok := instruction.Args[0].(x86asm.Reg); ok {
				if right, ok := instruction.Args[1].(x86asm.Imm); ok && uint32(int64(right)) == 0 {
					zeroOnFallthrough = left
				}
			}
		case x86asm.JNE:
			if conditionRegister != 0 {
				registers[conditionRegister] = x86Constant{ok: true}
			}
		case x86asm.CALL:
			call := cspCodeCall{pushes: append([]x86Constant(nil), pushes...)}
			if relative, ok := instruction.Args[0].(x86asm.Rel); ok {
				target := int64(startRVA) + int64(off) + int64(instruction.Len) + int64(relative)
				if target >= 0 && target <= int64(^uint32(0)) {
					call.target = uint32(target)
				}
			}
			calls = append(calls, call)
			pushes = pushes[:0]
			for _, register := range []x86asm.Reg{x86asm.EAX, x86asm.ECX, x86asm.EDX} {
				registers[register] = x86Constant{}
			}
		case x86asm.RET:
			return calls, nil
		default:
			if destination, ok := instruction.Args[0].(x86asm.Reg); ok && x86InstructionWritesFirstArgument(instruction.Op) {
				registers[destination] = x86Constant{}
			}
		}
		off += instruction.Len
	}
	return nil, fmt.Errorf("DllRegisterServer has no bounded return")
}

func x86InstructionWritesFirstArgument(operation x86asm.Op) bool {
	switch operation {
	case x86asm.AND, x86asm.OR, x86asm.LEA, x86asm.POP, x86asm.SHL, x86asm.SHR, x86asm.SAR:
		return true
	default:
		return false
	}
}

func x86ArgumentConstant(argument x86asm.Arg, registers map[x86asm.Reg]x86Constant) x86Constant {
	switch value := argument.(type) {
	case x86asm.Imm:
		return x86Constant{value: uint32(int64(value)), ok: true}
	case x86asm.Reg:
		return registers[value]
	default:
		return x86Constant{}
	}
}

func validateCSPRegistrationHelper(context *cspPEContext, target uint32, imports []peImport) (bool, error) {
	code, err := context.functionBytes(target)
	if err != nil {
		return false, nil
	}
	importByAddress := make(map[uint32]string)
	for _, imported := range imports {
		if imported.name != "" {
			importByAddress[context.optional.ImageBase+imported.iatRVA] = imported.name
		}
	}
	registerImports := make(map[x86asm.Reg]string)
	argumentOffsets := make(map[int64]bool)
	registryCalls := make(map[string]int)
	literals := make(map[string]bool)
	hasReturn := false
analysis:
	for off := 0; off < len(code); {
		instruction, decodeErr := x86asm.Decode(code[off:], 32)
		if decodeErr != nil || instruction.Len <= 0 {
			return false, nil
		}
		for _, argument := range instruction.Args {
			if argument == nil {
				break
			}
			switch value := argument.(type) {
			case x86asm.Mem:
				if value.Base == x86asm.EBP && value.Index == 0 && value.Disp >= 8 && value.Disp <= 40 && value.Disp%4 == 0 {
					argumentOffsets[value.Disp] = true
				}
			case x86asm.Imm:
				if text, ok := context.printableCStringVA(uint32(int64(value))); ok {
					literals[text] = true
				}
			}
		}
		if instruction.Op == x86asm.MOV {
			if destination, ok := instruction.Args[0].(x86asm.Reg); ok {
				delete(registerImports, destination)
				if source, ok := instruction.Args[1].(x86asm.Mem); ok && source.Base == 0 && source.Index == 0 {
					if name := importByAddress[uint32(source.Disp)]; name != "" {
						registerImports[destination] = name
					}
				}
			}
		}
		if instruction.Op == x86asm.CALL {
			name := ""
			switch target := instruction.Args[0].(type) {
			case x86asm.Mem:
				if target.Base == 0 && target.Index == 0 {
					name = importByAddress[uint32(target.Disp)]
				}
			case x86asm.Reg:
				name = registerImports[target]
			}
			if name != "" {
				registryCalls[name]++
			}
		}
		if instruction.Op == x86asm.RET {
			immediate, ok := instruction.Args[0].(x86asm.Imm)
			hasReturn = ok && uint32(int64(immediate)) == 36
			break analysis
		}
		off += instruction.Len
	}
	if !hasReturn || registryCalls["RegCreateKeyExA"] < 2 || registryCalls["RegSetValueExA"] < 4 {
		return false, nil
	}
	for offset := int64(8); offset <= 40; offset += 4 {
		if !argumentOffsets[offset] {
			return false, nil
		}
	}
	for _, literal := range []string{
		`SOFTWARE\Microsoft\Cryptography\Defaults\Provider\`,
		`SOFTWARE\Microsoft\Cryptography\Defaults\Provider Types\`,
		"Image Path", "Type", "SigInFile", "Signature", "Name", "TypeName",
	} {
		if !literals[literal] {
			return false, nil
		}
	}
	return true, nil
}

func cspRegistrationFromPushes(pushes []x86Constant, context *cspPEContext) (cspRegistration, error) {
	if len(pushes) < 9 {
		return cspRegistration{}, fmt.Errorf("call has %d pushed values, want nine arguments", len(pushes))
	}
	pushes = pushes[len(pushes)-9:]
	arguments := make([]x86Constant, 9)
	for index := range pushes {
		arguments[index] = pushes[len(pushes)-1-index]
	}
	for index, argument := range arguments {
		if !argument.ok {
			return cspRegistration{}, fmt.Errorf("argument %d is unresolved", index)
		}
	}
	provider, providerOK := context.printableCStringVA(arguments[0].value)
	typeKey, typeKeyOK := context.printableCStringVA(arguments[5].value)
	typeName, typeNameOK := context.printableCStringVA(arguments[6].value)
	if !providerOK || provider == "" || !typeKeyOK || !typeNameOK {
		return cspRegistration{}, fmt.Errorf("provider, type key, or type name is not a mapped printable string")
	}
	providerType := arguments[4].value
	if providerType < 1 || providerType > 999 || typeKey != fmt.Sprintf("Type %03d", providerType) {
		return cspRegistration{}, fmt.Errorf("provider type and type key are inconsistent")
	}
	imagePath, err := resolveCSPImagePath(context, arguments[1].value)
	if err != nil {
		return cspRegistration{}, err
	}
	signaturePointer := arguments[2].value
	signatureLength := arguments[3].value
	if signaturePointer == 0 && signatureLength != 0 {
		return cspRegistration{}, fmt.Errorf("null signature pointer has nonzero length")
	}
	if signatureLength > cspMaximumSignature {
		return cspRegistration{}, fmt.Errorf("signature exceeds analysis bounds")
	}
	var signature []byte
	if signaturePointer != 0 {
		rva, ok := context.addressRVA(signaturePointer)
		if !ok {
			return cspRegistration{}, fmt.Errorf("signature pointer is outside the PE image")
		}
		readSize := signatureLength
		if readSize == 0 {
			readSize = 1
		}
		raw, ok := context.rawRange(rva, readSize)
		if !ok {
			return cspRegistration{}, fmt.Errorf("signature data is outside mapped file data")
		}
		if signatureLength != 0 {
			signature = bytes.Clone(raw[:signatureLength])
		}
	}
	return cspRegistration{
		provider:        provider,
		imagePath:       imagePath,
		signatureData:   signature,
		providerType:    providerType,
		typeKey:         typeKey,
		typeName:        typeName,
		signatureInFile: arguments[7].value != 0,
		makeDefault:     arguments[8].value != 0,
	}, nil
}

func validateCSPRegistrationConflicts(registrations []cspRegistration) error {
	providers := make(map[string]cspRegistration)
	types := make(map[string]cspRegistration)
	for _, registration := range registrations {
		if previous, ok := providers[registration.provider]; ok && !equalCSPRegistration(previous, registration) {
			return fmt.Errorf("provider %q has conflicting registrations", registration.provider)
		}
		providers[registration.provider] = registration
		if previous, ok := types[registration.typeKey]; ok &&
			(previous.providerType != registration.providerType || previous.typeName != registration.typeName) {
			return fmt.Errorf("provider type %q has conflicting registrations", registration.typeKey)
		}
		types[registration.typeKey] = registration
	}
	return nil
}

func equalCSPRegistration(left, right cspRegistration) bool {
	return left.provider == right.provider &&
		left.imagePath == right.imagePath &&
		bytes.Equal(left.signatureData, right.signatureData) &&
		left.providerType == right.providerType &&
		left.typeKey == right.typeKey &&
		left.typeName == right.typeName &&
		left.signatureInFile == right.signatureInFile &&
		left.makeDefault == right.makeDefault
}
