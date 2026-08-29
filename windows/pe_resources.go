package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
)

func peResourcesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_resources", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_resources: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	resources, err := peResources(data)
	if err != nil {
		return nil, err
	}
	sort.Slice(resources, func(i, j int) bool {
		a, b := resources[i], resources[j]
		if a.typ != b.typ {
			return a.typ < b.typ
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return a.lang < b.lang
	})
	out := make([]starlark.Value, 0, len(resources))
	for _, resource := range resources {
		dict := starlark.NewDict(6)
		if err := dict.SetKey(starlark.String("type"), starlark.String(resource.typ)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("name"), starlark.String(resource.name)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("lang"), starlark.String(resource.lang)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("size"), starlark.MakeInt(len(resource.data))); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("data"), starlark.Bytes(resource.data)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("text"), starlark.String(decodeResourceText(resource.data))); err != nil {
			return nil, err
		}
		out = append(out, dict)
	}
	return starlark.NewList(out), nil
}

type peFixedVersion struct {
	file        [4]uint16
	product     [4]uint16
	flagsMask   uint32
	flags       uint32
	os          uint32
	fileType    uint32
	fileSubtype uint32
}

func peVersionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_version", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_version: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	resources, err := peResources(data)
	if err != nil {
		// Fixed-version probing is intentionally optional: installer payloads
		// contain data files alongside PE images and use None to select normal
		// overwrite behavior. Strict PE parsing remains available through the
		// other windows.pe properties.
		return starlark.None, nil
	}
	var selected []byte
	for _, resource := range resources {
		if resource.typ != "#16" {
			continue
		}
		selected = resource.data
		if resource.lang == "#1033" {
			break
		}
	}
	if selected == nil {
		return starlark.None, nil
	}
	version, ok := parsePEFixedVersion(selected)
	if !ok {
		return starlark.None, nil
	}
	versionList := func(parts [4]uint16) starlark.Value {
		return starlark.NewList([]starlark.Value{
			starlark.MakeUint(uint(parts[0])),
			starlark.MakeUint(uint(parts[1])),
			starlark.MakeUint(uint(parts[2])),
			starlark.MakeUint(uint(parts[3])),
		})
	}
	return starfile.NewRecord(map[string]starlark.Value{
		"file":       versionList(version.file),
		"product":    versionList(version.product),
		"flags_mask": starlark.MakeUint64(uint64(version.flagsMask)),
		"flags":      starlark.MakeUint64(uint64(version.flags)),
		"os":         starlark.MakeUint64(uint64(version.os)),
		"type":       starlark.MakeUint64(uint64(version.fileType)),
		"subtype":    starlark.MakeUint64(uint64(version.fileSubtype)),
	}), nil
}

func parsePEFixedVersion(data []byte) (peFixedVersion, bool) {
	var out peFixedVersion
	if len(data) < 6 {
		return out, false
	}
	totalLength := int(binary.LittleEndian.Uint16(data[0:2]))
	valueLength := int(binary.LittleEndian.Uint16(data[2:4]))
	if totalLength < 6 || totalLength > len(data) || valueLength < 52 {
		return out, false
	}
	key := utf16.Encode([]rune("VS_VERSION_INFO"))
	offset := 6
	for _, expected := range key {
		if offset+2 > totalLength || binary.LittleEndian.Uint16(data[offset:offset+2]) != expected {
			return out, false
		}
		offset += 2
	}
	if offset+2 > totalLength || binary.LittleEndian.Uint16(data[offset:offset+2]) != 0 {
		return out, false
	}
	offset += 2
	offset = (offset + 3) &^ 3
	if offset+52 > totalLength || binary.LittleEndian.Uint32(data[offset:offset+4]) != 0xfeef04bd {
		return out, false
	}
	fileMS := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
	fileLS := binary.LittleEndian.Uint32(data[offset+12 : offset+16])
	productMS := binary.LittleEndian.Uint32(data[offset+16 : offset+20])
	productLS := binary.LittleEndian.Uint32(data[offset+20 : offset+24])
	out.file = [4]uint16{uint16(fileMS >> 16), uint16(fileMS), uint16(fileLS >> 16), uint16(fileLS)}
	out.product = [4]uint16{uint16(productMS >> 16), uint16(productMS), uint16(productLS >> 16), uint16(productLS)}
	out.flagsMask = binary.LittleEndian.Uint32(data[offset+24 : offset+28])
	out.flags = binary.LittleEndian.Uint32(data[offset+28 : offset+32])
	out.os = binary.LittleEndian.Uint32(data[offset+32 : offset+36])
	out.fileType = binary.LittleEndian.Uint32(data[offset+36 : offset+40])
	out.fileSubtype = binary.LittleEndian.Uint32(data[offset+40 : offset+44])
	return out, true
}

func peMessagesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_messages", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_messages: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	resources, err := peResources(data)
	if err != nil {
		return nil, err
	}
	messages, err := peMessageResources(resources)
	if err != nil {
		return nil, err
	}
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].id != messages[j].id {
			return messages[i].id < messages[j].id
		}
		return messages[i].lang < messages[j].lang
	})
	out := make([]starlark.Value, 0, len(messages))
	for _, message := range messages {
		out = append(out, starfile.NewRecord(map[string]starlark.Value{
			"id":      starlark.MakeUint(uint(message.id)),
			"lang":    starlark.String(message.lang),
			"text":    starlark.String(message.text),
			"unicode": starlark.Bool(message.unicode),
		}))
	}
	return starlark.NewList(out), nil
}

func peSectionsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_sections", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_sections: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	out := make([]starlark.Value, 0, len(image.Sections))
	for _, section := range image.Sections {
		dict := starlark.NewDict(5)
		fields := []struct {
			name  string
			value starlark.Value
		}{
			{"name", starlark.String(section.Name)},
			{"virtual_address", starlark.MakeUint64(uint64(section.VirtualAddress))},
			{"virtual_size", starlark.MakeUint64(uint64(section.VirtualSize))},
			{"raw_size", starlark.MakeUint64(uint64(section.Size))},
			{"raw_offset", starlark.MakeUint64(uint64(section.Offset))},
			{"characteristics", starlark.MakeUint64(uint64(section.Characteristics))},
		}
		for _, field := range fields {
			if err := dict.SetKey(starlark.String(field.name), field.value); err != nil {
				return nil, err
			}
		}
		out = append(out, dict)
	}
	return starlark.NewList(out), nil
}

func peInfoBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_info", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_info: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	var entryPoint, imageBase, imageSize, sectionAlignment uint64
	switch header := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryPoint = uint64(header.AddressOfEntryPoint)
		imageBase = uint64(header.ImageBase)
		imageSize = uint64(header.SizeOfImage)
		sectionAlignment = uint64(header.SectionAlignment)
	case *pe.OptionalHeader64:
		entryPoint = uint64(header.AddressOfEntryPoint)
		imageBase = header.ImageBase
		imageSize = uint64(header.SizeOfImage)
		sectionAlignment = uint64(header.SectionAlignment)
	default:
		return nil, fmt.Errorf("pe_info: unsupported optional header %T", image.OptionalHeader)
	}
	dict := starlark.NewDict(5)
	fields := []struct {
		name  string
		value uint64
	}{
		{"machine", uint64(image.FileHeader.Machine)},
		{"entry_point", entryPoint},
		{"image_base", imageBase},
		{"image_size", imageSize},
		{"section_alignment", sectionAlignment},
	}
	for _, field := range fields {
		if err := dict.SetKey(starlark.String(field.name), starlark.MakeUint64(field.value)); err != nil {
			return nil, err
		}
	}
	return dict, nil
}

func peDisasmBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var rva uint64
	size := 256
	if err := starlark.UnpackArgs("pe_disasm", args, kwargs, "file", &value, "rva", &rva, "size?", &size); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_disasm: got %s, want file", value.Type())
	}
	if rva > uint64(^uint32(0)) || size < 0 {
		return nil, fmt.Errorf("pe_disasm: invalid RVA or size")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	mode, err := peDisasmMode(image.FileHeader.Machine)
	if err != nil {
		return nil, err
	}
	raw, err := peRVAOffset(image, uint32(rva))
	if err != nil {
		return nil, fmt.Errorf("pe_disasm: %w", err)
	}
	if uint64(raw) >= uint64(len(data)) {
		return nil, fmt.Errorf("pe_disasm: RVA %#x outside file", rva)
	}
	end := int(raw) + size
	if end > len(data) {
		end = len(data)
	}
	out := make([]starlark.Value, 0, size/3)
	for offset, address := int(raw), rva; offset < end; {
		inst, decodeErr := decodeX86Instruction(data[offset:end], mode)
		length := inst.Len
		text := ""
		if decodeErr != nil || length <= 0 {
			length = 1
			text = fmt.Sprintf("db 0x%02x", data[offset])
		} else {
			text = x86asm.IntelSyntax(inst, address, nil)
		}
		row := starlark.NewDict(6)
		op := ""
		operands := starlark.NewList(nil)
		if decodeErr == nil && inst.Len > 0 {
			op = strings.ToLower(inst.Op.String())
			for _, argument := range inst.Args {
				if argument == nil {
					break
				}
				operand, err := peDisasmOperand(argument, address, length)
				if err != nil {
					return nil, err
				}
				if err := operands.Append(operand); err != nil {
					return nil, err
				}
			}
		}
		fields := []struct {
			name  string
			value starlark.Value
		}{
			{"rva", starlark.MakeUint64(address)},
			{"size", starlark.MakeInt(length)},
			{"bytes", starlark.Bytes(data[offset : offset+length])},
			{"text", starlark.String(text)},
			{"op", starlark.String(op)},
			{"operands", operands},
		}
		for _, field := range fields {
			if err := row.SetKey(starlark.String(field.name), field.value); err != nil {
				return nil, err
			}
		}
		out = append(out, row)
		offset += length
		address += uint64(length)
	}
	return starlark.NewList(out), nil
}

func peDisasmOperand(argument x86asm.Arg, address uint64, length int) (*starlark.Dict, error) {
	operand := starlark.NewDict(8)
	set := func(name string, value starlark.Value) error {
		return operand.SetKey(starlark.String(name), value)
	}
	switch value := argument.(type) {
	case x86asm.Reg:
		if err := set("kind", starlark.String("register")); err != nil {
			return nil, err
		}
		if err := set("name", starlark.String(strings.ToLower(value.String()))); err != nil {
			return nil, err
		}
	case x86asm.Imm:
		if err := set("kind", starlark.String("immediate")); err != nil {
			return nil, err
		}
		if err := set("value", starlark.MakeInt64(int64(value))); err != nil {
			return nil, err
		}
		if err := set("u32", starlark.MakeUint64(uint64(uint32(int64(value))))); err != nil {
			return nil, err
		}
	case x86asm.Rel:
		target := uint64(uint32(int64(address) + int64(length) + int64(value)))
		if err := set("kind", starlark.String("relative")); err != nil {
			return nil, err
		}
		if err := set("displacement", starlark.MakeInt64(int64(value))); err != nil {
			return nil, err
		}
		if err := set("target", starlark.MakeUint64(target)); err != nil {
			return nil, err
		}
	case x86asm.Mem:
		if err := set("kind", starlark.String("memory")); err != nil {
			return nil, err
		}
		for name, field := range map[string]starlark.Value{
			"segment": starlark.String(x86RegisterName(value.Segment)),
			"base":    starlark.String(x86RegisterName(value.Base)),
			"index":   starlark.String(x86RegisterName(value.Index)),
			"scale":   starlark.MakeUint(uint(value.Scale)),
			"disp":    starlark.MakeInt64(value.Disp),
			"u32":     starlark.MakeUint64(uint64(uint32(value.Disp))),
		} {
			if err := set(name, field); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("pe_disasm: unsupported operand %T", argument)
	}
	return operand, nil
}

func x86RegisterName(register x86asm.Reg) string {
	if register == 0 {
		return ""
	}
	return strings.ToLower(register.String())
}

func peDisasmMode(machine uint16) (int, error) {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return 32, nil
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return 64, nil
	default:
		return 0, fmt.Errorf("pe_disasm: unsupported machine %#x", machine)
	}
}

func decodeX86Instruction(data []byte, mode int) (inst x86asm.Inst, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			inst = x86asm.Inst{}
			err = fmt.Errorf("x86 decoder panic: %v", recovered)
		}
	}()
	return x86asm.Decode(data, mode)
}

func pePatchBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var patchValue starlark.Value
	var rva uint64
	updateChecksum := true
	if err := starlark.UnpackArgs("pe_patch", args, kwargs, "file", &value, "rva", &rva, "data", &patchValue, "update_checksum?", &updateChecksum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_patch: got %s, want file", value.Type())
	}
	if rva > uint64(^uint32(0)) {
		return nil, fmt.Errorf("pe_patch: RVA %#x is too large", rva)
	}
	patch, err := bytesForValue(patchValue)
	if err != nil {
		return nil, fmt.Errorf("pe_patch: data: %w", err)
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("pe_patch: %w", err)
	}
	defer image.Close()
	offset, err := peRVAOffset(image, uint32(rva))
	if err != nil {
		return nil, fmt.Errorf("pe_patch: %w", err)
	}
	if uint64(offset) > uint64(len(data)) || uint64(len(patch)) > uint64(len(data))-uint64(offset) {
		return nil, fmt.Errorf("pe_patch: patch at RVA %#x exceeds file", rva)
	}
	copy(data[offset:], patch)
	if updateChecksum {
		if err := updatePEChecksum(data); err != nil {
			return nil, fmt.Errorf("pe_patch: %w", err)
		}
	}
	return starlark.Bytes(data), nil
}

func updatePEChecksum(data []byte) error {
	if len(data) < 0x40 {
		return fmt.Errorf("image is too short for a DOS header")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	optionalOffset := peOffset + 4 + 20
	checksumOffset := optionalOffset + 64
	if peOffset < 0 || optionalOffset < peOffset || checksumOffset+4 > len(data) {
		return fmt.Errorf("PE headers exceed the image")
	}
	if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return fmt.Errorf("invalid PE signature")
	}
	magic := binary.LittleEndian.Uint16(data[optionalOffset : optionalOffset+2])
	if magic != 0x10b && magic != 0x20b {
		return fmt.Errorf("unsupported optional-header magic %#x", magic)
	}

	binary.LittleEndian.PutUint32(data[checksumOffset:checksumOffset+4], 0)
	var sum uint64
	for offset := 0; offset < len(data); offset += 2 {
		word := uint16(data[offset])
		if offset+1 < len(data) {
			word |= uint16(data[offset+1]) << 8
		}
		sum += uint64(word)
		sum = (sum & 0xffff) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)
	sum += sum >> 16
	checksum := uint32(sum&0xffff) + uint32(len(data))
	binary.LittleEndian.PutUint32(data[checksumOffset:checksumOffset+4], checksum)
	return nil
}

func peImportsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_imports", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_imports: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	imports, err := peImports(data)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, 0, len(imports))
	for _, imp := range imports {
		dict := starlark.NewDict(4)
		if err := dict.SetKey(starlark.String("dll"), starlark.String(imp.dll)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("descriptor"), starlark.MakeInt(imp.descriptor)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("original_first_thunk"), starlark.MakeUint64(uint64(imp.originalFirstThunk))); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("first_thunk"), starlark.MakeUint64(uint64(imp.firstThunk))); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("table_rva"), starlark.MakeUint64(uint64(imp.tableRVA))); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("iat_rva"), starlark.MakeUint64(uint64(imp.iatRVA))); err != nil {
			return nil, err
		}
		if imp.name != "" {
			if err := dict.SetKey(starlark.String("name"), starlark.String(imp.name)); err != nil {
				return nil, err
			}
		}
		if imp.ordinal != 0 {
			if err := dict.SetKey(starlark.String("ordinal"), starlark.MakeInt(int(imp.ordinal))); err != nil {
				return nil, err
			}
		}
		if err := dict.SetKey(starlark.String("hint"), starlark.MakeInt(int(imp.hint))); err != nil {
			return nil, err
		}
		out = append(out, dict)
	}
	return starlark.NewList(out), nil
}

func peExportsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_exports", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_exports: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	exports, err := peExports(data)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, 0, len(exports))
	for _, exp := range exports {
		dict := starlark.NewDict(4)
		if exp.name != "" {
			if err := dict.SetKey(starlark.String("name"), starlark.String(exp.name)); err != nil {
				return nil, err
			}
		}
		if err := dict.SetKey(starlark.String("ordinal"), starlark.MakeInt(int(exp.ordinal))); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("rva"), starlark.MakeUint64(uint64(exp.rva))); err != nil {
			return nil, err
		}
		if exp.forwarder != "" {
			if err := dict.SetKey(starlark.String("forwarder"), starlark.String(exp.forwarder)); err != nil {
				return nil, err
			}
		}
		out = append(out, dict)
	}
	return starlark.NewList(out), nil
}

func peCodeViewBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_codeview", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_codeview: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	info, err := peCodeView(data)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return starlark.None, nil
	}
	out := starlark.NewDict(4)
	for key, value := range map[string]string{
		"path": info.path,
		"guid": info.guid,
		"key":  info.key,
	} {
		if err := out.SetKey(starlark.String(key), starlark.String(value)); err != nil {
			return nil, err
		}
	}
	if err := out.SetKey(starlark.String("age"), starlark.MakeUint64(uint64(info.age))); err != nil {
		return nil, err
	}
	return out, nil
}

func selfregPatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var module string
	if err := starlark.UnpackArgs("selfreg_patches", args, kwargs, "file", &value, "module", &module); err != nil {
		return nil, err
	}
	var file starfile.File
	switch value := value.(type) {
	case starfile.File:
		file = value
	case *windowsPE:
		var err error
		file, err = value.sourceFile()
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("selfreg_patches: got %s, want file or windows.pe", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	patches, err := selfregResourcePatches(data, module, nil)
	if err != nil {
		return nil, fmt.Errorf("selfreg_patches: %w", err)
	}
	out := make([]starlark.Value, 0, len(patches))
	for _, patch := range patches {
		dict := starlark.NewDict(4)
		if err := dict.SetKey(starlark.String("key"), starlark.String(patch.key)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("name"), starlark.String(patch.name)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("type"), starlark.String(patch.typ)); err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String("value"), patch.value); err != nil {
			return nil, err
		}
		out = append(out, dict)
	}
	return starlark.NewList(out), nil
}

func selfregResourcePatches(data []byte, module string, replacements map[string]string) ([]registryPatch, error) {
	resources, err := peResources(data)
	if err != nil {
		return nil, err
	}
	derived, err := rgsPEReplacements(data, resources)
	if err != nil {
		return nil, err
	}
	for name, replacement := range replacements {
		derived[name] = replacement
	}
	var patches []registryPatch
	for _, resource := range resources {
		switch strings.ToUpper(resource.typ) {
		case "REGISTRY", "WINE_REGISTRY":
		default:
			continue
		}
		parser := rgsParser{
			tokens:       rgsTokenize(decodeResourceText(resource.data)),
			module:       module,
			replacements: derived,
		}
		resourcePatches, err := parser.parse()
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", resource.typ, resource.name, err)
		}
		patches = append(patches, resourcePatches...)
	}
	return patches, nil
}

func rgsPEReplacements(data []byte, resources []peResource) (map[string]string, error) {
	stringsByID := peStringResources(resources)
	out := make(map[string]string)
	if len(stringsByID) == 0 {
		return out, nil
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	optional, ok := image.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return out, nil
	}
	for _, resource := range resources {
		if !strings.EqualFold(resource.typ, "REGISTRY") && !strings.EqualFold(resource.typ, "WINE_REGISTRY") {
			continue
		}
		for _, placeholder := range rgsPlaceholders(decodeResourceText(resource.data)) {
			if _, exists := out[placeholder]; exists {
				continue
			}
			value, ok := rgsPEReplacement(data, image, optional.ImageBase, placeholder, stringsByID)
			if ok {
				out[placeholder] = value
			}
		}
	}
	return out, nil
}

func peStringResources(resources []peResource) map[uint32]string {
	out := make(map[uint32]string)
	for _, resource := range resources {
		if resource.typ != "#6" || !strings.HasPrefix(resource.name, "#") {
			continue
		}
		block, err := strconv.ParseUint(strings.TrimPrefix(resource.name, "#"), 10, 32)
		if err != nil || block == 0 {
			continue
		}
		position := 0
		for slot := uint32(0); slot < 16 && position+2 <= len(resource.data); slot++ {
			length := int(binary.LittleEndian.Uint16(resource.data[position : position+2]))
			position += 2
			if position+length*2 > len(resource.data) {
				break
			}
			units := make([]uint16, length)
			for index := range units {
				units[index] = binary.LittleEndian.Uint16(resource.data[position+index*2 : position+index*2+2])
			}
			position += length * 2
			if text := strings.TrimRight(string(utf16.Decode(units)), "\x00"); text != "" {
				out[uint32((block-1)*16)+slot] = text
			}
		}
	}
	return out
}

func rgsPlaceholders(text string) []string {
	seen := make(map[string]bool)
	var out []string
	for {
		start := strings.IndexByte(text, '%')
		if start < 0 {
			break
		}
		text = text[start+1:]
		end := strings.IndexByte(text, '%')
		if end < 0 {
			break
		}
		name := text[:end]
		if name != "" && !strings.ContainsAny(name, `\\/ `) && !seen[strings.ToUpper(name)] {
			seen[strings.ToUpper(name)] = true
			out = append(out, name)
		}
		text = text[end+1:]
	}
	return out
}

func rgsPEReplacement(data []byte, image *pe.File, imageBase uint32, name string, stringsByID map[uint32]string) (string, bool) {
	units := append(utf16.Encode([]rune(name)), 0)
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	for search := 0; search < len(data); {
		found := bytes.Index(data[search:], encoded)
		if found < 0 {
			break
		}
		found += search
		rva, ok := peFileOffsetRVA(image, uint32(found))
		if ok {
			pointer := make([]byte, 4)
			binary.LittleEndian.PutUint32(pointer, imageBase+rva)
			for reference := 0; reference+8 <= len(data); {
				xref := bytes.Index(data[reference:], pointer)
				if xref < 0 {
					break
				}
				xref += reference
				slotRVA, ok := peFileOffsetRVA(image, uint32(xref+4))
				if ok && binary.LittleEndian.Uint32(data[xref+4:xref+8]) == 0 {
					slotVA := imageBase + slotRVA
					if resourceID, ok := rgsReplacementResourceID(data, slotVA, stringsByID); ok {
						return stringsByID[resourceID], true
					}
				}
				reference = xref + 4
			}
		}
		search = found + len(encoded)
	}
	return "", false
}

func peFileOffsetRVA(image *pe.File, offset uint32) (uint32, bool) {
	for _, section := range image.Sections {
		if offset >= section.Offset && offset < section.Offset+section.Size {
			return section.VirtualAddress + offset - section.Offset, true
		}
	}
	return 0, false
}

func rgsReplacementResourceID(data []byte, slotVA uint32, stringsByID map[uint32]string) (uint32, bool) {
	for write := 0; write+5 <= len(data); write++ {
		width := 0
		switch {
		case data[write] == 0xa3 && binary.LittleEndian.Uint32(data[write+1:write+5]) == slotVA:
			width = 5
		case write+6 <= len(data) && data[write] == 0x89 && data[write+1] == 0x05 && binary.LittleEndian.Uint32(data[write+2:write+6]) == slotVA:
			width = 6
		}
		if width == 0 {
			continue
		}
		start := max(0, write-48)
		for call := write - 5; call >= start; call-- {
			if data[call] != 0xe8 || call+5 > write {
				continue
			}
			pushStart := max(start, call-24)
			for push := call - 1; push >= pushStart; push-- {
				var resourceID uint32
				switch {
				case data[push] == 0x68 && push+5 <= call:
					resourceID = binary.LittleEndian.Uint32(data[push+1 : push+5])
				case data[push] == 0x6a && push+2 <= call:
					resourceID = uint32(data[push+1])
				default:
					continue
				}
				if _, ok := stringsByID[resourceID]; ok {
					return resourceID, true
				}
			}
		}
	}
	return 0, false
}

type registryPatch struct {
	key         string
	name        string
	typ         string
	value       starlark.Value
	addRegFlags uint32
}

type rgsParser struct {
	tokens       []string
	pos          int
	module       string
	replacements map[string]string
}

func (p *rgsParser) parse() ([]registryPatch, error) {
	var patches []registryPatch
	for !p.done() {
		root := p.next()
		if root == "" {
			break
		}
		if !p.consume("{") {
			continue
		}
		base, ok := rgsRootPath(root)
		if err := p.parseBlock(base, ok, &patches); err != nil {
			return nil, err
		}
	}
	return patches, nil
}

func (p *rgsParser) parseBlock(path string, enabled bool, patches *[]registryPatch) error {
	for !p.done() && !p.consume("}") {
		token := p.next()
		if token == "" {
			break
		}
		if strings.EqualFold(token, "NoRemove") || strings.EqualFold(token, "ForceRemove") {
			token = p.next()
		}
		token = p.expand(token)
		if strings.EqualFold(token, "Delete") || strings.EqualFold(token, "ForceRemove") || token == "" {
			continue
		}
		if strings.EqualFold(token, "val") {
			name := p.expand(p.next())
			if name == "" {
				continue
			}
			if p.consume("=") {
				patch, ok, err := p.parseValue(path, name)
				if err != nil {
					return err
				}
				if ok && enabled {
					*patches = append(*patches, patch)
				}
			}
			continue
		}

		childPath := joinRegistryPath(path, token)
		childEnabled := enabled && childPath != "" && !rgsHasPlaceholder(childPath)
		if p.consume("=") {
			patch, ok, err := p.parseValue(childPath, "(default)")
			if err != nil {
				return err
			}
			if ok && childEnabled {
				*patches = append(*patches, patch)
			}
		}
		if p.consume("{") {
			if err := p.parseBlock(childPath, childEnabled, patches); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *rgsParser) parseValue(path, name string) (registryPatch, bool, error) {
	typ := p.next()
	if typ == "" {
		return registryPatch{}, false, nil
	}
	raw := p.next()
	if raw == "" {
		return registryPatch{}, false, nil
	}
	name = p.expand(name)
	raw = p.expand(raw)
	raw = strings.ReplaceAll(raw, "%%", "%")
	if rgsHasPlaceholder(path) || rgsHasPlaceholder(name) {
		return registryPatch{}, false, nil
	}
	switch strings.ToLower(typ) {
	case "s":
		return registryPatch{key: path, name: name, typ: "REG_SZ", value: starlark.String(raw)}, true, nil
	case "e":
		return registryPatch{key: path, name: name, typ: "REG_EXPAND_SZ", value: starlark.String(raw)}, true, nil
	case "d":
		number := strings.ToLower(strings.TrimSpace(raw))
		number = strings.TrimPrefix(number, "0x")
		number = strings.TrimPrefix(number, "&h")
		u, err := strconv.ParseUint(number, 16, 32)
		if err != nil {
			if decimal, decimalErr := strconv.ParseInt(raw, 10, 32); decimalErr == nil {
				return registryPatch{key: path, name: name, typ: "REG_DWORD", value: starlark.MakeInt(int(decimal))}, true, nil
			} else {
				return registryPatch{}, false, err
			}
		}
		return registryPatch{key: path, name: name, typ: "REG_DWORD", value: starlark.MakeInt(int(int32(u)))}, true, nil
	default:
		return registryPatch{}, false, nil
	}
}

func (p *rgsParser) expand(value string) string {
	module := strings.ReplaceAll(p.module, "/", `\`)
	moduleDir := ""
	if separator := strings.LastIndex(module, `\`); separator >= 0 {
		moduleDir = module[:separator]
	}
	replacements := make(map[string]string, len(p.replacements)+4)
	for name, replacement := range p.replacements {
		replacements[strings.ToUpper(name)] = replacement
	}
	for name, replacement := range registrationModuleReplacements(module, moduleDir) {
		replacements[name] = replacement
	}
	return expandINFString(value, replacements)
}

func registrationModuleReplacements(module, moduleDir string) map[string]string {
	replacements := map[string]string{
		"MODULE":        module,
		"THISDLL":       module,
		"_SYS_MOD_PATH": module,
		"_SYS_MOD_DIR":  moduleDir,
		"SYS_MOD_PATH":  module,
		"SYS_MOD_DIR":   moduleDir,
	}
	base := path.Base(strings.ReplaceAll(module, `\`, "/"))
	token := strings.ToUpper(strings.TrimSuffix(base, path.Ext(base)))
	if token != "" {
		replacements[token] = module
	}
	return replacements
}

func registryPatchStarlarkValue(hive string, patch registryPatch) (*starlark.Dict, error) {
	out := starlark.NewDict(9)
	for field, value := range map[string]starlark.Value{
		"hive": starlark.String(hive), "key": starlark.String(patch.key),
		"name": starlark.String(patch.name), "type": starlark.String(patch.typ), "value": patch.value,
	} {
		if err := out.SetKey(starlark.String(field), value); err != nil {
			return nil, err
		}
	}
	if err := setAddRegBehaviorFields(out, patch.addRegFlags); err != nil {
		return nil, err
	}
	return out, nil
}

func rgsHasPlaceholder(value string) bool {
	for start := strings.IndexByte(value, '%'); start >= 0; {
		value = value[start+1:]
		end := strings.IndexByte(value, '%')
		if end < 0 {
			return false
		}
		name := value[:end]
		if name != "" && !strings.ContainsAny(name, `\\/ `) {
			return true
		}
		value = value[end+1:]
		start = strings.IndexByte(value, '%')
	}
	return false
}

func (p *rgsParser) done() bool {
	return p.pos >= len(p.tokens)
}

func (p *rgsParser) next() string {
	if p.done() {
		return ""
	}
	token := p.tokens[p.pos]
	p.pos++
	return token
}

func (p *rgsParser) consume(token string) bool {
	if p.done() || p.tokens[p.pos] != token {
		return false
	}
	p.pos++
	return true
}

func rgsRootPath(root string) (string, bool) {
	switch strings.ToUpper(root) {
	case "HKCR", "HKEY_CLASSES_ROOT":
		return "/Classes", true
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return "", true
	case "HKCU", "HKEY_CURRENT_USER", "HKU", "HKEY_USERS":
		return "", false
	default:
		return "", false
	}
}

func joinRegistryPath(base, child string) string {
	child = strings.Trim(child, "\\/")
	if child == "" {
		return base
	}
	if strings.EqualFold(base, "") {
		if strings.EqualFold(child, "Software") {
			return ""
		}
		if rest, ok := strings.CutPrefix(child, "Software\\"); ok {
			return "/" + strings.ReplaceAll(rest, "\\", "/")
		}
		return "/" + strings.ReplaceAll(child, "\\", "/")
	}
	return strings.TrimRight(base, "/") + "/" + strings.ReplaceAll(child, "\\", "/")
}

func rgsTokenize(input string) []string {
	var tokens []string
	for i := 0; i < len(input); {
		r, size := utf8Rune(input, i)
		if unicode.IsSpace(r) {
			i += size
			continue
		}
		if r == ';' {
			for i < len(input) && input[i] != '\n' && input[i] != '\r' {
				i++
			}
			continue
		}
		if r == '\'' || r == '"' {
			token, next := readQuotedRGS(input, i, byte(r))
			tokens = append(tokens, token)
			i = next
			continue
		}
		if r == '=' || r == '}' {
			tokens = append(tokens, string(r))
			i += size
			continue
		}
		if r == '{' {
			if token, next, ok := readGuidToken(input, i); ok {
				tokens = append(tokens, token)
				i = next
			} else {
				tokens = append(tokens, "{")
				i += size
			}
			continue
		}
		start := i
		for i < len(input) {
			r, size = utf8Rune(input, i)
			if unicode.IsSpace(r) || r == '{' || r == '}' || r == '=' || r == '\'' || r == '"' || r == ';' {
				break
			}
			i += size
		}
		tokens = append(tokens, input[start:i])
	}
	return tokens
}

func utf8Rune(input string, off int) (rune, int) {
	r := rune(input[off])
	if r < 0x80 {
		return r, 1
	}
	return utf8.DecodeRuneInString(input[off:])
}

func readQuotedRGS(input string, off int, quote byte) (string, int) {
	var out strings.Builder
	for i := off + 1; i < len(input); i++ {
		if input[i] == quote {
			if i+1 < len(input) && input[i+1] == quote {
				out.WriteByte(quote)
				i++
				continue
			}
			return out.String(), i + 1
		}
		out.WriteByte(input[i])
	}
	return out.String(), len(input)
}

func readGuidToken(input string, off int) (string, int, bool) {
	if off+1 >= len(input) || unicode.IsSpace(rune(input[off+1])) {
		return "", off, false
	}
	end := strings.IndexByte(input[off:], '}')
	if end < 0 {
		return "", off, false
	}
	end += off
	token := input[off : end+1]
	if len(token) >= 3 && strings.Contains(token, "-") && !strings.ContainsAny(token[1:len(token)-1], "{}\r\n\t ") {
		return token, end + 1, true
	}
	return "", off, false
}

type peResource struct {
	typ  string
	name string
	lang string
	data []byte
}

type peMessage struct {
	id      uint32
	lang    string
	text    string
	unicode bool
}

type peImport struct {
	dll                string
	name               string
	ordinal            uint16
	hint               uint16
	descriptor         int
	originalFirstThunk uint32
	firstThunk         uint32
	tableRVA           uint32
	iatRVA             uint32
}

type peExport struct {
	name      string
	ordinal   uint32
	rva       uint32
	forwarder string
}

type peCodeViewInfo struct {
	path string
	guid string
	key  string
	age  uint32
}

func peCodeView(data []byte) (*peCodeViewInfo, error) {
	pf, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	const imageDirectoryEntryDebug = 6
	debugRVA, debugSize, _, err := peDataDirectory(pf, imageDirectoryEntryDebug)
	if err != nil {
		return nil, fmt.Errorf("pe_codeview: %w", err)
	}
	if debugRVA == 0 || debugSize == 0 {
		return nil, nil
	}
	debugOffset, err := peRVAOffset(pf, debugRVA)
	if err != nil {
		return nil, fmt.Errorf("pe_codeview: %w", err)
	}
	const imageDebugDirectorySize = 28
	if debugOffset > uint32(len(data)) || debugSize > uint32(len(data))-debugOffset {
		return nil, fmt.Errorf("pe_codeview: debug directory outside file")
	}
	for off := debugOffset; off+imageDebugDirectorySize <= debugOffset+debugSize; off += imageDebugDirectorySize {
		entry := data[off : off+imageDebugDirectorySize]
		if binary.LittleEndian.Uint32(entry[12:16]) != 2 { // IMAGE_DEBUG_TYPE_CODEVIEW
			continue
		}
		size := binary.LittleEndian.Uint32(entry[16:20])
		rawOffset := binary.LittleEndian.Uint32(entry[24:28])
		if rawOffset > uint32(len(data)) || size > uint32(len(data))-rawOffset {
			return nil, fmt.Errorf("pe_codeview: CodeView record outside file")
		}
		info, err := parseCodeViewRecord(data[rawOffset : rawOffset+size])
		if err != nil {
			return nil, fmt.Errorf("pe_codeview: %w", err)
		}
		if info != nil {
			return info, nil
		}
	}
	return nil, nil
}

func parseCodeViewRecord(data []byte) (*peCodeViewInfo, error) {
	if len(data) < 4 || !bytes.Equal(data[:4], []byte("RSDS")) {
		return nil, nil
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("short RSDS record")
	}
	g := data[4:20]
	guid := fmt.Sprintf(
		"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
	)
	age := binary.LittleEndian.Uint32(data[20:24])
	pathBytes := data[24:]
	if nul := bytes.IndexByte(pathBytes, 0); nul >= 0 {
		pathBytes = pathBytes[:nul]
	}
	key := strings.ReplaceAll(guid, "-", "") + strings.ToUpper(strconv.FormatUint(uint64(age), 16))
	return &peCodeViewInfo{path: string(pathBytes), guid: guid, key: key, age: age}, nil
}

func peImports(data []byte) ([]peImport, error) {
	pf, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	importRVA, importSize, is64, err := peDataDirectory(pf, pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
	if err != nil {
		return nil, fmt.Errorf("pe_imports: %w", err)
	}
	if importRVA == 0 || importSize == 0 {
		return nil, nil
	}
	importOffset, err := peRVAOffset(pf, importRVA)
	if err != nil {
		return nil, fmt.Errorf("pe_imports: %w", err)
	}
	var out []peImport
	for descriptor := 0; ; descriptor++ {
		descOff := importOffset + uint32(descriptor*20)
		if descOff+20 > uint32(len(data)) {
			return nil, fmt.Errorf("pe_imports: import descriptor outside file")
		}
		originalFirstThunk := binary.LittleEndian.Uint32(data[descOff : descOff+4])
		nameRVA := binary.LittleEndian.Uint32(data[descOff+12 : descOff+16])
		firstThunk := binary.LittleEndian.Uint32(data[descOff+16 : descOff+20])
		if originalFirstThunk == 0 && nameRVA == 0 && firstThunk == 0 {
			break
		}
		dll, err := peCString(data, pf, nameRVA)
		if err != nil {
			return nil, fmt.Errorf("pe_imports: DLL name: %w", err)
		}
		thunkRVA := originalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}
		thunkOff, err := peRVAOffset(pf, thunkRVA)
		if err != nil {
			return nil, fmt.Errorf("pe_imports: thunk table: %w", err)
		}
		for index := uint32(0); ; index++ {
			tableEntryRVA, iatRVA := peImportEntryRVAs(thunkRVA, firstThunk, index, is64)
			if is64 {
				if thunkOff+8 > uint32(len(data)) {
					return nil, fmt.Errorf("pe_imports: thunk outside file")
				}
				thunk := binary.LittleEndian.Uint64(data[thunkOff : thunkOff+8])
				thunkOff += 8
				if thunk == 0 {
					break
				}
				if thunk&0x8000000000000000 != 0 {
					out = append(out, peImport{dll: dll, ordinal: uint16(thunk), descriptor: descriptor, originalFirstThunk: originalFirstThunk, firstThunk: firstThunk, tableRVA: tableEntryRVA, iatRVA: iatRVA})
					continue
				}
				imp, err := peImportByName(data, pf, uint32(thunk))
				if err != nil {
					return nil, err
				}
				imp.dll = dll
				imp.descriptor = descriptor
				imp.originalFirstThunk = originalFirstThunk
				imp.firstThunk = firstThunk
				imp.tableRVA = tableEntryRVA
				imp.iatRVA = iatRVA
				out = append(out, imp)
			} else {
				if thunkOff+4 > uint32(len(data)) {
					return nil, fmt.Errorf("pe_imports: thunk outside file")
				}
				thunk := binary.LittleEndian.Uint32(data[thunkOff : thunkOff+4])
				thunkOff += 4
				if thunk == 0 {
					break
				}
				if thunk&0x80000000 != 0 {
					out = append(out, peImport{dll: dll, ordinal: uint16(thunk), descriptor: descriptor, originalFirstThunk: originalFirstThunk, firstThunk: firstThunk, tableRVA: tableEntryRVA, iatRVA: iatRVA})
					continue
				}
				imp, err := peImportByName(data, pf, thunk)
				if err != nil {
					return nil, err
				}
				imp.dll = dll
				imp.descriptor = descriptor
				imp.originalFirstThunk = originalFirstThunk
				imp.firstThunk = firstThunk
				imp.tableRVA = tableEntryRVA
				imp.iatRVA = iatRVA
				out = append(out, imp)
			}
		}
	}
	return out, nil
}

func peImportEntryRVAs(tableRVA, firstThunk, index uint32, is64 bool) (uint32, uint32) {
	width := uint32(4)
	if is64 {
		width = 8
	}
	offset := index * width
	return tableRVA + offset, firstThunk + offset
}

func peExports(data []byte) ([]peExport, error) {
	pf, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	exportRVA, exportSize, _, err := peDataDirectory(pf, pe.IMAGE_DIRECTORY_ENTRY_EXPORT)
	if err != nil {
		return nil, fmt.Errorf("pe_exports: %w", err)
	}
	if exportRVA == 0 || exportSize == 0 {
		return nil, nil
	}
	exportOffset, err := peRVAOffset(pf, exportRVA)
	if err != nil {
		return nil, fmt.Errorf("pe_exports: %w", err)
	}
	if exportOffset+40 > uint32(len(data)) {
		return nil, fmt.Errorf("pe_exports: export directory outside file")
	}
	base := binary.LittleEndian.Uint32(data[exportOffset+16 : exportOffset+20])
	functionCount := binary.LittleEndian.Uint32(data[exportOffset+20 : exportOffset+24])
	nameCount := binary.LittleEndian.Uint32(data[exportOffset+24 : exportOffset+28])
	functionsRVA := binary.LittleEndian.Uint32(data[exportOffset+28 : exportOffset+32])
	namesRVA := binary.LittleEndian.Uint32(data[exportOffset+32 : exportOffset+36])
	ordinalsRVA := binary.LittleEndian.Uint32(data[exportOffset+36 : exportOffset+40])

	functionsOff, err := peRVAOffset(pf, functionsRVA)
	if err != nil {
		return nil, fmt.Errorf("pe_exports: export address table: %w", err)
	}
	if functionsOff+functionCount*4 > uint32(len(data)) {
		return nil, fmt.Errorf("pe_exports: export address table outside file")
	}
	namesByIndex := make(map[uint32]string)
	if nameCount > 0 {
		namesOff, err := peRVAOffset(pf, namesRVA)
		if err != nil {
			return nil, fmt.Errorf("pe_exports: export name table: %w", err)
		}
		ordinalsOff, err := peRVAOffset(pf, ordinalsRVA)
		if err != nil {
			return nil, fmt.Errorf("pe_exports: export ordinal table: %w", err)
		}
		if namesOff+nameCount*4 > uint32(len(data)) || ordinalsOff+nameCount*2 > uint32(len(data)) {
			return nil, fmt.Errorf("pe_exports: export name table outside file")
		}
		for i := uint32(0); i < nameCount; i++ {
			nameRVA := binary.LittleEndian.Uint32(data[namesOff+i*4 : namesOff+i*4+4])
			name, err := peCString(data, pf, nameRVA)
			if err != nil {
				return nil, fmt.Errorf("pe_exports: export name: %w", err)
			}
			index := uint32(binary.LittleEndian.Uint16(data[ordinalsOff+i*2 : ordinalsOff+i*2+2]))
			namesByIndex[index] = name
		}
	}

	out := make([]peExport, 0, functionCount)
	for i := uint32(0); i < functionCount; i++ {
		rva := binary.LittleEndian.Uint32(data[functionsOff+i*4 : functionsOff+i*4+4])
		if rva == 0 {
			continue
		}
		exp := peExport{name: namesByIndex[i], ordinal: base + i, rva: rva}
		if rva >= exportRVA && rva < exportRVA+exportSize {
			forwarder, err := peCString(data, pf, rva)
			if err != nil {
				return nil, fmt.Errorf("pe_exports: forwarder: %w", err)
			}
			exp.forwarder = forwarder
		}
		out = append(out, exp)
	}
	return out, nil
}

func peDataDirectory(file *pe.File, index int) (uint32, uint32, bool, error) {
	switch optional := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if index >= len(optional.DataDirectory) {
			return 0, 0, false, fmt.Errorf("data directory %d unavailable", index)
		}
		dir := optional.DataDirectory[index]
		return dir.VirtualAddress, dir.Size, false, nil
	case *pe.OptionalHeader64:
		if index >= len(optional.DataDirectory) {
			return 0, 0, true, fmt.Errorf("data directory %d unavailable", index)
		}
		dir := optional.DataDirectory[index]
		return dir.VirtualAddress, dir.Size, true, nil
	default:
		return 0, 0, false, fmt.Errorf("unsupported optional header")
	}
}

func peImportByName(data []byte, file *pe.File, rva uint32) (peImport, error) {
	off, err := peRVAOffset(file, rva)
	if err != nil {
		return peImport{}, fmt.Errorf("pe_imports: import by name: %w", err)
	}
	if off+2 > uint32(len(data)) {
		return peImport{}, fmt.Errorf("pe_imports: import by name outside file")
	}
	name, err := peCStringAt(data, off+2)
	if err != nil {
		return peImport{}, fmt.Errorf("pe_imports: import name: %w", err)
	}
	return peImport{hint: binary.LittleEndian.Uint16(data[off : off+2]), name: name}, nil
}

func peCString(data []byte, file *pe.File, rva uint32) (string, error) {
	off, err := peRVAOffset(file, rva)
	if err != nil {
		return "", err
	}
	return peCStringAt(data, off)
}

func peCStringAt(data []byte, off uint32) (string, error) {
	if off >= uint32(len(data)) {
		return "", fmt.Errorf("string outside file")
	}
	end := off
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}
	if end >= uint32(len(data)) {
		return "", fmt.Errorf("unterminated string")
	}
	return string(data[off:end]), nil
}

func peResources(data []byte) ([]peResource, error) {
	pf, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	var resourceRVA, resourceSize uint32
	switch optional := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		resourceRVA = optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
		resourceSize = optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].Size
	case *pe.OptionalHeader64:
		resourceRVA = optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
		resourceSize = optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].Size
	default:
		return nil, fmt.Errorf("pe_resources: unsupported optional header")
	}
	if resourceRVA == 0 || resourceSize == 0 {
		return nil, nil
	}

	resourceOffset, err := peRVAOffset(pf, resourceRVA)
	if err != nil {
		return nil, err
	}
	if resourceOffset > uint32(len(data)) || resourceOffset+resourceSize > uint32(len(data)) {
		return nil, fmt.Errorf("pe_resources: resource directory outside file")
	}

	reader := peResourceReader{file: data, pe: pf, baseRVA: resourceRVA, baseOffset: resourceOffset}
	var out []peResource
	if err := reader.walkDirectory(0, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type peResourceReader struct {
	file       []byte
	pe         *pe.File
	baseRVA    uint32
	baseOffset uint32
}

func (r peResourceReader) walkDirectory(dirRel uint32, path []string, out *[]peResource) error {
	dirOff := r.baseOffset + dirRel
	if dirOff+16 > uint32(len(r.file)) {
		return fmt.Errorf("pe_resources: resource directory outside file")
	}
	named := binary.LittleEndian.Uint16(r.file[dirOff+12 : dirOff+14])
	ids := binary.LittleEndian.Uint16(r.file[dirOff+14 : dirOff+16])
	count := int(named + ids)
	entryOff := dirOff + 16
	if entryOff+uint32(count*8) > uint32(len(r.file)) {
		return fmt.Errorf("pe_resources: resource entries outside file")
	}
	for i := 0; i < count; i++ {
		off := entryOff + uint32(i*8)
		nameRaw := binary.LittleEndian.Uint32(r.file[off : off+4])
		childRaw := binary.LittleEndian.Uint32(r.file[off+4 : off+8])
		name, err := r.resourceName(nameRaw)
		if err != nil {
			return err
		}
		childRel := childRaw & 0x7fffffff
		nextPath := append(append([]string(nil), path...), name)
		if childRaw&0x80000000 != 0 {
			if err := r.walkDirectory(childRel, nextPath, out); err != nil {
				return err
			}
			continue
		}
		dataEntryOff := r.baseOffset + childRel
		if dataEntryOff+16 > uint32(len(r.file)) {
			return fmt.Errorf("pe_resources: resource data entry outside file")
		}
		dataRVA := binary.LittleEndian.Uint32(r.file[dataEntryOff : dataEntryOff+4])
		size := binary.LittleEndian.Uint32(r.file[dataEntryOff+4 : dataEntryOff+8])
		dataOff, err := peRVAOffset(r.pe, dataRVA)
		if err != nil {
			return err
		}
		if dataOff > uint32(len(r.file)) || dataOff+size > uint32(len(r.file)) {
			return fmt.Errorf("pe_resources: resource data outside file")
		}
		typ, name, lang := "", "", ""
		if len(nextPath) > 0 {
			typ = nextPath[0]
		}
		if len(nextPath) > 1 {
			name = nextPath[1]
		}
		if len(nextPath) > 2 {
			lang = nextPath[2]
		}
		data := make([]byte, size)
		copy(data, r.file[dataOff:dataOff+size])
		*out = append(*out, peResource{typ: typ, name: name, lang: lang, data: data})
	}
	return nil
}

func (r peResourceReader) resourceName(raw uint32) (string, error) {
	if raw&0x80000000 == 0 {
		return fmt.Sprintf("#%d", raw), nil
	}
	nameRel := raw & 0x7fffffff
	nameOff := r.baseOffset + nameRel
	if nameOff+2 > uint32(len(r.file)) {
		return "", fmt.Errorf("pe_resources: resource name outside file")
	}
	chars := int(binary.LittleEndian.Uint16(r.file[nameOff : nameOff+2]))
	nameOff += 2
	if nameOff+uint32(chars*2) > uint32(len(r.file)) {
		return "", fmt.Errorf("pe_resources: resource name outside file")
	}
	units := make([]uint16, chars)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(r.file[nameOff+uint32(i*2) : nameOff+uint32(i*2+2)])
	}
	return string(utf16.Decode(units)), nil
}

func peRVAOffset(file *pe.File, rva uint32) (uint32, error) {
	for _, section := range file.Sections {
		start := section.VirtualAddress
		size := section.VirtualSize
		if size < section.Size {
			size = section.Size
		}
		if rva >= start && rva < start+size {
			return section.Offset + (rva - start), nil
		}
	}
	return 0, fmt.Errorf("pe_resources: RVA %#x not mapped", rva)
}

func decodeResourceText(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		return decodeUTF16LE(data[2:])
	case len(data) >= 2 && data[1] == 0:
		return decodeUTF16LE(data)
	default:
		return string(data)
	}
}

func peMessageResources(resources []peResource) ([]peMessage, error) {
	var out []peMessage
	for _, resource := range resources {
		if resource.typ != "#11" {
			continue
		}
		data := resource.data
		if len(data) < 4 {
			return nil, fmt.Errorf("pe_messages: truncated message table header")
		}
		blockCount := binary.LittleEndian.Uint32(data[:4])
		if blockCount > uint32((len(data)-4)/12) {
			return nil, fmt.Errorf("pe_messages: message block table outside resource")
		}
		for blockIndex := uint32(0); blockIndex < blockCount; blockIndex++ {
			blockOffset := 4 + blockIndex*12
			lowID := binary.LittleEndian.Uint32(data[blockOffset : blockOffset+4])
			highID := binary.LittleEndian.Uint32(data[blockOffset+4 : blockOffset+8])
			entryOffset := binary.LittleEndian.Uint32(data[blockOffset+8 : blockOffset+12])
			if highID < lowID || uint64(highID)-uint64(lowID)+1 > uint64(len(data))/4 {
				return nil, fmt.Errorf("pe_messages: invalid message ID range %#x-%#x", lowID, highID)
			}
			for id := uint64(lowID); id <= uint64(highID); id++ {
				if entryOffset > uint32(len(data)) || len(data)-int(entryOffset) < 4 {
					return nil, fmt.Errorf("pe_messages: message entry outside resource")
				}
				length := uint32(binary.LittleEndian.Uint16(data[entryOffset : entryOffset+2]))
				flags := binary.LittleEndian.Uint16(data[entryOffset+2 : entryOffset+4])
				if length < 4 || length > uint32(len(data))-entryOffset {
					return nil, fmt.Errorf("pe_messages: invalid message entry length %d", length)
				}
				payload := data[entryOffset+4 : entryOffset+length]
				isUnicode := flags&1 != 0
				var text string
				if isUnicode {
					if len(payload)%2 != 0 {
						return nil, fmt.Errorf("pe_messages: odd UTF-16 message length")
					}
					text = decodeUTF16LE(payload)
				} else {
					text = string(payload)
				}
				text = strings.TrimRight(text, "\x00")
				out = append(out, peMessage{id: uint32(id), lang: resource.lang, text: text, unicode: isUnicode})
				entryOffset += length
			}
		}
	}
	return out, nil
}
