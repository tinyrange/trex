package windows

import (
	"encoding/binary"
	"fmt"
	"sort"

	"go.starlark.net/starlark"
)

const defaultPE32ImageBase = uint32(0x00400000)

type pe32Fixup struct {
	offset int
	label  string
	kind   string
}

type pe32SectionImage struct {
	section   []byte
	labels    map[string]int
	fixups    []pe32Fixup
	imageBase uint32
}

// pe32ExecutableBuiltin links one labeled, in-memory section into a minimal
// PE32 executable. Instruction generation and platform policy remain with the
// caller; this primitive owns PE headers, imports, RVAs, and fixup bounds.
func pe32ExecutableBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sectionValue starlark.Value
	var labelsValue, importsValue *starlark.Dict
	var fixupsValue *starlark.List
	entry := "entry"
	imageBase := uint64(defaultPE32ImageBase)
	if err := starlark.UnpackArgs("pe32_executable", args, kwargs,
		"section", &sectionValue, "labels", &labelsValue, "fixups", &fixupsValue,
		"imports?", &importsValue, "entry?", &entry, "image_base?", &imageBase,
	); err != nil {
		return nil, err
	}
	if imageBase > uint64(^uint32(0)) {
		return nil, fmt.Errorf("pe32_executable: image_base exceeds 32 bits")
	}
	section, err := bytesForBinaryValue(sectionValue)
	if err != nil {
		return nil, fmt.Errorf("pe32_executable: section: %w", err)
	}
	image := &pe32SectionImage{section: append([]byte(nil), section...), labels: make(map[string]int), imageBase: uint32(imageBase)}
	for _, item := range labelsValue.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("pe32_executable: label name is %s, want string", item[0].Type())
		}
		offset, err := starlark.AsInt32(item[1])
		if err != nil || offset < 0 || int(offset) > len(image.section) {
			return nil, fmt.Errorf("pe32_executable: label %q has invalid offset", name)
		}
		image.labels[name] = int(offset)
	}
	for index := 0; index < fixupsValue.Len(); index++ {
		record, ok := fixupsValue.Index(index).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("pe32_executable: fixups[%d] is %s, want dict", index, fixupsValue.Index(index).Type())
		}
		offset, err := requiredDictInt(record, "offset")
		if err != nil || offset < 0 || offset+4 > len(image.section) {
			return nil, fmt.Errorf("pe32_executable: fixups[%d] has invalid offset", index)
		}
		label, err := requiredDictString(record, "label")
		if err != nil {
			return nil, fmt.Errorf("pe32_executable: fixups[%d]: %w", index, err)
		}
		kind := "address"
		if value, found, err := record.Get(starlark.String("kind")); err != nil {
			return nil, err
		} else if found {
			kind, ok = starlark.AsString(value)
			if !ok {
				return nil, fmt.Errorf("pe32_executable: fixups[%d] kind is %s, want string", index, value.Type())
			}
		}
		if kind != "address" && kind != "rva" && kind != "relative" {
			return nil, fmt.Errorf("pe32_executable: fixups[%d] has invalid kind %q", index, kind)
		}
		image.fixups = append(image.fixups, pe32Fixup{offset: offset, label: label, kind: kind})
	}
	imports, err := starlarkStringLists(importsValue, "pe32_executable: imports")
	if err != nil {
		return nil, err
	}
	importRVA, importSize, iatRVA, iatSize := image.addImports(imports)
	relocationRVA, relocationSize := image.addRelocations()
	if _, ok := image.labels[entry]; !ok {
		return nil, fmt.Errorf("pe32_executable: unresolved entry label %q", entry)
	}
	if err := image.resolve(); err != nil {
		return nil, fmt.Errorf("pe32_executable: %w", err)
	}
	return starlark.Bytes(image.peImage(entry, importRVA, importSize, iatRVA, iatSize, relocationRVA, relocationSize)), nil
}

func requiredDictInt(dict *starlark.Dict, name string) (int, error) {
	value, found, err := dict.Get(starlark.String(name))
	if err != nil || !found {
		return 0, fmt.Errorf("missing %s", name)
	}
	integer, err := starlark.AsInt32(value)
	return int(integer), err
}

func requiredDictString(dict *starlark.Dict, name string) (string, error) {
	value, found, err := dict.Get(starlark.String(name))
	if err != nil || !found {
		return "", fmt.Errorf("missing %s", name)
	}
	text, ok := starlark.AsString(value)
	if !ok {
		return "", fmt.Errorf("%s is %s, want string", name, value.Type())
	}
	return text, nil
}

func starlarkStringLists(dict *starlark.Dict, context string) (map[string][]string, error) {
	output := make(map[string][]string)
	if dict == nil {
		return output, nil
	}
	for _, item := range dict.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("%s key is %s, want string", context, item[0].Type())
		}
		iterable, ok := item[1].(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("%s[%q] is %s, want iterable", context, name, item[1].Type())
		}
		iterator := iterable.Iterate()
		var value starlark.Value
		for iterator.Next(&value) {
			text, ok := starlark.AsString(value)
			if !ok {
				iterator.Done()
				return nil, fmt.Errorf("%s[%q] item is %s, want string", context, name, value.Type())
			}
			output[name] = append(output[name], text)
		}
		iterator.Done()
	}
	return output, nil
}

func (image *pe32SectionImage) align(value int) {
	for len(image.section)%value != 0 {
		image.section = append(image.section, 0)
	}
}

func (image *pe32SectionImage) dword(value uint32) {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	image.section = append(image.section, raw[:]...)
}

func (image *pe32SectionImage) rva(label string) {
	image.fixups = append(image.fixups, pe32Fixup{offset: len(image.section), label: label, kind: "rva"})
	image.dword(0)
}

func (image *pe32SectionImage) addImports(imports map[string][]string) (uint32, uint32, uint32, uint32) {
	if len(imports) == 0 {
		return 0, 0, 0, 0
	}
	image.align(4)
	start := len(image.section)
	dlls := make([]string, 0, len(imports))
	for dll := range imports {
		dlls = append(dlls, dll)
	}
	sort.Strings(dlls)
	descriptors := make(map[string]int, len(dlls))
	for _, dll := range dlls {
		descriptors[dll] = len(image.section)
		image.section = append(image.section, make([]byte, 20)...)
	}
	image.section = append(image.section, make([]byte, 20)...)
	firstIAT := -1
	for _, dll := range dlls {
		functions := imports[dll]
		image.align(4)
		lookup := len(image.section)
		for _, name := range functions {
			image.rva("hint:" + dll + ":" + name)
		}
		image.dword(0)
		image.align(4)
		iat := len(image.section)
		if firstIAT < 0 {
			firstIAT = iat
		}
		for _, name := range functions {
			image.labels["iat:"+dll+":"+name] = len(image.section)
			image.rva("hint:" + dll + ":" + name)
		}
		image.dword(0)
		image.labels["dll:"+dll] = len(image.section)
		image.section = append(image.section, []byte(dll+"\x00")...)
		for _, name := range functions {
			image.align(2)
			image.labels["hint:"+dll+":"+name] = len(image.section)
			image.section = append(image.section, 0, 0)
			image.section = append(image.section, []byte(name+"\x00")...)
		}
		descriptor := descriptors[dll]
		binary.LittleEndian.PutUint32(image.section[descriptor:descriptor+4], uint32(0x1000+lookup))
		image.fixups = append(image.fixups, pe32Fixup{offset: descriptor + 12, label: "dll:" + dll, kind: "rva"})
		binary.LittleEndian.PutUint32(image.section[descriptor+16:descriptor+20], uint32(0x1000+iat))
	}
	end := len(image.section)
	return uint32(0x1000 + start), uint32(end - start), uint32(0x1000 + firstIAT), uint32(end - firstIAT)
}

func (image *pe32SectionImage) addRelocations() (uint32, uint32) {
	pages := make(map[uint32][]uint16)
	for _, fixup := range image.fixups {
		if fixup.kind != "address" {
			continue
		}
		rva := uint32(0x1000 + fixup.offset)
		page := rva &^ 0x0fff
		pages[page] = append(pages[page], uint16(3<<12)|(uint16(rva)&0x0fff))
	}
	if len(pages) == 0 {
		return 0, 0
	}
	image.align(4)
	start := len(image.section)
	ordered := make([]uint32, 0, len(pages))
	for page := range pages {
		ordered = append(ordered, page)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, page := range ordered {
		entries := pages[page]
		sort.Slice(entries, func(i, j int) bool { return entries[i] < entries[j] })
		if len(entries)%2 != 0 {
			entries = append(entries, 0)
		}
		image.dword(page)
		image.dword(uint32(8 + len(entries)*2))
		for _, entry := range entries {
			image.section = append(image.section, byte(entry), byte(entry>>8))
		}
	}
	return uint32(0x1000 + start), uint32(len(image.section) - start)
}

func (image *pe32SectionImage) resolve() error {
	for _, fixup := range image.fixups {
		target, ok := image.labels[fixup.label]
		if !ok {
			return fmt.Errorf("unresolved label %q", fixup.label)
		}
		var value uint32
		switch fixup.kind {
		case "rva":
			value = 0x1000 + uint32(target)
		case "relative":
			value = uint32(int64(target) - int64(fixup.offset+4))
		default:
			value = image.imageBase + 0x1000 + uint32(target)
		}
		binary.LittleEndian.PutUint32(image.section[fixup.offset:fixup.offset+4], value)
	}
	return nil
}

func (image *pe32SectionImage) peImage(entry string, importRVA, importSize, iatRVA, iatSize, relocationRVA, relocationSize uint32) []byte {
	const fileAlignment = 0x200
	rawSize := (len(image.section) + fileAlignment - 1) &^ (fileAlignment - 1)
	out := make([]byte, 0x200+rawSize)
	out[0], out[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(out[0x3c:0x40], 0x80)
	copy(out[0x80:], "PE\x00\x00")
	file := out[0x84:]
	binary.LittleEndian.PutUint16(file[0:2], 0x14c)
	binary.LittleEndian.PutUint16(file[2:4], 1)
	binary.LittleEndian.PutUint16(file[16:18], 0xe0)
	binary.LittleEndian.PutUint16(file[18:20], 0x0102)
	optional := file[20:]
	binary.LittleEndian.PutUint16(optional[0:2], 0x10b)
	optional[2], optional[3] = 7, 10
	binary.LittleEndian.PutUint32(optional[4:8], uint32(rawSize))
	binary.LittleEndian.PutUint32(optional[16:20], uint32(0x1000+image.labels[entry]))
	binary.LittleEndian.PutUint32(optional[20:24], 0x1000)
	binary.LittleEndian.PutUint32(optional[24:28], 0x1000)
	binary.LittleEndian.PutUint32(optional[28:32], image.imageBase)
	binary.LittleEndian.PutUint32(optional[32:36], 0x1000)
	binary.LittleEndian.PutUint32(optional[36:40], fileAlignment)
	binary.LittleEndian.PutUint16(optional[40:42], 5)
	binary.LittleEndian.PutUint16(optional[48:50], 5)
	binary.LittleEndian.PutUint32(optional[56:60], uint32(0x1000+((len(image.section)+0xfff)&^0xfff)))
	binary.LittleEndian.PutUint32(optional[60:64], 0x200)
	binary.LittleEndian.PutUint16(optional[68:70], 3)
	binary.LittleEndian.PutUint32(optional[72:76], 0x100000)
	binary.LittleEndian.PutUint32(optional[76:80], 0x1000)
	binary.LittleEndian.PutUint32(optional[80:84], 0x100000)
	binary.LittleEndian.PutUint32(optional[84:88], 0x1000)
	binary.LittleEndian.PutUint32(optional[92:96], 16)
	binary.LittleEndian.PutUint32(optional[104:108], importRVA)
	binary.LittleEndian.PutUint32(optional[108:112], importSize)
	binary.LittleEndian.PutUint32(optional[136:140], relocationRVA)
	binary.LittleEndian.PutUint32(optional[140:144], relocationSize)
	binary.LittleEndian.PutUint32(optional[192:196], iatRVA)
	binary.LittleEndian.PutUint32(optional[196:200], iatSize)
	section := optional[224:]
	copy(section[0:8], ".text")
	binary.LittleEndian.PutUint32(section[8:12], uint32(len(image.section)))
	binary.LittleEndian.PutUint32(section[12:16], 0x1000)
	binary.LittleEndian.PutUint32(section[16:20], uint32(rawSize))
	binary.LittleEndian.PutUint32(section[20:24], 0x200)
	binary.LittleEndian.PutUint32(section[36:40], 0xe0000060)
	copy(out[0x200:], image.section)
	return out
}
