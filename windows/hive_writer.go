package windows

import (
	"encoding/binary"
	"errors"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash/crc32"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/tinyrange/trex/storage"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

func windowsFiletime(value time.Time) int64   { return storage.WindowsFiletime(value) }
func align8(value int) int                    { return int(storage.Align(int64(value), 8)) }
func alignInt64(value, alignment int64) int64 { return storage.Align(value, alignment) }
func utf16Bytes(value string) []byte {
	units := utf16.Encode([]rune(value))
	data := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(data[index*2:], unit)
	}
	return data
}

var errRegistryFreeCell = errors.New("registry free cell")

const (
	registrySubkeyLeafEntries  = (hiveBaseBlockSize - 0x20 - 8) / 8
	registrySubkeyIndexEntries = (hiveBaseBlockSize - 0x20 - 8) / 4

	regNone                     = 0
	regSZ                       = 1
	regExpandSZ                 = 2
	regBinary                   = 3
	regDWORD                    = 4
	regDWORDBigEndian           = 5
	regLink                     = 6
	regMultiSZ                  = 7
	regResourceList             = 8
	regFullResourceDescriptor   = 9
	regResourceRequirementsList = 10
	regQWord                    = 11

	infAddRegNoClobber     = uint32(0x00000002)
	infAddRegDeleteValue   = uint32(0x00000004)
	infAddRegAppend        = uint32(0x00000008)
	infAddRegKeyOnly       = uint32(0x00000010)
	infAddRegOverwriteOnly = uint32(0x00000020)
)

type registryTree struct {
	name     string
	subkeys  map[string]*registryTree
	values   map[string]registryData
	flags    uint16
	flagsSet bool
	class    []byte
	security []byte
	cell     uint32
	parent   uint32
	listCell uint32
	valCell  uint32
}

type registryData struct {
	typ  uint32
	data []byte
}

type hiveWriter struct {
	data          []byte
	securityCells map[string]uint32
	format        registryHiveFormat
	binStart      int
	binEnd        int
	cellOffset    int
}

type registryHiveFormat struct {
	major uint32
	minor uint32
}

var defaultRegistryHiveFormat = registryHiveFormat{major: 1, minor: 5}

func registryHiveFormatFromValue(operation string, value starlark.Value) (registryHiveFormat, error) {
	if value == nil || value == starlark.None {
		return defaultRegistryHiveFormat, nil
	}
	file, ok := value.(starfile.File)
	if !ok {
		return registryHiveFormat{}, fmt.Errorf("%s: format is %s, want registry hive file", operation, value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return registryHiveFormat{}, fmt.Errorf("%s: read format hive: %w", operation, err)
	}
	if len(data) < hiveBaseBlockSize || string(data[:4]) != "regf" {
		return registryHiveFormat{}, fmt.Errorf("%s: format file is not a registry hive", operation)
	}
	format := registryHiveFormat{
		major: binary.LittleEndian.Uint32(data[0x14:0x18]),
		minor: binary.LittleEndian.Uint32(data[0x18:0x1c]),
	}
	if format.major != 1 || format.minor < 2 || format.minor > 5 {
		return registryHiveFormat{}, fmt.Errorf("%s: unsupported registry hive format %d.%d", operation, format.major, format.minor)
	}
	return format, nil
}

func hivesFromINFBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var infValue starlark.Value
	txtsetupValue := starlark.Value(starlark.None)
	extraValue := starlark.Value(starlark.None)
	patchesValue := starlark.Value(starlark.None)
	formatValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("hives_from_inf", args, kwargs, "inf", &infValue, "txtsetup?", &txtsetupValue, "extra?", &extraValue, "patches?", &patchesValue, "format?", &formatValue); err != nil {
		return nil, err
	}
	inf, ok := infValue.(*infFile)
	if !ok {
		return nil, fmt.Errorf("hives_from_inf: got %s, want inf", infValue.Type())
	}
	var txtsetup *infFile
	if txtsetupValue != starlark.None {
		var ok bool
		txtsetup, ok = txtsetupValue.(*infFile)
		if !ok {
			return nil, fmt.Errorf("hives_from_inf: got %s for txtsetup, want inf", txtsetupValue.Type())
		}
	}
	extra, err := unpackINFAddRegList("hives_from_inf", extraValue)
	if err != nil {
		return nil, err
	}
	patches, err := unpackHiveBuildPatches(patchesValue)
	if err != nil {
		return nil, err
	}
	format, err := registryHiveFormatFromValue("hives_from_inf", formatValue)
	if err != nil {
		return nil, err
	}
	hives, err := buildWindowsHivesFromINF(inf, txtsetup, extra, patches, format)
	if err != nil {
		return nil, err
	}
	out := starlark.NewDict(len(hives))
	for name, file := range hives {
		if err := out.SetKey(starlark.String(name), file); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func infPatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var infValue starlark.Value
	var hiveName string
	section := "AddReg"
	if err := starlark.UnpackArgs("inf_patches", args, kwargs, "inf", &infValue, "hive", &hiveName, "section?", &section); err != nil {
		return nil, err
	}
	inf, ok := infValue.(*infFile)
	if !ok {
		return nil, fmt.Errorf("inf_patches: got %s, want inf", infValue.Type())
	}
	addRegValue, found, err := inf.json.Get(starlark.String(section))
	if err != nil {
		return nil, err
	}
	if !found {
		return starlark.NewList(nil), nil
	}
	addReg, ok := addRegValue.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("inf_patches: %s is %s, want dict", section, addRegValue.Type())
	}
	targetHive := strings.ToUpper(hiveName)
	patches := make([]starlark.Value, 0, addReg.Len())
	for _, item := range addReg.Items() {
		row, ok := item[1].(*starlark.List)
		if !ok || row.Len() < 2 {
			continue
		}
		patch, ok, err := patchFromINFAddRegRow(row, targetHive)
		if err != nil {
			return nil, err
		}
		if ok {
			patches = append(patches, patch)
		}
	}
	return starlark.NewList(patches), nil
}

func hivePatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	raw := false
	if err := starlark.UnpackArgs("hive_patches", args, kwargs, "file", &value, "raw?", &raw); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("hive_patches: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	hive, err := newRegistryHive(&starfile.Bytes{Name: file.String(), Data: data})
	if err != nil {
		return nil, err
	}
	root, err := hive.readKey(hive.rootCell)
	if err != nil {
		return nil, err
	}
	patches := starlark.NewList(nil)
	if raw {
		if err := hive.appendRawPatches(root, nil, patches); err != nil {
			return nil, err
		}
	} else if err := hive.appendPatches(root, nil, patches); err != nil {
		return nil, err
	}
	return patches, nil
}

func hiveKeysBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	metadata := false
	if err := starlark.UnpackArgs("hive_keys", args, kwargs, "file", &value, "metadata?", &metadata); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("hive_keys: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	hive, err := newRegistryHive(&starfile.Bytes{Name: file.String(), Data: data})
	if err != nil {
		return nil, err
	}
	root, err := hive.readKey(hive.rootCell)
	if err != nil {
		return nil, err
	}
	keys := starlark.NewList(nil)
	if metadata {
		if err := hive.appendKeyMetadata(root, nil, keys); err != nil {
			return nil, err
		}
	} else if err := hive.appendKeys(root, nil, keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func hiveFromPatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var patches *starlark.List
	keysValue := starlark.Value(starlark.None)
	formatValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("hive_from_patches", args, kwargs, "name", &name, "patches", &patches, "keys?", &keysValue, "format?", &formatValue); err != nil {
		return nil, err
	}
	root := newRegistryTree(name)
	if keysValue != starlark.None {
		keys, ok := keysValue.(*starlark.List)
		if !ok {
			return nil, fmt.Errorf("hive_from_patches: got %s for keys, want list", keysValue.Type())
		}
		for i := 0; i < keys.Len(); i++ {
			item := keys.Index(i)
			if keyPath, ok := starlark.AsString(item); ok {
				ensureRegistryKey(root, keyPath)
				continue
			}
			metadata, ok := item.(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("hive_from_patches: keys[%d] is %s, want string or dict", i, item.Type())
			}
			keyParts, _, err := registryPathFromDict(metadata)
			if err != nil {
				return nil, fmt.Errorf("hive_from_patches: keys[%d]: %w", i, err)
			}
			node := ensureRegistryKeyParts(root, keyParts)
			if flagsValue, found, err := metadata.Get(starlark.String("flags")); err != nil {
				return nil, err
			} else if found {
				flags, err := starlark.AsInt32(flagsValue)
				if err != nil || flags < 0 || flags > 0xffff {
					return nil, fmt.Errorf("hive_from_patches: keys[%d] has invalid flags", i)
				}
				node.flags = uint16(flags)
				node.flagsSet = true
			}
			if classValue, found, err := metadata.Get(starlark.String("class")); err != nil {
				return nil, err
			} else if found {
				classData, err := bytesForValue(classValue)
				if err != nil {
					return nil, fmt.Errorf("hive_from_patches: keys[%d] class: %w", i, err)
				}
				node.class = classData
			}
			if securityValue, found, err := metadata.Get(starlark.String("security")); err != nil {
				return nil, err
			} else if found {
				securityData, err := bytesForValue(securityValue)
				if err != nil {
					return nil, fmt.Errorf("hive_from_patches: keys[%d] security: %w", i, err)
				}
				if err := validateSelfRelativeSecurityDescriptor(securityData); err != nil {
					return nil, fmt.Errorf("hive_from_patches: keys[%d] security: %w", i, err)
				}
				node.security = securityData
			}
		}
	}
	for i := 0; i < patches.Len(); i++ {
		patch, ok := patches.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("hive_from_patches: patch %d is %s, want dict", i, patches.Index(i).Type())
		}
		keyParts, _, err := registryPathFromDict(patch)
		if err != nil {
			return nil, err
		}
		valueName, err := requiredPatchString(patch, "name")
		if err != nil {
			return nil, err
		}
		dataTypeValue, found, err := patch.Get(starlark.String("type"))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("hive_from_patches: patch %d missing type", i)
		}
		value, found, err := patch.Get(starlark.String("value"))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("hive_from_patches: patch %d missing value", i)
		}
		var registryValue registryData
		if dataType, ok := starlark.AsString(dataTypeValue); ok {
			registryValue, err = registryDataFromStarlark(dataType, value)
		} else if typeInt, ok := dataTypeValue.(starlark.Int); ok {
			typ, ok := typeInt.Uint64()
			if !ok || typ > 0xffffffff {
				return nil, fmt.Errorf("hive_from_patches: patch %d has invalid numeric type", i)
			}
			data, dataErr := bytesForValue(value)
			if dataErr != nil {
				return nil, fmt.Errorf("hive_from_patches: patch %d data: %w", i, dataErr)
			}
			registryValue = registryData{typ: uint32(typ), data: data}
		} else {
			return nil, fmt.Errorf("hive_from_patches: patch %d type is %s, want string or int", i, dataTypeValue.Type())
		}
		if err != nil {
			return nil, fmt.Errorf("hive_from_patches: patch %d: %w", i, err)
		}
		flags, err := unpackAddRegBehaviorFlags(patch, "hive_from_patches")
		if err != nil {
			return nil, fmt.Errorf("hive_from_patches: patch %d: %w", i, err)
		}
		if err := applyRegistryValueParts(root, keyParts, valueName, registryValue, flags); err != nil {
			return nil, fmt.Errorf("hive_from_patches: patch %d: %w", i, err)
		}
	}
	format, err := registryHiveFormatFromValue("hive_from_patches", formatValue)
	if err != nil {
		return nil, err
	}
	data, err := buildRegistryHiveWithFormat(root, format)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: strings.ToLower(name) + ".hiv", Data: data}, nil
}

type hiveRawValue struct {
	name  string
	value registryData
}

func (h *registryHive) appendPatches(key hiveKey, keyParts []string, patches *starlark.List) error {
	keyPath := registryDisplayPath(keyParts)
	values, err := h.readRawValues(key)
	if err != nil {
		return fmt.Errorf("hive_patches: key %q: %w", keyPath, err)
	}
	for _, value := range values {
		patch, err := registryPatchDict(keyPath, keyParts, value.name, value.value)
		if err != nil {
			return fmt.Errorf("hive_patches: key %q value %q: %w", keyPath, value.name, err)
		}
		if err := patches.Append(patch); err != nil {
			return err
		}
	}
	children, err := h.readSubkeys(key)
	if err != nil {
		return err
	}
	for _, child := range children {
		childParts := appendRegistryPathPart(keyParts, child.name)
		if err := h.appendPatches(child, childParts, patches); err != nil {
			return err
		}
	}
	return nil
}

func (h *registryHive) appendRawPatches(key hiveKey, keyParts []string, patches *starlark.List) error {
	keyPath := registryDisplayPath(keyParts)
	values, err := h.readRawValues(key)
	if err != nil {
		return fmt.Errorf("hive_patches: key %q: %w", keyPath, err)
	}
	for _, value := range values {
		patch := starlark.NewDict(5)
		for _, field := range []struct {
			name  string
			value starlark.Value
		}{
			{"key", starlark.String(keyPath)},
			{"key_parts", registryPathList(keyParts)},
			{"name", starlark.String(value.name)},
			{"type", starlark.MakeUint64(uint64(value.value.typ))},
			{"value", starlark.Bytes(value.value.data)},
		} {
			if err := patch.SetKey(starlark.String(field.name), field.value); err != nil {
				return err
			}
		}
		if err := patches.Append(patch); err != nil {
			return err
		}
	}
	children, err := h.readSubkeys(key)
	if err != nil {
		return err
	}
	for _, child := range children {
		childParts := appendRegistryPathPart(keyParts, child.name)
		if err := h.appendRawPatches(child, childParts, patches); err != nil {
			return err
		}
	}
	return nil
}

func (h *registryHive) appendKeys(key hiveKey, keyParts []string, keys *starlark.List) error {
	keyPath := registryDisplayPath(keyParts)
	if err := keys.Append(starlark.String(keyPath)); err != nil {
		return err
	}
	children, err := h.readSubkeys(key)
	if err != nil {
		return err
	}
	for _, child := range children {
		childParts := appendRegistryPathPart(keyParts, child.name)
		if err := h.appendKeys(child, childParts, keys); err != nil {
			return err
		}
	}
	return nil
}

func (h *registryHive) appendKeyMetadata(key hiveKey, keyParts []string, keys *starlark.List) error {
	keyPath := registryDisplayPath(keyParts)
	classData, err := h.readKeyClass(key)
	if err != nil {
		return err
	}
	securityData, err := h.readKeySecurity(key)
	if err != nil {
		return err
	}
	metadata := starlark.NewDict(5)
	if err := metadata.SetKey(starlark.String("key"), starlark.String(keyPath)); err != nil {
		return err
	}
	if err := metadata.SetKey(starlark.String("key_parts"), registryPathList(keyParts)); err != nil {
		return err
	}
	if err := metadata.SetKey(starlark.String("flags"), starlark.MakeInt(int(key.flags))); err != nil {
		return err
	}
	if err := metadata.SetKey(starlark.String("class"), starlark.Bytes(classData)); err != nil {
		return err
	}
	if err := metadata.SetKey(starlark.String("security"), starlark.Bytes(securityData)); err != nil {
		return err
	}
	if err := keys.Append(metadata); err != nil {
		return err
	}
	children, err := h.readSubkeys(key)
	if err != nil {
		return err
	}
	for _, child := range children {
		childParts := appendRegistryPathPart(keyParts, child.name)
		if err := h.appendKeyMetadata(child, childParts, keys); err != nil {
			return err
		}
	}
	return nil
}

func (h *registryHive) readRawValues(key hiveKey) ([]hiveRawValue, error) {
	if key.values == 0 || key.valueList == 0xffffffff {
		return nil, nil
	}
	list, err := h.readCell(key.valueList)
	if err != nil {
		return nil, err
	}
	needed := int(key.values) * 4
	if needed > len(list) {
		return nil, fmt.Errorf("hive_patches: truncated value list")
	}
	values := make([]hiveRawValue, 0, key.values)
	for offset := 0; offset < needed; offset += 4 {
		value, err := h.readRawValue(binary.LittleEndian.Uint32(list[offset : offset+4]))
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func (h *registryHive) readRawValue(cell uint32) (hiveRawValue, error) {
	data, err := h.readCell(cell)
	if err != nil {
		return hiveRawValue{}, err
	}
	if len(data) < 0x14 || string(data[0:2]) != "vk" {
		return hiveRawValue{}, fmt.Errorf("hive_patches: cell 0x%x is not a value node", cell)
	}
	nameLength := int(binary.LittleEndian.Uint16(data[0x02:0x04]))
	dataLengthRaw := binary.LittleEndian.Uint32(data[0x04:0x08])
	dataCell := binary.LittleEndian.Uint32(data[0x08:0x0c])
	valueType := binary.LittleEndian.Uint32(data[0x0c:0x10])
	flags := binary.LittleEndian.Uint16(data[0x10:0x12])
	nameStart := 0x14
	nameEnd := nameStart + nameLength
	if nameEnd > len(data) {
		return hiveRawValue{}, fmt.Errorf("hive_patches: invalid value name length")
	}
	valueData, err := h.readValueData(dataLengthRaw, dataCell)
	if err != nil {
		return hiveRawValue{}, err
	}
	return hiveRawValue{
		name:  hiveValueName(data[nameStart:nameEnd], flags),
		value: registryData{typ: valueType, data: append([]byte(nil), valueData...)},
	}, nil
}

func registryPatchDict(keyPath string, keyParts []string, name string, data registryData) (*starlark.Dict, error) {
	dataType, value, err := registryDataToStarlark(data)
	if err != nil {
		return nil, err
	}
	patch := starlark.NewDict(5)
	if err := patch.SetKey(starlark.String("key"), starlark.String(keyPath)); err != nil {
		return nil, err
	}
	if err := patch.SetKey(starlark.String("key_parts"), registryPathList(keyParts)); err != nil {
		return nil, err
	}
	if err := patch.SetKey(starlark.String("name"), starlark.String(name)); err != nil {
		return nil, err
	}
	if err := patch.SetKey(starlark.String("type"), starlark.String(dataType)); err != nil {
		return nil, err
	}
	if err := patch.SetKey(starlark.String("value"), value); err != nil {
		return nil, err
	}
	return patch, nil
}

type infAddRegSection struct {
	inf     *infFile
	section string
}

type hiveBuildPatch struct {
	hive        string
	key         string
	name        string
	value       registryData
	addRegFlags uint32
}

func unpackHiveBuildPatches(value starlark.Value) ([]hiveBuildPatch, error) {
	if value == starlark.None {
		return nil, nil
	}
	list, ok := value.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("hives_from_inf: got %s for patches, want list", value.Type())
	}
	patches := make([]hiveBuildPatch, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		patch, ok := list.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("hives_from_inf: patches[%d] is %s, want dict", i, list.Index(i).Type())
		}
		hiveName, err := requiredPatchString(patch, "hive")
		if err != nil {
			return nil, err
		}
		keyPath, err := requiredPatchString(patch, "key")
		if err != nil {
			return nil, err
		}
		name, err := requiredPatchString(patch, "name")
		if err != nil {
			return nil, err
		}
		dataType, err := requiredPatchString(patch, "type")
		if err != nil {
			return nil, err
		}
		rawValue, found, err := patch.Get(starlark.String("value"))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("hives_from_inf: patches[%d] missing value", i)
		}
		addRegFlags, err := unpackAddRegBehaviorFlags(patch, fmt.Sprintf("hives_from_inf: patches[%d]", i))
		if err != nil {
			return nil, err
		}
		registryValue, err := registryDataFromStarlark(dataType, rawValue)
		if err != nil {
			return nil, fmt.Errorf("hives_from_inf: patches[%d]: %w", i, err)
		}
		patches = append(patches, hiveBuildPatch{
			hive:        strings.ToUpper(hiveName),
			key:         keyPath,
			name:        name,
			value:       registryValue,
			addRegFlags: addRegFlags,
		})
	}
	return patches, nil
}

func unpackINFAddRegList(name string, value starlark.Value) ([]infAddRegSection, error) {
	if value == starlark.None {
		return nil, nil
	}
	list, ok := value.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("%s: got %s for extra, want list", name, value.Type())
	}
	out := make([]infAddRegSection, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		item := list.Index(i)
		if inf, ok := item.(*infFile); ok {
			out = append(out, infAddRegSection{inf: inf, section: "AddReg"})
			continue
		}
		dict, ok := item.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("%s: extra[%d] is %s, want inf or dict", name, i, item.Type())
		}
		infValue, found, err := dict.Get(starlark.String("inf"))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%s: extra[%d] missing inf", name, i)
		}
		inf, ok := infValue.(*infFile)
		if !ok {
			return nil, fmt.Errorf("%s: extra[%d].inf is %s, want inf", name, i, infValue.Type())
		}
		section := "AddReg"
		sectionValue, found, err := dict.Get(starlark.String("section"))
		if err != nil {
			return nil, err
		}
		if found {
			var ok bool
			section, ok = starlark.AsString(sectionValue)
			if !ok {
				return nil, fmt.Errorf("%s: extra[%d].section is %s, want string", name, i, sectionValue.Type())
			}
		}
		out = append(out, infAddRegSection{inf: inf, section: section})
	}
	return out, nil
}

func patchHiveBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var patches *starlark.List
	if err := starlark.UnpackArgs("patch_hive", args, kwargs, "file", &value, "patches", &patches); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("patch_hive: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if len(data) < hiveBaseBlockSize || string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("patch_hive: invalid regf signature")
	}
	hiveSize := int(binary.LittleEndian.Uint32(data[0x28:0x2c]))
	if hiveSize < 0 || hiveBaseBlockSize+hiveSize > len(data) {
		return nil, fmt.Errorf("patch_hive: invalid hive bins size")
	}
	hive := mutableHive{data: data[:hiveBaseBlockSize+hiveSize]}
	for i := 0; i < patches.Len(); i++ {
		patch, ok := patches.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("patch_hive: patch %d is %s, want dict", i, patches.Index(i).Type())
		}
		keyPath, err := requiredPatchString(patch, "key")
		if err != nil {
			return nil, err
		}
		name, err := requiredPatchString(patch, "name")
		if err != nil {
			return nil, err
		}
		dataType, err := requiredPatchString(patch, "type")
		if err != nil {
			return nil, err
		}
		value, found, err := patch.Get(starlark.String("value"))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("patch_hive: patch %d missing value", i)
		}
		registryValue, err := registryDataFromStarlark(dataType, value)
		if err != nil {
			return nil, fmt.Errorf("patch_hive: patch %d: %w", i, err)
		}
		addRegFlags, err := unpackAddRegBehaviorFlags(patch, fmt.Sprintf("patch_hive: patch %d", i))
		if err != nil {
			return nil, err
		}
		if err := hive.applyValue(keyPath, name, registryValue, addRegFlags); err != nil {
			return nil, fmt.Errorf("patch_hive: patch %d %s/%s: %w", i, keyPath, name, err)
		}
	}
	return &starfile.Bytes{Name: "patched.hiv", Data: hive.data}, nil
}

func hiveLogBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("hive_log", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("hive_log: got %s, want file", value.Type())
	}
	header := make([]byte, hiveBaseBlockSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, err
	}
	if string(header[0:4]) != "regf" {
		return nil, fmt.Errorf("hive_log: invalid regf signature")
	}
	binary.LittleEndian.PutUint32(header[0x1c:0x20], 1)
	binary.LittleEndian.PutUint32(header[0x1fc:0x200], 0)
	checksum := uint32(0)
	for off := 0; off < 0x1fc; off += 4 {
		checksum ^= binary.LittleEndian.Uint32(header[off : off+4])
	}
	binary.LittleEndian.PutUint32(header[0x1fc:0x200], checksum)
	return &starfile.Bytes{Name: "hive.log", Data: header}, nil
}

type mutableHive struct {
	data []byte
}

func requiredPatchString(patch *starlark.Dict, key string) (string, error) {
	value, found, err := patch.Get(starlark.String(key))
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("patch_hive: patch missing %s", key)
	}
	out, ok := starlark.AsString(value)
	if !ok {
		return "", fmt.Errorf("patch_hive: patch %s is %s, want string", key, value.Type())
	}
	return out, nil
}

func registryPathFromDict(value *starlark.Dict) ([]string, string, error) {
	partsValue, found, err := value.Get(starlark.String("key_parts"))
	if err != nil {
		return nil, "", err
	}
	if found {
		parts, err := registryPathParts(partsValue)
		if err != nil {
			return nil, "", fmt.Errorf("key_parts: %w", err)
		}
		return parts, registryDisplayPath(parts), nil
	}
	keyPath, err := requiredPatchString(value, "key")
	if err != nil {
		return nil, "", err
	}
	parts, err := registryPathParts(starlark.String(keyPath))
	if err != nil {
		return nil, "", err
	}
	return parts, registryDisplayPath(parts), nil
}

func registryPathList(parts []string) *starlark.List {
	values := make([]starlark.Value, len(parts))
	for index, part := range parts {
		values[index] = starlark.String(part)
	}
	return starlark.NewList(values)
}

func appendRegistryPathPart(parts []string, part string) []string {
	child := make([]string, len(parts)+1)
	copy(child, parts)
	child[len(parts)] = part
	return child
}

func unpackAddRegBehaviorFlags(patch *starlark.Dict, context string) (uint32, error) {
	var flags uint32
	for _, behavior := range []struct {
		name string
		flag uint32
	}{
		{name: "if_absent", flag: infAddRegNoClobber},
		{name: "delete", flag: infAddRegDeleteValue},
		{name: "append", flag: infAddRegAppend},
		{name: "overwrite_only", flag: infAddRegOverwriteOnly},
	} {
		value, found, err := patch.Get(starlark.String(behavior.name))
		if err != nil {
			return 0, err
		}
		if !found {
			continue
		}
		enabled, ok := value.(starlark.Bool)
		if !ok {
			return 0, fmt.Errorf("%s %s is %s, want bool", context, behavior.name, value.Type())
		}
		if enabled {
			flags |= behavior.flag
		}
	}
	return flags, nil
}

func registryDataFromStarlark(dataType string, value starlark.Value) (registryData, error) {
	normalizedType := strings.ToUpper(dataType)
	switch normalizedType {
	case "REG_SZ", "SZ":
		s, ok := starlark.AsString(value)
		if !ok {
			return registryData{}, fmt.Errorf("REG_SZ value is %s, want string", value.Type())
		}
		return registryString(regSZ, s), nil
	case "REG_EXPAND_SZ", "EXPAND_SZ":
		s, ok := starlark.AsString(value)
		if !ok {
			return registryData{}, fmt.Errorf("REG_EXPAND_SZ value is %s, want string", value.Type())
		}
		return registryString(regExpandSZ, s), nil
	case "REG_DWORD", "DWORD":
		i, ok := starlarkRegistryDWORD(value)
		if !ok {
			return registryData{}, fmt.Errorf("REG_DWORD value is %s, want int", value.Type())
		}
		return registryDWORD(i), nil
	case "REG_QWORD", "QWORD":
		i, ok := value.(starlark.Int)
		if !ok {
			return registryData{}, fmt.Errorf("REG_QWORD value is %s, want int", value.Type())
		}
		v, ok := i.Uint64()
		if !ok {
			return registryData{}, fmt.Errorf("REG_QWORD value overflows uint64")
		}
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, v)
		return registryData{typ: regQWord, data: data}, nil
	case "REG_MULTI_SZ", "MULTI_SZ":
		list, ok := value.(*starlark.List)
		if !ok {
			return registryData{}, fmt.Errorf("REG_MULTI_SZ value is %s, want list", value.Type())
		}
		values := make([]string, 0, list.Len())
		for i := 0; i < list.Len(); i++ {
			s, ok := starlark.AsString(list.Index(i))
			if !ok {
				return registryData{}, fmt.Errorf("REG_MULTI_SZ value[%d] is %s, want string", i, list.Index(i).Type())
			}
			values = append(values, s)
		}
		return registryMultiString(values), nil
	case "REG_BINARY", "BINARY":
		data, err := bytesForValue(value)
		if err != nil {
			return registryData{}, err
		}
		return registryData{typ: regBinary, data: data}, nil
	case "REG_DWORD_BIG_ENDIAN", "DWORD_BIG_ENDIAN":
		data, err := bytesForValue(value)
		if err != nil {
			return registryData{}, err
		}
		return registryData{typ: regDWORDBigEndian, data: data}, nil
	case "REG_LINK", "LINK":
		data, err := bytesForValue(value)
		if err != nil {
			return registryData{}, err
		}
		return registryData{typ: regLink, data: data}, nil
	case "REG_RESOURCE_LIST", "RESOURCE_LIST":
		data, err := bytesForValue(value)
		if err != nil {
			return registryData{}, err
		}
		return registryData{typ: regResourceList, data: data}, nil
	case "REG_FULL_RESOURCE_DESCRIPTOR", "FULL_RESOURCE_DESCRIPTOR":
		data, err := bytesForValue(value)
		if err != nil {
			return registryData{}, err
		}
		return registryData{typ: regFullResourceDescriptor, data: data}, nil
	case "REG_RESOURCE_REQUIREMENTS_LIST", "RESOURCE_REQUIREMENTS_LIST":
		data, err := bytesForValue(value)
		if err != nil {
			return registryData{}, err
		}
		return registryData{typ: regResourceRequirementsList, data: data}, nil
	case "REG_NONE", "NONE":
		data, err := bytesForValue(value)
		if err != nil {
			return registryData{}, err
		}
		return registryData{typ: regNone, data: data}, nil
	default:
		const privateTypePrefix = "REG_TYPE_"
		if strings.HasPrefix(normalizedType, privateTypePrefix) {
			typ, err := strconv.ParseUint(strings.TrimPrefix(normalizedType, privateTypePrefix), 0, 32)
			if err != nil {
				return registryData{}, fmt.Errorf("invalid private registry type %q", dataType)
			}
			data, err := bytesForValue(value)
			if err != nil {
				return registryData{}, err
			}
			return registryData{typ: uint32(typ), data: data}, nil
		}
		return registryData{}, fmt.Errorf("unsupported registry type %q", dataType)
	}
}

func starlarkRegistryDWORD(value starlark.Value) (uint32, bool) {
	if i, ok := value.(starlark.Int); ok {
		if unsigned, ok := i.Uint64(); ok && unsigned <= 0xffffffff {
			return uint32(unsigned), true
		}
	}
	signed, err := starlark.AsInt32(value)
	if err != nil {
		return 0, false
	}
	return uint32(signed), true
}

func registryDataToStarlark(data registryData) (string, starlark.Value, error) {
	switch data.typ {
	case regNone:
		return "REG_NONE", starlark.Bytes(data.data), nil
	case regSZ:
		return "REG_SZ", starlark.String(strings.TrimRight(decodeUTF16LE(data.data), "\x00")), nil
	case regExpandSZ:
		return "REG_EXPAND_SZ", starlark.String(strings.TrimRight(decodeUTF16LE(data.data), "\x00")), nil
	case regBinary:
		return "REG_BINARY", starlark.Bytes(data.data), nil
	case regDWORD:
		if len(data.data) < 4 {
			return "", nil, fmt.Errorf("REG_DWORD data has %d bytes, want 4", len(data.data))
		}
		return "REG_DWORD", starlark.MakeInt(int(binary.LittleEndian.Uint32(data.data))), nil
	case regDWORDBigEndian:
		return "REG_DWORD_BIG_ENDIAN", starlark.Bytes(data.data), nil
	case regLink:
		return "REG_LINK", starlark.Bytes(data.data), nil
	case regMultiSZ:
		parts := strings.Split(strings.TrimRight(decodeUTF16LE(data.data), "\x00"), "\x00")
		values := make([]starlark.Value, 0, len(parts))
		for _, part := range parts {
			if part != "" {
				values = append(values, starlark.String(part))
			}
		}
		return "REG_MULTI_SZ", starlark.NewList(values), nil
	case regResourceList:
		return "REG_RESOURCE_LIST", starlark.Bytes(data.data), nil
	case regFullResourceDescriptor:
		return "REG_FULL_RESOURCE_DESCRIPTOR", starlark.Bytes(data.data), nil
	case regResourceRequirementsList:
		return "REG_RESOURCE_REQUIREMENTS_LIST", starlark.Bytes(data.data), nil
	case regQWord:
		if len(data.data) < 8 {
			return "", nil, fmt.Errorf("REG_QWORD data has %d bytes, want 8", len(data.data))
		}
		return "REG_QWORD", starlark.MakeUint64(binary.LittleEndian.Uint64(data.data)), nil
	default:
		return fmt.Sprintf("REG_TYPE_%d", data.typ), starlark.Bytes(data.data), nil
	}
}

func (h *mutableHive) rootCell() uint32 {
	return binary.LittleEndian.Uint32(h.data[0x24:0x28])
}

func (h *mutableHive) patchValue(keyPath, valueName string, value registryData) error {
	key, err := h.lookupKey(keyPath)
	if err != nil {
		return err
	}
	valueCell, err := h.findValueCell(key, valueName)
	if err != nil {
		return err
	}
	body, err := h.cellBody(valueCell)
	if err != nil {
		return err
	}
	if len(body) < 0x14 || string(body[0:2]) != "vk" {
		return fmt.Errorf("patch_hive: cell 0x%x is not a value", valueCell)
	}
	oldLengthRaw := binary.LittleEndian.Uint32(body[0x04:0x08])
	oldDataCell := binary.LittleEndian.Uint32(body[0x08:0x0c])
	if len(value.data) <= 4 {
		var inline [4]byte
		copy(inline[:], value.data)
		binary.LittleEndian.PutUint32(body[0x04:0x08], uint32(len(value.data))|0x80000000)
		binary.LittleEndian.PutUint32(body[0x08:0x0c], binary.LittleEndian.Uint32(inline[:]))
		binary.LittleEndian.PutUint32(body[0x0c:0x10], value.typ)
		if keyBody, err := h.cellBody(key); err == nil {
			updateKeyMaxValue(keyBody, body)
		}
		return nil
	}
	if oldLengthRaw&0x80000000 != 0 {
		dataCell, err := h.allocateCell(value.data)
		if err != nil {
			return err
		}
		body, err = h.cellBody(valueCell)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(body[0x04:0x08], uint32(len(value.data)))
		binary.LittleEndian.PutUint32(body[0x08:0x0c], dataCell)
		binary.LittleEndian.PutUint32(body[0x0c:0x10], value.typ)
		if keyBody, err := h.cellBody(key); err == nil {
			updateKeyMaxValue(keyBody, body)
		}
		return nil
	}
	oldBody, err := h.cellBody(oldDataCell)
	if err != nil {
		return err
	}
	if len(value.data) > len(oldBody) {
		dataCell, err := h.allocateCell(value.data)
		if err != nil {
			return err
		}
		body, err = h.cellBody(valueCell)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(body[0x04:0x08], uint32(len(value.data)))
		binary.LittleEndian.PutUint32(body[0x08:0x0c], dataCell)
		binary.LittleEndian.PutUint32(body[0x0c:0x10], value.typ)
		if keyBody, err := h.cellBody(key); err == nil {
			updateKeyMaxValue(keyBody, body)
		}
		return nil
	}
	clear(oldBody)
	copy(oldBody, value.data)
	binary.LittleEndian.PutUint32(body[0x04:0x08], uint32(len(value.data)))
	binary.LittleEndian.PutUint32(body[0x0c:0x10], value.typ)
	if keyBody, err := h.cellBody(key); err == nil {
		updateKeyMaxValue(keyBody, body)
	}
	return nil
}

func (h *mutableHive) setValue(keyPath, valueName string, value registryData) error {
	key, err := h.ensureKey(keyPath)
	if err != nil {
		return err
	}
	if _, err := h.findValueCell(key, valueName); err == nil {
		return h.patchValue(keyPath, valueName, value)
	}
	valueCell, err := h.writeValue(valueName, value)
	if err != nil {
		return err
	}
	return h.addValueCell(key, valueCell)
}

func (h *mutableHive) applyValue(keyPath, valueName string, value registryData, flags uint32) error {
	key, lookupErr := h.lookupKey(keyPath)
	valueExists := false
	if lookupErr == nil {
		_, valueErr := h.findValueCell(key, valueName)
		valueExists = valueErr == nil
	}
	switch {
	case flags&infAddRegDeleteValue != 0:
		if !valueExists {
			return nil
		}
		return h.deleteValue(keyPath, valueName)
	case flags&infAddRegAppend != 0:
		if !valueExists {
			return h.setValue(keyPath, valueName, value)
		}
		existing, err := h.readValue(keyPath, valueName)
		if err != nil {
			return err
		}
		merged, err := appendRegistryMultiString(existing, value)
		if err != nil {
			return err
		}
		return h.setValue(keyPath, valueName, merged)
	case flags&infAddRegNoClobber != 0:
		if valueExists {
			return nil
		}
		return h.setValue(keyPath, valueName, value)
	case flags&infAddRegOverwriteOnly != 0:
		if !valueExists {
			return nil
		}
		return h.setValue(keyPath, valueName, value)
	default:
		return h.setValue(keyPath, valueName, value)
	}
}

func (h *mutableHive) readValue(keyPath, valueName string) (registryData, error) {
	key, err := h.lookupKey(keyPath)
	if err != nil {
		return registryData{}, err
	}
	valueCell, err := h.findValueCell(key, valueName)
	if err != nil {
		return registryData{}, err
	}
	body, err := h.cellBody(valueCell)
	if err != nil {
		return registryData{}, err
	}
	if len(body) < 0x14 || string(body[:2]) != "vk" {
		return registryData{}, fmt.Errorf("patch_hive: cell 0x%x is not a value", valueCell)
	}
	lengthRaw := binary.LittleEndian.Uint32(body[0x04:0x08])
	length := int(lengthRaw & 0x7fffffff)
	data := make([]byte, length)
	if lengthRaw&0x80000000 != 0 {
		if length > 4 {
			return registryData{}, fmt.Errorf("patch_hive: invalid inline value length %d", length)
		}
		copy(data, body[0x08:0x0c])
	} else if length != 0 {
		dataCell := binary.LittleEndian.Uint32(body[0x08:0x0c])
		stored, err := h.cellBody(dataCell)
		if err != nil {
			return registryData{}, err
		}
		if length > len(stored) {
			return registryData{}, fmt.Errorf("patch_hive: truncated value data")
		}
		copy(data, stored[:length])
	}
	return registryData{typ: binary.LittleEndian.Uint32(body[0x0c:0x10]), data: data}, nil
}

func (h *mutableHive) deleteValue(keyPath, valueName string) error {
	keyCell, err := h.lookupKey(keyPath)
	if err != nil {
		return err
	}
	valueCell, err := h.findValueCell(keyCell, valueName)
	if err != nil {
		return err
	}
	key, err := h.cellBody(keyCell)
	if err != nil {
		return err
	}
	count := int(binary.LittleEndian.Uint32(key[0x24:0x28]))
	listCell := binary.LittleEndian.Uint32(key[0x28:0x2c])
	cells, err := h.valueCells(listCell, count)
	if err != nil {
		return err
	}
	remaining := make([]uint32, 0, len(cells)-1)
	for _, cell := range cells {
		if cell != valueCell {
			remaining = append(remaining, cell)
		}
	}
	key, err = h.cellBody(keyCell)
	if err != nil {
		return err
	}
	if len(remaining) == 0 {
		binary.LittleEndian.PutUint32(key[0x24:0x28], 0)
		binary.LittleEndian.PutUint32(key[0x28:0x2c], 0xffffffff)
		return nil
	}
	newList, err := h.writeValueList(remaining)
	if err != nil {
		return err
	}
	key, err = h.cellBody(keyCell)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(key[0x24:0x28], uint32(len(remaining)))
	binary.LittleEndian.PutUint32(key[0x28:0x2c], newList)
	return nil
}

func (h *mutableHive) ensureKey(keyPath string) (uint32, error) {
	current := h.rootCell()
	if keyPath == "/" {
		return current, nil
	}
	for _, part := range strings.Split(strings.Trim(storage.CleanPath(keyPath), "/"), "/") {
		next, err := h.findSubkeyCell(current, part)
		if err == nil {
			current = next
			continue
		}
		child, err := h.writeKey(part, current)
		if err != nil {
			return 0, err
		}
		if err := h.addSubkeyCell(current, child); err != nil {
			return 0, err
		}
		current = child
	}
	return current, nil
}

func (h *mutableHive) lookupKey(keyPath string) (uint32, error) {
	current := h.rootCell()
	if keyPath == "/" {
		return current, nil
	}
	for _, part := range strings.Split(strings.Trim(storage.CleanPath(keyPath), "/"), "/") {
		next, err := h.findSubkeyCell(current, part)
		if err != nil {
			return 0, err
		}
		current = next
	}
	return current, nil
}

func (h *mutableHive) addSubkeyCell(parentCell, childCell uint32) error {
	parent, err := h.cellBody(parentCell)
	if err != nil {
		return err
	}
	child, err := h.cellBody(childCell)
	if err != nil {
		return err
	}
	count := binary.LittleEndian.Uint32(parent[0x14:0x18])
	listCell := binary.LittleEndian.Uint32(parent[0x1c:0x20])
	var cells []uint32
	if count > 0 && listCell != 0xffffffff {
		cells, err = h.subkeyCells(listCell)
		if errors.Is(err, errRegistryFreeCell) {
			cells = nil
			err = nil
		}
		if err != nil {
			return err
		}
	}
	cells = append(cells, childCell)
	type namedCell struct {
		cell   uint32
		name   string
		folded string
	}
	named := make([]namedCell, len(cells))
	for i, cell := range cells {
		name, err := h.subkeyName(cell)
		if err != nil {
			return err
		}
		named[i] = namedCell{cell: cell, name: name, folded: strings.ToUpper(name)}
	}
	sort.Slice(named, func(i, j int) bool {
		if named[i].folded != named[j].folded {
			return named[i].folded < named[j].folded
		}
		if named[i].name != named[j].name {
			return named[i].name < named[j].name
		}
		return named[i].cell < named[j].cell
	})
	for i := 1; i < len(named); i++ {
		if strings.EqualFold(named[i-1].name, named[i].name) {
			return fmt.Errorf("patch_hive: duplicate subkey %q", named[i].name)
		}
	}
	for i := range named {
		cells[i] = named[i].cell
	}
	newList, err := h.writeSubkeyList(cells)
	if err != nil {
		return err
	}
	parent, err = h.cellBody(parentCell)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(parent[0x14:0x18], uint32(len(cells)))
	binary.LittleEndian.PutUint32(parent[0x1c:0x20], newList)
	updateKeyMaxSubkeyName(parent, child)
	return nil
}

func (h *mutableHive) addValueCell(keyCell, valueCell uint32) error {
	key, err := h.cellBody(keyCell)
	if err != nil {
		return err
	}
	count := int(binary.LittleEndian.Uint32(key[0x24:0x28]))
	listCell := binary.LittleEndian.Uint32(key[0x28:0x2c])
	cells := make([]uint32, 0, count+1)
	if count > 0 && listCell != 0xffffffff {
		cells, err = h.valueCells(listCell, count)
		if err != nil {
			return err
		}
	}
	cells = append(cells, valueCell)
	newList, err := h.writeValueList(cells)
	if err != nil {
		return err
	}
	value, err := h.cellBody(valueCell)
	if err != nil {
		return err
	}
	key, err = h.cellBody(keyCell)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(key[0x24:0x28], uint32(len(cells)))
	binary.LittleEndian.PutUint32(key[0x28:0x2c], newList)
	updateKeyMaxValue(key, value)
	return nil
}

func (h *mutableHive) findSubkeyCell(keyCell uint32, name string) (uint32, error) {
	key, err := h.cellBody(keyCell)
	if err != nil {
		return 0, err
	}
	if len(key) < 0x4c || string(key[0:2]) != "nk" {
		return 0, fmt.Errorf("patch_hive: cell 0x%x is not a key", keyCell)
	}
	count := binary.LittleEndian.Uint32(key[0x14:0x18])
	listCell := binary.LittleEndian.Uint32(key[0x1c:0x20])
	if count == 0 || listCell == 0xffffffff {
		return 0, fmt.Errorf("patch_hive: subkey %q not found", name)
	}
	cells, err := h.subkeyCells(listCell)
	if errors.Is(err, errRegistryFreeCell) {
		return 0, fmt.Errorf("patch_hive: subkey %q not found", name)
	}
	if err != nil {
		return 0, err
	}
	for _, cell := range cells {
		childName, err := h.subkeyName(cell)
		if errors.Is(err, errRegistryFreeCell) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if strings.EqualFold(childName, name) {
			return cell, nil
		}
	}
	return 0, fmt.Errorf("patch_hive: subkey %q not found", name)
}

func (h *mutableHive) findValueCell(keyCell uint32, name string) (uint32, error) {
	key, err := h.cellBody(keyCell)
	if err != nil {
		return 0, err
	}
	count := int(binary.LittleEndian.Uint32(key[0x24:0x28]))
	listCell := binary.LittleEndian.Uint32(key[0x28:0x2c])
	if count == 0 || listCell == 0xffffffff {
		return 0, fmt.Errorf("patch_hive: value %q not found", name)
	}
	cells, err := h.valueCells(listCell, count)
	if err != nil {
		return 0, err
	}
	for _, cell := range cells {
		value, err := h.cellBody(cell)
		if err != nil {
			return 0, err
		}
		if len(value) < 0x14 || string(value[0:2]) != "vk" {
			continue
		}
		flags := binary.LittleEndian.Uint16(value[0x10:0x12])
		nameLength := int(binary.LittleEndian.Uint16(value[0x02:0x04]))
		if 0x14+nameLength > len(value) {
			continue
		}
		if strings.EqualFold(hiveValueName(value[0x14:0x14+nameLength], flags), name) {
			return cell, nil
		}
	}
	return 0, fmt.Errorf("patch_hive: value %q not found", name)
}

func (h *mutableHive) valueCells(listCell uint32, count int) ([]uint32, error) {
	list, err := h.cellBody(listCell)
	if errors.Is(err, errRegistryFreeCell) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, count)
	for offset := 0; offset+4 <= len(list) && offset/4 < count; offset += 4 {
		cell := binary.LittleEndian.Uint32(list[offset : offset+4])
		value, err := h.cellBody(cell)
		if errors.Is(err, errRegistryFreeCell) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(value) < 0x14 || string(value[0:2]) != "vk" {
			continue
		}
		out = append(out, cell)
	}
	return out, nil
}

func (h *mutableHive) subkeyCells(cell uint32) ([]uint32, error) {
	list, err := h.cellBody(cell)
	if err != nil {
		return nil, err
	}
	if len(list) < 4 {
		return nil, fmt.Errorf("patch_hive: invalid subkey list")
	}
	signature := string(list[0:2])
	count := int(binary.LittleEndian.Uint16(list[2:4]))
	var out []uint32
	switch signature {
	case "lf", "lh":
		for offset, i := 4, 0; i < count; offset, i = offset+8, i+1 {
			if offset+8 > len(list) {
				return nil, fmt.Errorf("patch_hive: truncated %s list", signature)
			}
			child := binary.LittleEndian.Uint32(list[offset : offset+4])
			out, err = h.appendLiveSubkeyCell(out, child)
			if err != nil {
				return nil, err
			}
		}
	case "li":
		for offset, i := 4, 0; i < count; offset, i = offset+4, i+1 {
			if offset+4 > len(list) {
				return nil, fmt.Errorf("patch_hive: truncated li list")
			}
			child := binary.LittleEndian.Uint32(list[offset : offset+4])
			out, err = h.appendLiveSubkeyCell(out, child)
			if err != nil {
				return nil, err
			}
		}
	case "ri":
		for offset, i := 4, 0; i < count; offset, i = offset+4, i+1 {
			if offset+4 > len(list) {
				return nil, fmt.Errorf("patch_hive: truncated ri list")
			}
			more, err := h.subkeyCells(binary.LittleEndian.Uint32(list[offset : offset+4]))
			if errors.Is(err, errRegistryFreeCell) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, more...)
		}
	default:
		return nil, fmt.Errorf("patch_hive: unsupported subkey list %q", signature)
	}
	return out, nil
}

func (h *mutableHive) appendLiveSubkeyCell(out []uint32, cell uint32) ([]uint32, error) {
	child, err := h.cellBody(cell)
	if errors.Is(err, errRegistryFreeCell) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if len(child) < 0x4c || string(child[0:2]) != "nk" {
		return out, nil
	}
	return append(out, cell), nil
}

func (h *mutableHive) writeKey(name string, parent uint32) (uint32, error) {
	nameBytes := []byte(name)
	body := make([]byte, 0x4c+len(nameBytes))
	copy(body[0:2], "nk")
	binary.LittleEndian.PutUint16(body[2:4], 0x20)
	binary.LittleEndian.PutUint64(body[4:12], uint64(windowsFiletime(time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC))))
	binary.LittleEndian.PutUint32(body[0x10:0x14], parent)
	binary.LittleEndian.PutUint32(body[0x1c:0x20], 0xffffffff)
	binary.LittleEndian.PutUint32(body[0x20:0x24], 0xffffffff)
	binary.LittleEndian.PutUint32(body[0x28:0x2c], 0xffffffff)
	binary.LittleEndian.PutUint32(body[0x2c:0x30], h.inheritedSecurity(parent))
	binary.LittleEndian.PutUint32(body[0x30:0x34], 0xffffffff)
	binary.LittleEndian.PutUint16(body[0x48:0x4a], uint16(len(nameBytes)))
	copy(body[0x4c:], nameBytes)
	return h.allocateCell(body)
}

func (h *mutableHive) writeValue(name string, value registryData) (uint32, error) {
	hiveName := name
	if isDefaultRegistryValueName(name) {
		hiveName = ""
	}
	nameBytes := []byte(hiveName)
	dataLength := uint32(len(value.data))
	dataCell := uint32(0)
	if len(value.data) <= 4 {
		dataLength |= 0x80000000
		var inline [4]byte
		copy(inline[:], value.data)
		dataCell = binary.LittleEndian.Uint32(inline[:])
	} else {
		var err error
		dataCell, err = h.allocateCell(value.data)
		if err != nil {
			return 0, err
		}
	}
	body := make([]byte, 0x14+len(nameBytes))
	copy(body[0:2], "vk")
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint32(body[4:8], dataLength)
	binary.LittleEndian.PutUint32(body[8:12], dataCell)
	binary.LittleEndian.PutUint32(body[12:16], value.typ)
	binary.LittleEndian.PutUint16(body[16:18], 1)
	copy(body[0x14:], nameBytes)
	return h.allocateCell(body)
}

func (h *mutableHive) writeValueList(cells []uint32) (uint32, error) {
	body := make([]byte, len(cells)*4)
	for i, cell := range cells {
		binary.LittleEndian.PutUint32(body[i*4:i*4+4], cell)
	}
	return h.allocateCell(body)
}

func (h *mutableHive) writeSubkeyList(cells []uint32) (uint32, error) {
	if len(cells) <= registrySubkeyIndexEntries {
		return h.writeSubkeyLeaf(cells)
	}
	leaves := make([]uint32, 0, (len(cells)+registrySubkeyIndexEntries-1)/registrySubkeyIndexEntries)
	for start := 0; start < len(cells); start += registrySubkeyIndexEntries {
		end := min(start+registrySubkeyIndexEntries, len(cells))
		leaf, err := h.writeSubkeyLeaf(cells[start:end])
		if err != nil {
			return 0, err
		}
		leaves = append(leaves, leaf)
	}
	body := make([]byte, 4+len(leaves)*4)
	copy(body[0:2], "ri")
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(leaves)))
	for i, leaf := range leaves {
		binary.LittleEndian.PutUint32(body[4+i*4:8+i*4], leaf)
	}
	return h.allocateCell(body)
}

func (h *mutableHive) writeSubkeyLeaf(cells []uint32) (uint32, error) {
	body := make([]byte, 4+len(cells)*4)
	copy(body[0:2], "li")
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(cells)))
	for i, cell := range cells {
		offset := 4 + i*4
		binary.LittleEndian.PutUint32(body[offset:offset+4], cell)
	}
	return h.allocateCell(body)
}

func (h *mutableHive) subkeyName(cell uint32) (string, error) {
	child, err := h.cellBody(cell)
	if err != nil {
		return "", err
	}
	if len(child) < 0x4c || string(child[0:2]) != "nk" {
		return "", fmt.Errorf("patch_hive: cell 0x%x is not a key", cell)
	}
	flags := binary.LittleEndian.Uint16(child[0x02:0x04])
	nameLength := int(binary.LittleEndian.Uint16(child[0x48:0x4a]))
	if 0x4c+nameLength > len(child) {
		return "", fmt.Errorf("patch_hive: truncated key name in cell 0x%x", cell)
	}
	return hiveName(child[0x4c:0x4c+nameLength], flags), nil
}

func (h *mutableHive) subkeyNameHint(cell uint32) []byte {
	name, err := h.subkeyName(cell)
	if err != nil {
		return nil
	}
	hint := make([]byte, 4)
	copy(hint, []byte(strings.ToUpper(name)))
	return hint
}

func (h *mutableHive) inheritedSecurity(parent uint32) uint32 {
	body, err := h.cellBody(parent)
	if err != nil || len(body) < 0x30 {
		return 0xffffffff
	}
	return binary.LittleEndian.Uint32(body[0x2c:0x30])
}

func (h *mutableHive) allocateCell(body []byte) (uint32, error) {
	needed := align8(len(body) + 4)
	if len(h.data) < hiveBaseBlockSize+0x20 || string(h.data[hiveBaseBlockSize:hiveBaseBlockSize+4]) != "hbin" {
		return 0, fmt.Errorf("patch_hive: missing hbin")
	}
	hbinSize := int(alignInt64(int64(needed+0x20), hiveBaseBlockSize))
	oldSize := int(binary.LittleEndian.Uint32(h.data[0x28:0x2c]))
	newHbin := make([]byte, hbinSize)
	copy(newHbin[0:4], "hbin")
	binary.LittleEndian.PutUint32(newHbin[4:8], uint32(oldSize))
	binary.LittleEndian.PutUint32(newHbin[8:12], uint32(hbinSize))
	binary.LittleEndian.PutUint32(newHbin[0x20:0x24], uint32(int32(-needed)))
	copy(newHbin[0x24:0x24+len(body)], body)
	if remaining := hbinSize - 0x20 - needed; remaining >= 8 {
		binary.LittleEndian.PutUint32(newHbin[0x20+needed:0x24+needed], uint32(remaining))
	}
	h.data = append(h.data, newHbin...)
	binary.LittleEndian.PutUint32(h.data[0x28:0x2c], uint32(oldSize+hbinSize))
	h.updateBaseChecksum()
	return uint32(oldSize + 0x20), nil
}

func (h *mutableHive) allocateExistingCell(body []byte, needed int) (uint32, bool) {
	hiveSize := int(binary.LittleEndian.Uint32(h.data[0x28:0x2c]))
	for binRel := 0; binRel+0x20 <= hiveSize; {
		binOff := hiveBaseBlockSize + binRel
		if binOff+0x20 > len(h.data) || string(h.data[binOff:binOff+4]) != "hbin" {
			return 0, false
		}
		binSize := int(binary.LittleEndian.Uint32(h.data[binOff+8 : binOff+12]))
		if binSize <= 0 || binOff+binSize > len(h.data) {
			return 0, false
		}
		for cellOff := binOff + 0x20; cellOff+4 <= binOff+binSize; {
			rawSize := int32(binary.LittleEndian.Uint32(h.data[cellOff : cellOff+4]))
			if rawSize == 0 {
				break
			}
			cellSize := int(rawSize)
			if cellSize < 0 {
				cellSize = -cellSize
			}
			if cellSize < 8 || cellOff+cellSize > binOff+binSize {
				break
			}
			if rawSize > 0 && cellSize >= needed {
				h.writeAllocatedCell(cellOff, cellSize, body, needed)
				return uint32(cellOff - hiveBaseBlockSize), true
			}
			cellOff += cellSize
		}
		binRel += binSize
	}
	return 0, false
}

func (h *mutableHive) writeAllocatedCell(cellOff, cellSize int, body []byte, needed int) {
	used := needed
	if cellSize-needed < 8 {
		used = cellSize
	}
	binary.LittleEndian.PutUint32(h.data[cellOff:cellOff+4], uint32(int32(-used)))
	clear(h.data[cellOff+4 : cellOff+used])
	copy(h.data[cellOff+4:cellOff+4+len(body)], body)
	if remaining := cellSize - used; remaining >= 8 {
		restOff := cellOff + used
		binary.LittleEndian.PutUint32(h.data[restOff:restOff+4], uint32(remaining))
		clear(h.data[restOff+4 : cellOff+cellSize])
	}
}

func (h *mutableHive) updateBaseChecksum() {
	binary.LittleEndian.PutUint32(h.data[0x1fc:0x200], 0)
	checksum := uint32(0)
	for off := 0; off < 0x1fc; off += 4 {
		checksum ^= binary.LittleEndian.Uint32(h.data[off : off+4])
	}
	binary.LittleEndian.PutUint32(h.data[0x1fc:0x200], checksum)
}

func (h *mutableHive) cellBody(cell uint32) ([]byte, error) {
	offset := hiveBaseBlockSize + int(cell)
	if offset < hiveBaseBlockSize || offset+4 > len(h.data) {
		return nil, fmt.Errorf("patch_hive: cell 0x%x outside hive", cell)
	}
	size := int32(binary.LittleEndian.Uint32(h.data[offset : offset+4]))
	if size == 0 {
		return nil, fmt.Errorf("patch_hive: empty cell 0x%x: %w", cell, errRegistryFreeCell)
	}
	if size > 0 {
		return nil, fmt.Errorf("patch_hive: free cell 0x%x: %w", cell, errRegistryFreeCell)
	}
	if size < 0 {
		size = -size
	}
	end := offset + int(size)
	if int(size) < 4 || end > len(h.data) {
		return nil, fmt.Errorf("patch_hive: invalid cell 0x%x size", cell)
	}
	return h.data[offset+4 : end], nil
}

func buildWindowsHivesFromINF(inf *infFile, txtsetup *infFile, extra []infAddRegSection, patches []hiveBuildPatch, format registryHiveFormat) (map[string]starlark.Value, error) {
	roots := map[string]*registryTree{
		"SYSTEM":   newRegistryTree("SYSTEM"),
		"SOFTWARE": newRegistryTree("SOFTWARE"),
		"DEFAULT":  newRegistryTree("DEFAULT"),
		"SAM":      newRegistryTree("SAM"),
		"SECURITY": newRegistryTree("SECURITY"),
	}
	if err := applyINFAddRegSection(roots, inf, "AddReg"); err != nil {
		return nil, err
	}
	for _, extraSection := range extra {
		if err := applyINFAddRegSection(roots, extraSection.inf, extraSection.section); err != nil {
			return nil, err
		}
	}
	if txtsetup != nil {
		applyTxtSetupRegistry(roots, txtsetup)
	}
	for _, patch := range patches {
		root := roots[patch.hive]
		if root == nil {
			return nil, fmt.Errorf("hives_from_inf: unknown hive %q", patch.hive)
		}
		if err := applyRegistryValue(root, patch.key, patch.name, patch.value, patch.addRegFlags); err != nil {
			return nil, fmt.Errorf("hives_from_inf: patch %s/%s: %w", patch.key, patch.name, err)
		}
	}

	out := make(map[string]starlark.Value, len(roots))
	for name, tree := range roots {
		data, err := buildRegistryHiveWithFormat(tree, format)
		if err != nil {
			return nil, fmt.Errorf("%s hive: %w", name, err)
		}
		out[name] = &starfile.Bytes{Name: strings.ToLower(name) + ".hiv", Data: data}
	}
	return out, nil
}

func applyINFAddRegSection(roots map[string]*registryTree, inf *infFile, section string) error {
	addRegValue, found, err := inf.json.Get(starlark.String(section))
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	addReg, ok := addRegValue.(*starlark.Dict)
	if !ok {
		return fmt.Errorf("hives_from_inf: %s is %s, want dict", section, addRegValue.Type())
	}
	for _, item := range addReg.Items() {
		row, ok := item[1].(*starlark.List)
		if !ok || row.Len() < 2 {
			continue
		}
		if err := applyAddRegRow(roots, row); err != nil {
			return err
		}
	}
	return nil
}

func newRegistryTree(name string) *registryTree {
	return &registryTree{name: name, subkeys: make(map[string]*registryTree), values: make(map[string]registryData)}
}

func applyAddRegRow(roots map[string]*registryTree, row *starlark.List) error {
	root, ok := starlark.AsString(row.Index(0))
	if !ok || !strings.HasPrefix(strings.ToUpper(root), "HK") {
		return nil
	}
	keyPath, ok := starlark.AsString(row.Index(1))
	if !ok {
		return nil
	}
	valueName := "(default)"
	if row.Len() >= 3 {
		if name, ok := starlark.AsString(row.Index(2)); ok && name != "" {
			valueName = name
		}
	}
	flags := uint32(0)
	if row.Len() >= 4 {
		if s, ok := starlark.AsString(row.Index(3)); ok && s != "" {
			parsed, err := parseRegistryDWORD(s)
			if err != nil {
				return nil
			}
			flags = uint32(parsed)
		}
	}
	if flags&infAddRegKeyOnly != 0 {
		hive, mapped := mapINFRegistryPath(root, keyPath)
		if hive != "" {
			ensureRegistryKey(roots[hive], mapped)
		}
		return nil
	}
	data := registryData{typ: regSZ, data: utf16Nul("")}
	if row.Len() >= 5 {
		values := make([]string, 0, row.Len()-4)
		for i := 4; i < row.Len(); i++ {
			if s, ok := starlark.AsString(row.Index(i)); ok {
				values = append(values, s)
			}
		}
		data = registryDataFromINF(flags, values)
	} else if flags&0xffff == 0x10 {
		data = registryData{typ: regNone}
	} else {
		data = registryDataFromINF(flags, nil)
	}
	hive, mapped := mapINFRegistryPath(root, keyPath)
	if hive == "" {
		return nil
	}
	return applyRegistryValue(roots[hive], mapped, valueName, data, flags)
}

func patchFromINFAddRegRow(row *starlark.List, targetHive string) (*starlark.Dict, bool, error) {
	hive, patch, ok, err := registryPatchFromINFAddRegRow(row)
	if err != nil || !ok || strings.ToUpper(hive) != targetHive {
		return nil, false, err
	}
	out := starlark.NewDict(4)
	for field, value := range map[string]starlark.Value{
		"key":   starlark.String(patch.key),
		"name":  starlark.String(patch.name),
		"type":  starlark.String(patch.typ),
		"value": patch.value,
	} {
		if err := out.SetKey(starlark.String(field), value); err != nil {
			return nil, false, err
		}
	}
	if err := setAddRegBehaviorFields(out, patch.addRegFlags); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func registryPatchFromINFAddRegRow(row *starlark.List) (string, registryPatch, bool, error) {
	root, ok := starlark.AsString(row.Index(0))
	if !ok || !strings.HasPrefix(strings.ToUpper(root), "HK") {
		return "", registryPatch{}, false, nil
	}
	keyPath, ok := starlark.AsString(row.Index(1))
	if !ok {
		return "", registryPatch{}, false, nil
	}
	valueName := "(default)"
	if row.Len() >= 3 {
		if name, ok := starlark.AsString(row.Index(2)); ok && name != "" {
			valueName = name
		}
	}
	flags := uint32(0)
	if row.Len() >= 4 {
		if s, ok := starlark.AsString(row.Index(3)); ok && s != "" {
			parsed, err := parseRegistryDWORD(s)
			if err != nil {
				return "", registryPatch{}, false, nil
			}
			flags = uint32(parsed)
		}
	}
	if flags&infAddRegKeyOnly != 0 {
		return "", registryPatch{}, false, nil
	}
	data := registryData{typ: regSZ, data: utf16Nul("")}
	if row.Len() >= 5 {
		values := make([]string, 0, row.Len()-4)
		for i := 4; i < row.Len(); i++ {
			if s, ok := starlark.AsString(row.Index(i)); ok {
				values = append(values, s)
			}
		}
		data = registryDataFromINF(flags, values)
	} else if flags&0xffff == 0x10 {
		data = registryData{typ: regNone}
	} else {
		data = registryDataFromINF(flags, nil)
	}
	hive, mapped := mapINFRegistryPath(root, keyPath)
	if hive == "" {
		return "", registryPatch{}, false, nil
	}
	dataType, value, err := registryDataToStarlark(data)
	if err != nil {
		return "", registryPatch{}, false, err
	}
	return hive, registryPatch{key: mapped, name: valueName, typ: dataType, value: value, addRegFlags: flags}, true, nil
}

func applyTxtSetupRegistry(roots map[string]*registryTree, txtsetup *infFile) {
	system := roots["SYSTEM"]
	availableDrivers := txtsetupDriverFiles(txtsetup)
	loadSections := map[string]string{
		"BusExtenders.Load":     "System Bus Extender",
		"BootBusExtenders.Load": "Boot Bus Extender",
		"FileSystems.Load":      "starfile.File System",
		"Keyboard.Load":         "Keyboard Port",
		"MouseDrivers.Load":     "Pointer Port",
		"SCSI.Load":             "SCSI Miniport",
		"SystemPartition.Load":  "System Bus Extender",
	}
	for section, group := range loadSections {
		values, ok := infSectionDict(txtsetup, section)
		if !ok {
			continue
		}
		for _, item := range values.Items() {
			selector, ok := starlark.AsString(item[0])
			if !ok || selector == "" {
				continue
			}
			driver := firstInfString(item[1])
			if driver == "" {
				driver = selector + ".sys"
			}
			if !availableDrivers[strings.ToLower(driver)] {
				continue
			}
			service := strings.TrimSuffix(path.Base(strings.ReplaceAll(driver, "\\", "/")), path.Ext(driver))
			if existingPath := existingServicePathForDriver(system, driver); existingPath != "" {
				setRegistryValue(system, existingPath, "Start", registryDWORD(0))
				continue
			}
			servicePath := "/ControlSet001/Services/" + service
			setRegistryValue(system, servicePath, "ErrorControl", registryDWORD(0))
			setRegistryValue(system, servicePath, "Group", registryString(regSZ, group))
			setRegistryValue(system, servicePath, "ImagePath", registryString(regExpandSZ, "system32\\drivers\\"+driver))
			setRegistryValue(system, servicePath, "Start", registryDWORD(0))
			setRegistryValue(system, servicePath, "Type", registryDWORD(1))
		}
	}

	applyTxtSetupNLSRegistry(system, txtsetup)

	hardware, ok := infSectionDict(txtsetup, "HardwareIdsDatabase")
	if !ok {
		return
	}
	for _, item := range hardware.Items() {
		hwid, ok := starlark.AsString(item[0])
		if !ok || hwid == "" {
			continue
		}
		service := firstInfString(item[1])
		if service == "" {
			continue
		}
		keyPath := "/ControlSet001/Control/CriticalDeviceDatabase/" + strings.ReplaceAll(hwid, "\\", "#")
		setRegistryValue(system, keyPath, "Service", registryString(regSZ, service))
		setRegistryValue(system, keyPath, "ClassGUID", registryString(regSZ, criticalDeviceClassGUID(hwid)))
	}
}

func existingServicePathForDriver(system *registryTree, driver string) string {
	driver = path.Base(strings.ReplaceAll(driver, "\\", "/"))
	name := strings.TrimSuffix(driver, path.Ext(driver))
	services := ensureRegistryKey(system, "/ControlSet001/Services")
	service := services.subkeys[strings.ToUpper(name)]
	if service == nil {
		return ""
	}
	return "/ControlSet001/Services/" + service.name
}

func applyTxtSetupNLSRegistry(system *registryTree, txtsetup *infFile) {
	nls, ok := infSectionDict(txtsetup, "nls")
	if !ok {
		return
	}
	codePageKey := "/ControlSet001/Control/NLS/CodePage"
	languageKey := "/ControlSet001/Control/NLS/Language"
	localeKey := "/ControlSet001/Control/NLS/Locale"

	if pairs := infNLSFileCodePairs(nls, "AnsiCodepage"); len(pairs) > 0 {
		setRegistryValue(system, codePageKey, "ACP", registryString(regSZ, pairs[0].code))
		setRegistryValue(system, codePageKey, pairs[0].code, registryString(regSZ, pairs[0].file))
	}
	if pairs := infNLSFileCodePairs(nls, "OemCodepage"); len(pairs) > 0 {
		setRegistryValue(system, codePageKey, "OEMCP", registryString(regSZ, pairs[0].code))
		for _, pair := range pairs {
			setRegistryValue(system, codePageKey, pair.code, registryString(regSZ, pair.file))
		}
	}
	if pairs := infNLSFileCodePairs(nls, "MacCodepage"); len(pairs) > 0 {
		setRegistryValue(system, codePageKey, "MACCP", registryString(regSZ, pairs[0].code))
		for _, pair := range pairs {
			setRegistryValue(system, codePageKey, pair.code, registryString(regSZ, pair.file))
		}
	}
	if pairs := infNLSFileCodePairs(nls, "UnicodeCasetable"); len(pairs) > 0 {
		lang := pairs[0].code
		setRegistryValue(system, languageKey, "Default", registryString(regSZ, lang))
		setRegistryValue(system, languageKey, "InstallLanguage", registryString(regSZ, lang))
		setRegistryValue(system, languageKey, lang, registryString(regSZ, pairs[0].file))
		locale := "0000" + strings.ToLower(lang)
		setRegistryValue(system, localeKey, "(default)", registryString(regSZ, locale))
		setRegistryValue(system, localeKey, locale, registryString(regSZ, "1"))
	}
	if values := infStringList(nls, "OemHalFont"); len(values) > 0 {
		setRegistryValue(system, codePageKey, "OEMHAL", registryString(regSZ, values[0]))
	}
}

type nlsFileCodePair struct {
	file string
	code string
}

func infNLSFileCodePairs(section *starlark.Dict, name string) []nlsFileCodePair {
	values := infStringList(section, name)
	pairs := make([]nlsFileCodePair, 0, len(values)/2)
	for i := 0; i+1 < len(values); i += 2 {
		if values[i] == "" || values[i+1] == "" {
			continue
		}
		pairs = append(pairs, nlsFileCodePair{file: values[i], code: values[i+1]})
	}
	return pairs
}

func txtsetupDriverFiles(txtsetup *infFile) map[string]bool {
	out := make(map[string]bool)
	for _, section := range []string{"SourceDisksFiles", "SourceDisksFiles.x86", "SourceDisksFiles.amd64"} {
		files, ok := infSectionDict(txtsetup, section)
		if !ok {
			continue
		}
		for _, item := range files.Items() {
			name, ok := starlark.AsString(item[0])
			if ok && strings.HasSuffix(strings.ToLower(name), ".sys") {
				out[strings.ToLower(name)] = true
			}
		}
	}
	return out
}

func infSectionDict(inf *infFile, section string) (*starlark.Dict, bool) {
	value, found, err := inf.json.Get(starlark.String(section))
	if err != nil || !found {
		for _, item := range inf.json.Items() {
			name, ok := starlark.AsString(item[0])
			if !ok || !strings.EqualFold(name, section) {
				continue
			}
			value = item[1]
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}
	dict, ok := value.(*starlark.Dict)
	return dict, ok
}

func infStringList(section *starlark.Dict, name string) []string {
	value, found, err := section.Get(starlark.String(name))
	if err != nil || !found {
		for _, item := range section.Items() {
			itemName, ok := starlark.AsString(item[0])
			if !ok || !strings.EqualFold(itemName, name) {
				continue
			}
			value = item[1]
			found = true
			break
		}
		if !found {
			return nil
		}
	}
	if s, ok := starlark.AsString(value); ok {
		return []string{s}
	}
	list, ok := value.(*starlark.List)
	if !ok {
		return nil
	}
	out := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		if s, ok := starlark.AsString(list.Index(i)); ok {
			out = append(out, s)
		}
	}
	return out
}

func firstInfString(value starlark.Value) string {
	if s, ok := starlark.AsString(value); ok {
		return s
	}
	list, ok := value.(*starlark.List)
	if !ok || list.Len() == 0 {
		return ""
	}
	s, _ := starlark.AsString(list.Index(0))
	return s
}

func criticalDeviceClassGUID(hwid string) string {
	upper := strings.ToUpper(hwid)
	switch {
	case strings.HasPrefix(upper, "USB\\") || strings.HasPrefix(upper, "USB#"):
		return "{36FC9E60-C465-11CF-8056-444553540000}"
	case strings.Contains(upper, "CC_010") || strings.Contains(upper, "GENDISK"):
		return "{4D36E967-E325-11CE-BFC1-08002BE10318}"
	case strings.Contains(upper, "CC_03"):
		return "{4D36E968-E325-11CE-BFC1-08002BE10318}"
	case strings.Contains(upper, "PNP030") || strings.Contains(upper, "KEYBOARD"):
		return "{4D36E96B-E325-11CE-BFC1-08002BE10318}"
	case strings.Contains(upper, "PNP0F") || strings.Contains(upper, "MOUSE"):
		return "{4D36E96F-E325-11CE-BFC1-08002BE10318}"
	default:
		return "{4D36E97D-E325-11CE-BFC1-08002BE10318}"
	}
}

func mapINFRegistryPath(root, keyPath string) (string, string) {
	keyPath = strings.ReplaceAll(keyPath, "\\", "/")
	switch strings.ToUpper(root) {
	case "HKLM":
		cleaned := storage.CleanPath(keyPath)
		parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
		if len(parts) == 0 {
			return "", ""
		}
		switch strings.ToUpper(parts[0]) {
		case "SYSTEM":
			rest := parts[1:]
			if len(rest) > 0 && strings.EqualFold(rest[0], "CurrentControlSet") {
				rest[0] = "ControlSet001"
			}
			return "SYSTEM", "/" + strings.Join(rest, "/")
		case "SOFTWARE":
			return "SOFTWARE", "/" + strings.Join(parts[1:], "/")
		case "SAM":
			return "SAM", "/" + strings.Join(parts[1:], "/")
		case "SECURITY":
			return "SECURITY", "/" + strings.Join(parts[1:], "/")
		}
	case "HKCR":
		return "SOFTWARE", path.Join("/Classes", storage.CleanPath(keyPath))
	case "HKCU":
		return "DEFAULT", storage.CleanPath(keyPath)
	case "HKU":
		cleaned := storage.CleanPath(keyPath)
		if strings.HasPrefix(strings.ToUpper(cleaned), "/.DEFAULT") {
			return "DEFAULT", strings.TrimPrefix(cleaned, "/.DEFAULT")
		}
	}
	return "", ""
}

func registryDataFromINF(flags uint32, values []string) registryData {
	switch flags & 0xffff0000 {
	case 0x00010000:
		if flags&0x00000001 != 0 {
			if len(values) > 0 {
				v, _ := parseRegistryDWORD(values[0])
				return registryDWORD(uint32(v))
			}
			return registryDWORD(0)
		}
		return registryMultiString(values)
	case 0x00020000:
		return registryString(regExpandSZ, strings.Join(values, ","))
	case 0x00030000:
		return registryData{typ: regBinary, data: parseHexBytes(values)}
	case 0x00040000:
		return registryData{typ: regDWORDBigEndian, data: parseHexBytes(values)}
	case 0x00050000:
		return registryData{typ: regLink, data: parseHexBytes(values)}
	case 0x00060000:
		return registryData{typ: regResourceList, data: parseHexBytes(values)}
	case 0x00070000:
		return registryData{typ: regFullResourceDescriptor, data: parseHexBytes(values)}
	case 0x00080000:
		return registryData{typ: regResourceRequirementsList, data: parseHexBytes(values)}
	case 0x000a0000:
		return registryData{typ: regResourceRequirementsList, data: parseHexBytes(values)}
	case 0x000b0000:
		return registryData{typ: regQWord, data: parseHexBytes(values)}
	}
	switch flags & 0x0000ffff {
	case 0x0001:
		return registryData{typ: regBinary, data: parseHexBytes(values)}
	case 0x0003:
		return registryData{typ: regBinary, data: parseHexBytes(values)}
	}
	if len(values) == 0 {
		return registryString(regSZ, "")
	}
	return registryString(regSZ, strings.Join(values, ","))
}

func registryString(typ uint32, value string) registryData {
	if typ == regBinary {
		return registryData{typ: typ, data: []byte(value)}
	}
	return registryData{typ: typ, data: utf16Nul(normalizeWindows1252Text(value))}
}

func registryDWORD(value uint32) registryData {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, value)
	return registryData{typ: regDWORD, data: data}
}

func registryMultiString(values []string) registryData {
	var data []byte
	for _, value := range values {
		data = append(data, utf16Nul(normalizeWindows1252Text(value))...)
	}
	if len(values) == 0 {
		data = append(data, 0, 0)
	}
	data = append(data, 0, 0)
	return registryData{typ: regMultiSZ, data: data}
}

func normalizeWindows1252Text(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	special := map[byte]rune{
		0x80: '€', 0x82: '‚', 0x83: 'ƒ', 0x84: '„', 0x85: '…', 0x86: '†', 0x87: '‡',
		0x88: 'ˆ', 0x89: '‰', 0x8a: 'Š', 0x8b: '‹', 0x8c: 'Œ', 0x8e: 'Ž',
		0x91: '‘', 0x92: '’', 0x93: '“', 0x94: '”', 0x95: '•', 0x96: '–', 0x97: '—',
		0x98: '˜', 0x99: '™', 0x9a: 'š', 0x9b: '›', 0x9c: 'œ', 0x9e: 'ž', 0x9f: 'Ÿ',
	}
	var output strings.Builder
	for _, character := range []byte(value) {
		if decoded, ok := special[character]; ok {
			output.WriteRune(decoded)
		} else {
			output.WriteRune(rune(character))
		}
	}
	return output.String()
}

func parseHexBytes(values []string) []byte {
	out := make([]byte, 0, len(values))
	for _, value := range values {
		v, err := parseRegistryInt(value)
		if err == nil {
			out = append(out, byte(v))
		}
	}
	return out
}

func parseRegistryInt(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	value = strings.TrimPrefix(value, "0X")
	if value == "" {
		return 0, nil
	}
	return strconv.ParseUint(value, 16, 64)
}

func parseRegistryDWORD(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return strconv.ParseUint(value[2:], 16, 64)
	}
	if strings.HasPrefix(value, "-") {
		signed, err := strconv.ParseInt(value, 10, 64)
		return uint64(signed), err
	}
	return strconv.ParseUint(value, 10, 64)
}

func ensureRegistryKey(root *registryTree, keyPath string) *registryTree {
	parts := strings.Split(strings.Trim(storage.CleanPath(keyPath), "/"), "/")
	return ensureRegistryKeyParts(root, parts)
}

func ensureRegistryKeyParts(root *registryTree, parts []string) *registryTree {
	current := root
	for _, part := range parts {
		if part == "" {
			continue
		}
		key := strings.ToUpper(part)
		child := current.subkeys[key]
		if child == nil {
			child = newRegistryTree(part)
			current.subkeys[key] = child
		}
		current = child
	}
	return current
}

func setRegistryValue(root *registryTree, keyPath, name string, value registryData) {
	parts := strings.Split(strings.Trim(storage.CleanPath(keyPath), "/"), "/")
	setRegistryValueParts(root, parts, name, value)
}

func setRegistryValueParts(root *registryTree, parts []string, name string, value registryData) {
	key := ensureRegistryKeyParts(root, parts)
	if isDefaultRegistryValueName(name) {
		name = "(default)"
	}
	for existing := range key.values {
		if strings.EqualFold(existing, name) {
			delete(key.values, existing)
			break
		}
	}
	key.values[name] = value
}

func applyRegistryValue(root *registryTree, keyPath, name string, value registryData, flags uint32) error {
	parts := strings.Split(strings.Trim(storage.CleanPath(keyPath), "/"), "/")
	return applyRegistryValueParts(root, parts, name, value, flags)
}

func applyRegistryValueParts(root *registryTree, parts []string, name string, value registryData, flags uint32) error {
	key := ensureRegistryKeyParts(root, parts)
	existingName, existing, found := registryTreeValue(key, name)
	switch {
	case flags&infAddRegDeleteValue != 0:
		if found {
			delete(key.values, existingName)
		}
		return nil
	case flags&infAddRegAppend != 0:
		if !found {
			setRegistryValueParts(root, parts, name, value)
			return nil
		}
		merged, err := appendRegistryMultiString(existing, value)
		if err != nil {
			return err
		}
		setRegistryValueParts(root, parts, name, merged)
		return nil
	case flags&infAddRegNoClobber != 0:
		if !found {
			setRegistryValueParts(root, parts, name, value)
		}
		return nil
	case flags&infAddRegOverwriteOnly != 0:
		if found {
			setRegistryValueParts(root, parts, name, value)
		}
		return nil
	default:
		setRegistryValueParts(root, parts, name, value)
		return nil
	}
}

func registryTreeValue(key *registryTree, name string) (string, registryData, bool) {
	if isDefaultRegistryValueName(name) {
		name = "(default)"
	}
	for existingName, value := range key.values {
		if strings.EqualFold(existingName, name) {
			return existingName, value, true
		}
	}
	return "", registryData{}, false
}

func appendRegistryMultiString(existing, addition registryData) (registryData, error) {
	if existing.typ != regMultiSZ || addition.typ != regMultiSZ {
		return registryData{}, fmt.Errorf("append requires REG_MULTI_SZ values, got types %d and %d", existing.typ, addition.typ)
	}
	values := registryMultiStringValues(existing)
	for _, candidate := range registryMultiStringValues(addition) {
		found := false
		for _, value := range values {
			if strings.EqualFold(value, candidate) {
				found = true
				break
			}
		}
		if !found {
			values = append(values, candidate)
		}
	}
	return registryMultiString(values), nil
}

func registryMultiStringValues(value registryData) []string {
	decoded := strings.TrimRight(decodeUTF16LE(value.data), "\x00")
	if decoded == "" {
		return nil
	}
	return strings.Split(decoded, "\x00")
}

func setRegistryValueIfAbsent(root *registryTree, keyPath, name string, value registryData) {
	key := ensureRegistryKey(root, keyPath)
	if isDefaultRegistryValueName(name) {
		name = "(default)"
	}
	for existing := range key.values {
		if strings.EqualFold(existing, name) {
			return
		}
	}
	key.values[name] = value
}

func setAddRegBehaviorFields(out *starlark.Dict, flags uint32) error {
	for _, behavior := range []struct {
		name string
		flag uint32
	}{
		{name: "if_absent", flag: infAddRegNoClobber},
		{name: "delete", flag: infAddRegDeleteValue},
		{name: "append", flag: infAddRegAppend},
		{name: "overwrite_only", flag: infAddRegOverwriteOnly},
	} {
		if flags&behavior.flag == 0 {
			continue
		}
		if err := out.SetKey(starlark.String(behavior.name), starlark.True); err != nil {
			return err
		}
	}
	return nil
}

func registryNameUTF16ByteLen(name string) int {
	if isDefaultRegistryValueName(name) {
		return 0
	}
	return len(utf16.Encode([]rune(name))) * 2
}

func isDefaultRegistryValueName(name string) bool {
	return name == "" || strings.EqualFold(name, "(default)")
}

func maxRegistrySubkeyNameLen(node *registryTree) int {
	maxLen := 0
	for _, child := range node.subkeys {
		if n := registryNameUTF16ByteLen(child.name); n > maxLen {
			maxLen = n
		}
	}
	return maxLen
}

func maxRegistrySubkeyClassLen(node *registryTree) int {
	maxLen := 0
	for _, child := range node.subkeys {
		if len(child.class) > maxLen {
			maxLen = len(child.class)
		}
	}
	return maxLen
}

func maxRegistryValueNameLen(node *registryTree) int {
	maxLen := 0
	for name := range node.values {
		if n := registryNameUTF16ByteLen(name); n > maxLen {
			maxLen = n
		}
	}
	return maxLen
}

func maxRegistryValueDataLen(node *registryTree) int {
	maxLen := 0
	for _, value := range node.values {
		if len(value.data) > maxLen {
			maxLen = len(value.data)
		}
	}
	return maxLen
}

func updateKeyMaxSubkeyName(key, child []byte) {
	if len(key) < 0x38 || len(child) < 0x4c || string(child[0:2]) != "nk" {
		return
	}
	flags := binary.LittleEndian.Uint16(child[0x02:0x04])
	nameLength := int(binary.LittleEndian.Uint16(child[0x48:0x4a]))
	if 0x4c+nameLength > len(child) {
		return
	}
	nameLen := registryNameUTF16ByteLen(hiveName(child[0x4c:0x4c+nameLength], flags))
	if nameLen > int(binary.LittleEndian.Uint32(key[0x34:0x38])) {
		binary.LittleEndian.PutUint32(key[0x34:0x38], uint32(nameLen))
	}
}

func updateKeyMaxValue(key, value []byte) {
	if len(key) < 0x44 || len(value) < 0x14 || string(value[0:2]) != "vk" {
		return
	}
	flags := binary.LittleEndian.Uint16(value[0x10:0x12])
	nameLength := int(binary.LittleEndian.Uint16(value[0x02:0x04]))
	if 0x14+nameLength > len(value) {
		return
	}
	nameLen := registryNameUTF16ByteLen(hiveValueName(value[0x14:0x14+nameLength], flags))
	if nameLen > int(binary.LittleEndian.Uint32(key[0x3c:0x40])) {
		binary.LittleEndian.PutUint32(key[0x3c:0x40], uint32(nameLen))
	}
	dataLen := int(binary.LittleEndian.Uint32(value[0x04:0x08]) & 0x7fffffff)
	if dataLen > int(binary.LittleEndian.Uint32(key[0x40:0x44])) {
		binary.LittleEndian.PutUint32(key[0x40:0x44], uint32(dataLen))
	}
}

func buildRegistryHive(root *registryTree) ([]byte, error) {
	return buildRegistryHiveWithFormat(root, defaultRegistryHiveFormat)
}

func buildRegistryHiveWithFormat(root *registryTree, format registryHiveFormat) ([]byte, error) {
	inheritRegistryTreeSecurity(root, nil)
	w := &hiveWriter{data: make([]byte, 0, 128*1024), format: format, securityCells: make(map[string]uint32)}
	root.parent = 0xffffffff
	root.listCell = 0xffffffff
	root.valCell = 0xffffffff
	root.cell = w.writeKey(root, len(root.subkeys), len(root.values))
	if err := w.writeSecurityCells(root); err != nil {
		return nil, err
	}
	if err := w.writeTree(root); err != nil {
		return nil, err
	}
	w.finishBin()
	full := make([]byte, hiveBaseBlockSize+len(w.data))
	header := full[:hiveBaseBlockSize]
	copy(header[0:4], "regf")
	binary.LittleEndian.PutUint32(header[4:8], 1)
	binary.LittleEndian.PutUint32(header[8:12], 1)
	binary.LittleEndian.PutUint64(header[12:20], uint64(windowsFiletime(time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC))))
	binary.LittleEndian.PutUint32(header[20:24], format.major)
	binary.LittleEndian.PutUint32(header[24:28], format.minor)
	binary.LittleEndian.PutUint32(header[28:32], 0)
	binary.LittleEndian.PutUint32(header[32:36], 1)
	binary.LittleEndian.PutUint32(header[36:40], root.cell)
	binary.LittleEndian.PutUint32(header[40:44], uint32(len(w.data)))
	binary.LittleEndian.PutUint32(header[44:48], 1)
	copy(header[48:112], utf16Bytes(root.name))
	checksum := uint32(0)
	for off := 0; off < 0x1fc; off += 4 {
		checksum ^= binary.LittleEndian.Uint32(header[off : off+4])
	}
	binary.LittleEndian.PutUint32(header[0x1fc:0x200], checksum)

	copy(full[hiveBaseBlockSize:], w.data)
	return full, nil
}

func inheritRegistryTreeSecurity(node *registryTree, parent []byte) {
	if len(node.security) == 0 {
		if len(parent) == 0 {
			node.security = defaultRegistrySecurityDescriptor()
		} else {
			node.security = append([]byte(nil), parent...)
		}
	}
	for _, child := range node.subkeys {
		inheritRegistryTreeSecurity(child, node.security)
	}
}

func (w *hiveWriter) writeTree(node *registryTree) error {
	for _, child := range sortedRegistryChildren(node) {
		child.parent = node.cell
		child.listCell = 0xffffffff
		child.valCell = 0xffffffff
		child.cell = w.writeKey(child, len(child.subkeys), len(child.values))
		if err := w.writeTree(child); err != nil {
			return err
		}
	}
	valueNames := sortedRegistryValueNames(node)
	valueCells := make([]uint32, 0, len(valueNames))
	for _, name := range valueNames {
		cell, err := w.writeValue(name, node.values[name])
		if err != nil {
			return err
		}
		valueCells = append(valueCells, cell)
	}
	if len(valueCells) > 0 {
		node.valCell = w.writeValueList(valueCells)
	} else {
		node.valCell = 0xffffffff
	}
	children := sortedRegistryChildren(node)
	if len(children) > 0 {
		node.listCell = w.writeSubkeyList(children)
	} else {
		node.listCell = 0xffffffff
	}
	classCell := uint32(0xffffffff)
	if len(node.class) > 0 {
		classCell = w.writeRawCell(node.class)
	}
	security := node.security
	if len(security) == 0 {
		security = defaultRegistrySecurityDescriptor()
	}
	w.patchKeyReferences(node.cell, node.listCell, node.valCell, w.securityCells[string(security)], classCell, len(node.class))
	return nil
}

func (w *hiveWriter) writeValue(name string, value registryData) (uint32, error) {
	hiveName := name
	if isDefaultRegistryValueName(name) {
		hiveName = ""
	}
	nameBytes := []byte(hiveName)
	dataLength := uint32(len(value.data))
	dataCell := uint32(0)
	if len(value.data) <= 4 {
		dataLength |= 0x80000000
		var inline [4]byte
		copy(inline[:], value.data)
		dataCell = binary.LittleEndian.Uint32(inline[:])
	} else {
		dataCell = w.writeRawCell(value.data)
	}
	body := make([]byte, 0x14+len(nameBytes))
	copy(body[0:2], "vk")
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint32(body[4:8], dataLength)
	binary.LittleEndian.PutUint32(body[8:12], dataCell)
	binary.LittleEndian.PutUint32(body[12:16], value.typ)
	binary.LittleEndian.PutUint16(body[16:18], 1)
	copy(body[0x14:], nameBytes)
	return w.writeCell(body), nil
}

func (w *hiveWriter) writeValueList(cells []uint32) uint32 {
	body := make([]byte, len(cells)*4)
	for i, cell := range cells {
		binary.LittleEndian.PutUint32(body[i*4:i*4+4], cell)
	}
	return w.writeCell(body)
}

func (w *hiveWriter) writeSubkeyList(children []*registryTree) uint32 {
	leafEntries := registrySubkeyLeafEntries
	if w.format.minor == 2 {
		leafEntries = registrySubkeyIndexEntries
	}
	if len(children) <= leafEntries {
		return w.writeSubkeyLeaf(children)
	}
	leaves := make([]uint32, 0, (len(children)+leafEntries-1)/leafEntries)
	for start := 0; start < len(children); start += leafEntries {
		end := min(start+leafEntries, len(children))
		leaves = append(leaves, w.writeSubkeyLeaf(children[start:end]))
	}
	body := make([]byte, 4+len(leaves)*4)
	copy(body[0:2], "ri")
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(leaves)))
	for i, leaf := range leaves {
		binary.LittleEndian.PutUint32(body[4+i*4:8+i*4], leaf)
	}
	return w.writeCell(body)
}

func (w *hiveWriter) writeSubkeyLeaf(children []*registryTree) uint32 {
	entrySize := 8
	if w.format.minor == 2 {
		entrySize = 4
	}
	body := make([]byte, 4+len(children)*entrySize)
	if w.format.minor == 2 {
		copy(body[0:2], "li")
	} else if w.format.minor >= 5 {
		copy(body[0:2], "lh")
	} else {
		copy(body[0:2], "lf")
	}
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(children)))
	for i, child := range children {
		offset := 4 + i*entrySize
		binary.LittleEndian.PutUint32(body[offset:offset+4], child.cell)
		if w.format.minor == 2 {
			continue
		} else if w.format.minor >= 5 {
			binary.LittleEndian.PutUint32(body[offset+4:offset+8], registryNameHash(child.name))
		} else {
			copy(body[offset+4:offset+8], registryFastLeafHint(child.name))
		}
	}
	return w.writeCell(body)
}

func registryFastLeafHint(name string) []byte {
	hint := make([]byte, 4)
	copy(hint, []byte(strings.ToUpper(name)))
	return hint
}

func registryNameHash(name string) uint32 {
	var hash uint32
	for _, r := range strings.ToUpper(name) {
		hash = hash*37 + uint32(r)
	}
	return hash
}

func (w *hiveWriter) writeKey(node *registryTree, subkeys, values int) uint32 {
	flags := node.flags
	if !node.flagsSet {
		flags = 0x20
		if node.name == "SYSTEM" || node.name == "SOFTWARE" || node.name == "DEFAULT" || node.name == "SAM" || node.name == "SECURITY" {
			flags |= 0x000c
		}
	}
	nameBytes := []byte(node.name)
	if flags&0x20 == 0 {
		nameBytes = utf16Bytes(node.name)
	}
	body := make([]byte, 0x4c+len(nameBytes))
	copy(body[0:2], "nk")
	binary.LittleEndian.PutUint16(body[2:4], flags)
	t := uint64(windowsFiletime(time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)))
	binary.LittleEndian.PutUint64(body[4:12], t)
	binary.LittleEndian.PutUint32(body[0x10:0x14], node.parent)
	binary.LittleEndian.PutUint32(body[0x14:0x18], uint32(subkeys))
	binary.LittleEndian.PutUint32(body[0x1c:0x20], node.listCell)
	binary.LittleEndian.PutUint32(body[0x20:0x24], 0xffffffff)
	binary.LittleEndian.PutUint32(body[0x24:0x28], uint32(values))
	binary.LittleEndian.PutUint32(body[0x28:0x2c], node.valCell)
	binary.LittleEndian.PutUint32(body[0x2c:0x30], 0xffffffff)
	binary.LittleEndian.PutUint32(body[0x30:0x34], 0xffffffff)
	binary.LittleEndian.PutUint32(body[0x34:0x38], uint32(maxRegistrySubkeyNameLen(node)))
	binary.LittleEndian.PutUint32(body[0x38:0x3c], uint32(maxRegistrySubkeyClassLen(node)))
	binary.LittleEndian.PutUint32(body[0x3c:0x40], uint32(maxRegistryValueNameLen(node)))
	binary.LittleEndian.PutUint32(body[0x40:0x44], uint32(maxRegistryValueDataLen(node)))
	binary.LittleEndian.PutUint16(body[0x48:0x4a], uint16(len(nameBytes)))
	copy(body[0x4c:], nameBytes)
	return w.writeCell(body)
}

func (w *hiveWriter) writeSecurity(descriptor []byte, refcount int) uint32 {
	body := make([]byte, 0x14+len(descriptor))
	copy(body[0:2], "sk")
	cell := w.nextCell(len(body))
	binary.LittleEndian.PutUint32(body[0x04:0x08], cell)
	binary.LittleEndian.PutUint32(body[0x08:0x0c], cell)
	binary.LittleEndian.PutUint32(body[0x0c:0x10], uint32(refcount))
	binary.LittleEndian.PutUint32(body[0x10:0x14], uint32(len(descriptor)))
	copy(body[0x14:], descriptor)
	return w.writeCell(body)
}

func (w *hiveWriter) patchKeyReferences(cell, subkeyList, valueList, securityCell, classCell uint32, classLen int) {
	offset := int(cell) + 4
	binary.LittleEndian.PutUint32(w.data[offset+0x1c:offset+0x20], subkeyList)
	binary.LittleEndian.PutUint32(w.data[offset+0x28:offset+0x2c], valueList)
	binary.LittleEndian.PutUint32(w.data[offset+0x2c:offset+0x30], securityCell)
	binary.LittleEndian.PutUint32(w.data[offset+0x30:offset+0x34], classCell)
	binary.LittleEndian.PutUint16(w.data[offset+0x4a:offset+0x4c], uint16(classLen))
}

func (w *hiveWriter) writeRawCell(data []byte) uint32 {
	return w.writeCell(data)
}

func (w *hiveWriter) writeCell(body []byte) uint32 {
	size := align8(len(body) + 4)
	cell := w.nextCell(len(body))
	binary.LittleEndian.PutUint32(w.data[w.cellOffset:w.cellOffset+4], uint32(int32(-size)))
	copy(w.data[w.cellOffset+4:w.cellOffset+size], body)
	w.cellOffset += size
	return cell
}

func (w *hiveWriter) nextCell(bodySize int) uint32 {
	needed := align8(bodySize + 4)
	if w.cellOffset == 0 || w.cellOffset+needed > w.binEnd {
		w.finishBin()
		w.startBin(needed)
	}
	return uint32(w.cellOffset)
}

func (w *hiveWriter) startBin(needed int) {
	binSize := int(alignInt64(int64(0x20+needed), hiveBaseBlockSize))
	for len(w.data)%binSize != 0 {
		w.appendEmptyBin()
	}
	w.binStart = len(w.data)
	w.binEnd = w.binStart + binSize
	w.data = append(w.data, make([]byte, binSize)...)
	copy(w.data[w.binStart:w.binStart+4], "hbin")
	binary.LittleEndian.PutUint32(w.data[w.binStart+4:w.binStart+8], uint32(w.binStart))
	binary.LittleEndian.PutUint32(w.data[w.binStart+8:w.binStart+12], uint32(binSize))
	w.cellOffset = w.binStart + 0x20
}

func (w *hiveWriter) appendEmptyBin() {
	start := len(w.data)
	w.data = append(w.data, make([]byte, hiveBaseBlockSize)...)
	copy(w.data[start:start+4], "hbin")
	binary.LittleEndian.PutUint32(w.data[start+4:start+8], uint32(start))
	binary.LittleEndian.PutUint32(w.data[start+8:start+12], hiveBaseBlockSize)
	binary.LittleEndian.PutUint32(w.data[start+0x20:start+0x24], hiveBaseBlockSize-0x20)
}

func (w *hiveWriter) finishBin() {
	if w.cellOffset == 0 || w.cellOffset >= w.binEnd {
		return
	}
	remaining := w.binEnd - w.cellOffset
	if remaining >= 8 {
		binary.LittleEndian.PutUint32(w.data[w.cellOffset:w.cellOffset+4], uint32(remaining))
	}
	w.cellOffset = 0
	w.binStart = 0
	w.binEnd = 0
}

func sortedRegistryChildren(node *registryTree) []*registryTree {
	keys := make([]string, 0, len(node.subkeys))
	for key := range node.subkeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]*registryTree, len(keys))
	for i, key := range keys {
		out[i] = node.subkeys[key]
	}
	return out
}

func sortedRegistryValueNames(node *registryTree) []string {
	names := make([]string, 0, len(node.values))
	for name := range node.values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func countRegistryKeys(node *registryTree) int {
	total := 1
	for _, child := range node.subkeys {
		total += countRegistryKeys(child)
	}
	return total
}

func validateSelfRelativeSecurityDescriptor(descriptor []byte) error {
	if len(descriptor) < 20 || descriptor[0] != 1 {
		return fmt.Errorf("invalid self-relative security descriptor header")
	}
	if binary.LittleEndian.Uint16(descriptor[2:4])&0x8000 == 0 {
		return fmt.Errorf("security descriptor is not self-relative")
	}
	for _, field := range []struct {
		offset int
		acl    bool
	}{
		{4, false},
		{8, false},
		{12, true},
		{16, true},
	} {
		start := int(binary.LittleEndian.Uint32(descriptor[field.offset : field.offset+4]))
		if start == 0 {
			continue
		}
		if start < 20 || start >= len(descriptor) {
			return fmt.Errorf("security descriptor component offset %#x is outside descriptor", start)
		}
		if field.acl {
			if len(descriptor)-start < 8 {
				return fmt.Errorf("truncated ACL in security descriptor")
			}
			size := int(binary.LittleEndian.Uint16(descriptor[start+2 : start+4]))
			if size < 8 || size > len(descriptor)-start {
				return fmt.Errorf("invalid ACL size in security descriptor")
			}
			continue
		}
		if len(descriptor)-start < 8 {
			return fmt.Errorf("truncated SID in security descriptor")
		}
		size := 8 + int(descriptor[start+1])*4
		if size > len(descriptor)-start {
			return fmt.Errorf("truncated SID subauthorities in security descriptor")
		}
	}
	return nil
}

func (w *hiveWriter) writeSecurityCells(root *registryTree) error {
	descriptors := make(map[string][]byte)
	refcounts := make(map[string]int)
	var collect func(*registryTree) error
	collect = func(node *registryTree) error {
		descriptor := node.security
		if len(descriptor) == 0 {
			descriptor = defaultRegistrySecurityDescriptor()
		}
		if err := validateSelfRelativeSecurityDescriptor(descriptor); err != nil {
			return fmt.Errorf("registry key %q security: %w", node.name, err)
		}
		key := string(descriptor)
		descriptors[key] = descriptor
		refcounts[key]++
		for _, child := range node.subkeys {
			if err := collect(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := collect(root); err != nil {
		return err
	}
	keys := make([]string, 0, len(descriptors))
	for key := range descriptors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	cells := make([]uint32, len(keys))
	for index, key := range keys {
		cells[index] = w.writeSecurity(descriptors[key], refcounts[key])
		w.securityCells[key] = cells[index]
	}
	for index, cell := range cells {
		previous := cells[(index+len(cells)-1)%len(cells)]
		next := cells[(index+1)%len(cells)]
		body := int(cell) + 4
		binary.LittleEndian.PutUint32(w.data[body+0x04:body+0x08], next)
		binary.LittleEndian.PutUint32(w.data[body+0x08:body+0x0c], previous)
	}
	return nil
}

func defaultRegistrySecurityDescriptor() []byte {
	system := registrySID(5, 18)
	administrators := registrySID(5, 32, 544)
	sids := [][]byte{administrators, system}
	aclSize := 8
	for _, sid := range sids {
		aclSize += 8 + len(sid)
	}
	ownerOffset := 20 + aclSize
	groupOffset := ownerOffset + len(administrators)
	descriptor := make([]byte, groupOffset+len(administrators))
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(descriptor[2:4], 0x8004)
	binary.LittleEndian.PutUint32(descriptor[4:8], uint32(ownerOffset))
	binary.LittleEndian.PutUint32(descriptor[8:12], uint32(groupOffset))
	binary.LittleEndian.PutUint32(descriptor[16:20], 20)
	acl := descriptor[20:]
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(sids)))
	offset := 8
	for _, sid := range sids {
		aceSize := 8 + len(sid)
		acl[offset] = 0
		binary.LittleEndian.PutUint16(acl[offset+2:offset+4], uint16(aceSize))
		binary.LittleEndian.PutUint32(acl[offset+4:offset+8], 0x000f003f)
		copy(acl[offset+8:offset+aceSize], sid)
		offset += aceSize
	}
	copy(descriptor[ownerOffset:], administrators)
	copy(descriptor[groupOffset:], administrators)
	return descriptor
}

func registrySID(authority byte, subauth ...uint32) []byte {
	sid := make([]byte, 8+len(subauth)*4)
	sid[0] = 1
	sid[1] = byte(len(subauth))
	sid[7] = authority
	for i, v := range subauth {
		binary.LittleEndian.PutUint32(sid[8+i*4:12+i*4], v)
	}
	return sid
}

func utf16Nul(s string) []byte {
	units := utf16.Encode([]rune(s + "\x00"))
	data := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(data[i*2:i*2+2], unit)
	}
	return data
}

var _ = crc32.ChecksumIEEE
