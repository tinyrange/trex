package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type apiSetExtension struct {
	name      string
	flags     uint16
	contracts []apiSetContract
}

type apiSetContract struct {
	name              string
	metadata, version uint32
	hosts             []apiSetHost
}

type apiSetHost struct {
	host, alias string
	metadata    uint32
}

// Version 7 extensions use ASCII contract/package names and counted UTF-16
// host/alias strings. They are distinct from a version 6 base namespace.
// Offsets remain relative to .apiset, including shared host records.
func parseAPISetExtension(data []byte) (*apiSetExtension, error) {
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	var section *pe.Section
	for _, s := range image.Sections {
		if s.Name == ".apiset" {
			if section != nil {
				return nil, fmt.Errorf("ambiguous .apiset section")
			}
			section = s
		}
	}
	if section == nil || section.Size < 20 || uint64(section.Offset)+uint64(section.Size) > uint64(len(data)) {
		return nil, fmt.Errorf("missing or truncated .apiset section")
	}
	b := data[section.Offset : uint64(section.Offset)+uint64(section.Size)]
	if binary.LittleEndian.Uint16(b) != 7 {
		return nil, fmt.Errorf("expected version 7 API-set extension")
	}
	size := binary.LittleEndian.Uint32(b[4:])
	if size < 20 || size > uint32(len(b)) || size > section.VirtualSize {
		return nil, fmt.Errorf("invalid API-set extension size")
	}
	b = b[:size]
	span := func(offset, length uint64) ([]byte, error) {
		if offset > uint64(len(b)) || length > uint64(len(b))-offset {
			return nil, fmt.Errorf("API-set range outside namespace")
		}
		return b[offset : offset+length], nil
	}
	ascii := func(offset uint32, length uint16) (string, error) {
		value, err := span(uint64(offset), uint64(length)+1)
		if err != nil {
			return "", err
		}
		if length == 0 || value[length] != 0 {
			return "", fmt.Errorf("unterminated API-set name")
		}
		for _, ch := range value[:length] {
			if ch < 0x20 || ch > 0x7e {
				return "", fmt.Errorf("non-ASCII API-set name")
			}
		}
		return string(value[:length]), nil
	}
	wide := func(offset, length uint32) (string, error) {
		return apiSetUTF16(b, uint64(offset), uint64(length)*2)
	}

	result := &apiSetExtension{flags: binary.LittleEndian.Uint16(b[2:])}
	result.name, err = ascii(binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint16(b[16:]))
	if err != nil {
		return nil, err
	}
	entryOffset, count := binary.LittleEndian.Uint32(b[12:]), binary.LittleEndian.Uint16(b[18:])
	if entryOffset < 20 {
		return nil, fmt.Errorf("API-set entries overlap header")
	}
	entries, err := span(uint64(entryOffset), uint64(count)*20)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for i := 0; i < int(count); i++ {
		e := entries[i*20 : (i+1)*20]
		contract := apiSetContract{metadata: binary.LittleEndian.Uint32(e[12:]), version: binary.LittleEndian.Uint32(e[16:])}
		contract.name, err = ascii(binary.LittleEndian.Uint32(e), binary.LittleEndian.Uint16(e[8:]))
		if err != nil {
			return nil, err
		}
		if seen[strings.ToLower(contract.name)] {
			return nil, fmt.Errorf("duplicate API-set contract")
		}
		seen[strings.ToLower(contract.name)] = true
		values, err := span(uint64(binary.LittleEndian.Uint32(e[4:])), uint64(binary.LittleEndian.Uint16(e[10:]))*16)
		if err != nil {
			return nil, err
		}
		for at := 0; at < len(values); at += 16 {
			v := values[at : at+16]
			host, err := wide(binary.LittleEndian.Uint32(v), uint32(binary.LittleEndian.Uint16(v[8:])))
			if err != nil {
				return nil, err
			}
			alias, err := wide(binary.LittleEndian.Uint32(v[4:]), uint32(binary.LittleEndian.Uint16(v[10:])))
			if err != nil {
				return nil, err
			}
			contract.hosts = append(contract.hosts, apiSetHost{host, alias, binary.LittleEndian.Uint32(v[12:])})
		}
		result.contracts = append(result.contracts, contract)
	}
	return result, nil
}

func apiSetExtensionValue(extension *apiSetExtension) (starlark.Value, error) {
	out := starlark.NewDict(4)
	out.SetKey(starlark.String("name"), starlark.String(extension.name))
	out.SetKey(starlark.String("version"), starlark.MakeInt(7))
	out.SetKey(starlark.String("flags"), starlark.MakeInt(int(extension.flags)))
	var contracts []starlark.Value
	for _, c := range extension.contracts {
		d := starlark.NewDict(4)
		d.SetKey(starlark.String("name"), starlark.String(c.name))
		d.SetKey(starlark.String("metadata"), starlark.MakeUint64(uint64(c.metadata)))
		d.SetKey(starlark.String("version"), starlark.MakeUint64(uint64(c.version)))
		var hosts []starlark.Value
		for _, h := range c.hosts {
			value := starlark.NewDict(3)
			value.SetKey(starlark.String("host"), starlark.String(h.host))
			value.SetKey(starlark.String("alias"), starlark.String(h.alias))
			value.SetKey(starlark.String("metadata"), starlark.MakeUint64(uint64(h.metadata)))
			hosts = append(hosts, value)
		}
		d.SetKey(starlark.String("hosts"), starlark.NewList(hosts))
		contracts = append(contracts, d)
	}
	out.SetKey(starlark.String("contracts"), starlark.NewList(contracts))
	return out, nil
}

func peAPISetExtensionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("api_set_extension", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("api_set_extension: expected file")
	}
	data, err := peReadSnapshotData(file)
	if err != nil {
		return nil, err
	}
	extension, err := parseAPISetExtension(data)
	if err != nil {
		return nil, err
	}
	return apiSetExtensionValue(extension)
}
