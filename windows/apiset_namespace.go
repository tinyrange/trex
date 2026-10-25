package windows

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func apiSetUTF16(data []byte, offset, length uint64) (string, error) {
	if length == 0 {
		return "", nil
	}
	if offset == 0 || length&1 != 0 || offset > uint64(len(data)) || length > uint64(len(data))-offset {
		return "", fmt.Errorf("invalid API-set UTF-16 range")
	}
	value := data[offset : offset+length]
	units := make([]uint16, len(value)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(value[i*2:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 {
			return "", fmt.Errorf("embedded NUL in API-set string")
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("unpaired API-set surrogate")
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", fmt.Errorf("unpaired API-set surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}

// Version 6 is the in-memory PEB namespace and the base .apiset section.
// Unlike a v7 extension, all lengths here are byte counts, not characters.
func parseAPISetNamespace(data []byte) (starlark.Value, error) {
	if len(data) < 28 || binary.LittleEndian.Uint32(data) != 6 {
		return nil, fmt.Errorf("expected version 6 API-set namespace")
	}
	size := binary.LittleEndian.Uint32(data[4:])
	if size < 28 || uint64(size) > uint64(len(data)) {
		return nil, fmt.Errorf("truncated API-set namespace")
	}
	data = data[:size]
	span := func(offset, length uint64) ([]byte, error) {
		if offset > uint64(len(data)) || length > uint64(len(data))-offset {
			return nil, fmt.Errorf("API-set table outside namespace")
		}
		return data[offset : offset+length], nil
	}
	count := binary.LittleEndian.Uint32(data[12:])
	entries, err := span(uint64(binary.LittleEndian.Uint32(data[16:])), uint64(count)*24)
	if err != nil {
		return nil, err
	}
	hashes, err := span(uint64(binary.LittleEndian.Uint32(data[20:])), uint64(count)*8)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < count; i++ {
		if binary.LittleEndian.Uint32(hashes[uint64(i)*8+4:]) >= count {
			return nil, fmt.Errorf("API-set hash index outside entry table")
		}
	}
	var contracts []starlark.Value
	seen := make(map[string]bool)
	for i := uint32(0); i < count; i++ {
		e := entries[uint64(i)*24 : uint64(i+1)*24]
		length, hashed := binary.LittleEndian.Uint32(e[8:]), binary.LittleEndian.Uint32(e[12:])
		if length == 0 || hashed > length || hashed&1 != 0 {
			return nil, fmt.Errorf("invalid API-set name/hash length")
		}
		name, err := apiSetUTF16(data, uint64(binary.LittleEndian.Uint32(e[4:])), uint64(length))
		if err != nil {
			return nil, err
		}
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("duplicate API-set contract")
		}
		seen[strings.ToLower(name)] = true
		values, err := span(uint64(binary.LittleEndian.Uint32(e[16:])), uint64(binary.LittleEndian.Uint32(e[20:]))*20)
		if err != nil {
			return nil, err
		}
		var hosts []starlark.Value
		for at := 0; at < len(values); at += 20 {
			v := values[at : at+20]
			alias, err := apiSetUTF16(data, uint64(binary.LittleEndian.Uint32(v[4:])), uint64(binary.LittleEndian.Uint32(v[8:])))
			if err != nil {
				return nil, err
			}
			host, err := apiSetUTF16(data, uint64(binary.LittleEndian.Uint32(v[12:])), uint64(binary.LittleEndian.Uint32(v[16:])))
			if err != nil {
				return nil, err
			}
			h := starlark.NewDict(3)
			h.SetKey(starlark.String("flags"), starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(v))))
			h.SetKey(starlark.String("alias"), starlark.String(alias))
			h.SetKey(starlark.String("host"), starlark.String(host))
			hosts = append(hosts, h)
		}
		c := starlark.NewDict(4)
		c.SetKey(starlark.String("name"), starlark.String(name))
		c.SetKey(starlark.String("flags"), starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(e))))
		c.SetKey(starlark.String("hashed_length"), starlark.MakeUint64(uint64(hashed)))
		c.SetKey(starlark.String("hosts"), starlark.NewList(hosts))
		contracts = append(contracts, c)
	}
	result := starlark.NewDict(4)
	result.SetKey(starlark.String("version"), starlark.MakeInt(6))
	result.SetKey(starlark.String("flags"), starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(data[8:]))))
	result.SetKey(starlark.String("hash_factor"), starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(data[24:]))))
	result.SetKey(starlark.String("contracts"), starlark.NewList(contracts))
	result.Freeze()
	return result, nil
}

func apiSetNamespaceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("api_set_namespace", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("api_set_namespace: expected file")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return parseAPISetNamespace(data)
}
