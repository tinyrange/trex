package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"

	"go.starlark.net/starlark"
)

type dosSetverTable struct {
	start   int
	end     int
	entries int
}

func windowsSetverBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starfile.File
	var name string
	var major, minor int
	maximum := 16 << 20
	if err := starlark.UnpackArgs("setver", args, kwargs, "source", &source, "name", &name, "major", &major, "minor", &minor, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("setver: maximum must be positive")
	}
	name = strings.ToUpper(name)
	if !validDOSSetverName(name) {
		return nil, fmt.Errorf("setver: name %q is not an uppercase DOS filename of at most 12 characters", name)
	}
	if major < 0 || major > 255 || minor < 0 || minor > 99 {
		return nil, fmt.Errorf("setver: version %d.%d is out of range", major, minor)
	}
	data, err := bytesForBinaryValueLimited(source, int64(maximum))
	if err != nil {
		return nil, fmt.Errorf("setver: %w", err)
	}
	table, err := findDOSSetverTable(data)
	if err != nil {
		return nil, fmt.Errorf("setver: %w", err)
	}
	patched := append([]byte(nil), data...)
	for cursor := table.start; cursor < table.end; {
		length := int(patched[cursor])
		if string(patched[cursor+1:cursor+1+length]) == name {
			patched[cursor+1+length] = byte(major)
			patched[cursor+2+length] = byte(minor)
			return &starfile.Bytes{Name: "SETVER.EXE", Data: patched}, nil
		}
		cursor += length + 3
	}
	required := len(name) + 4 // length, name, version pair, and new terminator
	if table.end+required > len(patched) {
		return nil, fmt.Errorf("version table has no room for %q", name)
	}
	for offset := table.end; offset < table.end+required; offset++ {
		if patched[offset] != 0 {
			return nil, fmt.Errorf("version table has no room for %q", name)
		}
	}
	patched[table.end] = byte(len(name))
	copy(patched[table.end+1:], name)
	patched[table.end+1+len(name)] = byte(major)
	patched[table.end+2+len(name)] = byte(minor)
	patched[table.end+3+len(name)] = 0
	return &starfile.Bytes{Name: "SETVER.EXE", Data: patched}, nil
}

func findDOSSetverTable(data []byte) (dosSetverTable, error) {
	best := dosSetverTable{}
	ambiguous := false
	for start := 0; start < len(data); start++ {
		cursor := start
		entries := 0
		for cursor < len(data) && data[cursor] != 0 {
			length := int(data[cursor])
			if length < 1 || length > 12 || cursor+length+3 > len(data) || !validDOSSetverName(string(data[cursor+1:cursor+1+length])) || data[cursor+1+length] < 2 || data[cursor+2+length] > 99 {
				entries = 0
				break
			}
			entries++
			cursor += length + 3
		}
		if entries < 4 || cursor >= len(data) || data[cursor] != 0 {
			continue
		}
		if entries > best.entries {
			best = dosSetverTable{start: start, end: cursor, entries: entries}
			ambiguous = false
		} else if entries == best.entries && start != best.start {
			ambiguous = true
		}
	}
	if best.entries == 0 {
		return dosSetverTable{}, fmt.Errorf("could not locate a DOS SETVER version table")
	}
	if ambiguous {
		return dosSetverTable{}, fmt.Errorf("DOS SETVER version table is ambiguous")
	}
	return best, nil
}

func validDOSSetverName(name string) bool {
	if len(name) == 0 || len(name) > 12 {
		return false
	}
	for _, character := range []byte(name) {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.$~!#%&-{}()@'^`", rune(character)) {
			continue
		}
		return false
	}
	return true
}
