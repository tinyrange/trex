package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"unicode/utf16"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

func utf16StringsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	minimum := 4
	if err := starlark.UnpackArgs("utf16_strings", args, kwargs, "file", &value, "minimum?", &minimum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("utf16_strings: got %s, want file", value.Type())
	}
	if minimum < 1 {
		return nil, fmt.Errorf("utf16_strings: minimum must be positive")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("utf16_strings: %w", err)
	}
	stringsValue := scanUTF16Strings(data, minimum)
	values := make([]starlark.Value, len(stringsValue))
	for index, value := range stringsValue {
		values[index] = starlark.String(value)
	}
	return starlark.NewList(values), nil
}

func scanUTF16Strings(data []byte, minimum int) []string {
	seen := make(map[string]struct{})
	var out []string
	// Reuse scratch space across candidates, most of which are rejected as
	// binary data. Decoding accepted strings produces independently owned text.
	var units []uint16
	for alignment := 0; alignment < 2; alignment++ {
		for offset := alignment; offset+1 < len(data); {
			units = units[:0]
			ascii := 0
			for offset+1 < len(data) {
				unit := uint16(data[offset]) | uint16(data[offset+1])<<8
				if unit == 0 || (unit < 0x20 && unit != '\t') || unit == 0xffff {
					break
				}
				units = append(units, unit)
				if unit <= 0x7e {
					ascii++
				}
				offset += 2
			}
			if len(units) >= minimum && ascii*2 >= len(units) {
				value := string(utf16.Decode(units))
				if utf8.ValidString(value) {
					if _, exists := seen[value]; !exists {
						seen[value] = struct{}{}
						out = append(out, value)
					}
				}
			}
			offset += 2
		}
	}
	return out
}
