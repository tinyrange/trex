package nsis

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// NSIS 3 Unicode offsets address UTF-16LE units, not bytes. Wire control
// values are LANG=1, SHELL=2, VAR=3, ESCAPE=4 (exehead/fileform.h).
// A reference's following unit contains two seven-bit value bytes; shell
// references preserve those bytes instead of interpreting a host folder.
func decodeUTF16String(table []byte, offset int32) (string, []byte, error) {
	if offset < 0 {
		return fmt.Sprintf("${LANG:%d}", -int64(offset)-1), nil, nil
	}
	start := int64(offset) * 2
	if len(table)%2 != 0 || start >= int64(len(table)) {
		return "", nil, fmt.Errorf("UTF-16 string offset out of bounds")
	}
	src := table[int(start):]
	var out strings.Builder
	for pos := 0; ; {
		if pos/2 > 65536 {
			return "", nil, ErrLimit
		}
		if pos+2 > len(src) {
			return "", nil, fmt.Errorf("unterminated UTF-16 string")
		}
		at := pos
		unit := binary.LittleEndian.Uint16(src[pos:])
		pos += 2
		if unit == 0 {
			return out.String(), src[:at], nil
		}
		if unit <= 4 {
			if pos+2 > len(src) {
				return "", nil, fmt.Errorf("truncated UTF-16 string code")
			}
			value := binary.LittleEndian.Uint16(src[pos:])
			pos += 2
			if value == 0 {
				return "", nil, fmt.Errorf("empty UTF-16 string code")
			}
			if unit != 4 {
				a, b := byte(value), byte(value>>8)
				number := int(a&127) | int(b&127)<<7
				switch unit {
				case 1:
					fmt.Fprintf(&out, "${LANG:%d}", number)
				case 2:
					fmt.Fprintf(&out, "${SHELL:%02x,%02x}", a, b)
				case 3:
					out.WriteString(variable(number))
				}
				continue
			}
			unit = value
		}
		var char rune = rune(unit)
		if unit >= 0xd800 && unit <= 0xdbff {
			if pos+2 > len(src) {
				return "", nil, fmt.Errorf("truncated UTF-16 surrogate")
			}
			low := binary.LittleEndian.Uint16(src[pos:])
			pos += 2
			if low < 0xdc00 || low > 0xdfff {
				return "", nil, fmt.Errorf("invalid UTF-16 surrogate")
			}
			char = utf16.DecodeRune(rune(unit), rune(low))
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return "", nil, fmt.Errorf("unpaired UTF-16 surrogate")
		}
		if char == '$' {
			out.WriteByte('$')
		}
		out.WriteRune(char)
	}
}
