package udf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// udfSymlinkTarget decodes ECMA-167 section 4/14.16 path components, with
// UDF CS0 compressed Unicode identifiers. Keep '..' and '.' components as
// recorded: cleaning the path could change its meaning through another link.
func udfSymlinkTarget(data []byte) (string, error) {
	var components []string
	absolute := false
	for len(data) > 0 {
		if len(data) < 4 || int(data[1]) > len(data)-4 {
			return "", fmt.Errorf("udf: truncated symbolic link component")
		}
		kind := data[0]
		n := int(data[1])
		identifier := data[4 : 4+n]
		data = data[4+n:]
		switch kind {
		case 1, 2:
			if n != 0 {
				return "", fmt.Errorf("udf: named volume or external symbolic link root is unsupported")
			}
			if absolute || len(components) != 0 {
				return "", fmt.Errorf("udf: misplaced symbolic link root")
			}
			absolute = true
		case 3, 4:
			if n != 0 {
				return "", fmt.Errorf("udf: invalid special symbolic link component")
			}
			component := ".."
			if kind == 4 {
				component = "."
			}
			components = append(components, component)
		case 5:
			name, err := udfLinkIdentifier(identifier)
			if err != nil {
				return "", err
			}
			components = append(components, name)
		default:
			return "", fmt.Errorf("udf: unsupported symbolic link component type %d", kind)
		}
	}
	result := strings.Join(components, "/")
	if absolute {
		result = "/" + result
	}
	if result == "" {
		return "", fmt.Errorf("udf: empty symbolic link")
	}
	return result, nil
}

func udfLinkIdentifier(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("udf: empty symbolic link identifier")
	}
	var units []uint16
	switch data[0] {
	case 8:
		for _, c := range data[1:] {
			units = append(units, uint16(c))
		}
	case 16:
		if len(data)%2 != 1 {
			return "", fmt.Errorf("udf: odd symbolic link Unicode length")
		}
		for pos := 1; pos < len(data); pos += 2 {
			units = append(units, binary.BigEndian.Uint16(data[pos:]))
		}
	default:
		return "", fmt.Errorf("udf: invalid symbolic link Unicode compression %d", data[0])
	}
	for pos := 0; pos < len(units); pos++ {
		c := units[pos]
		if c == 0 || c == '/' {
			return "", fmt.Errorf("udf: invalid symbolic link identifier")
		}
		if c >= 0xd800 && c <= 0xdbff {
			pos++
			if pos >= len(units) || units[pos] < 0xdc00 || units[pos] > 0xdfff {
				return "", fmt.Errorf("udf: invalid symbolic link surrogate")
			}
		} else if c >= 0xdc00 && c <= 0xdfff {
			return "", fmt.Errorf("udf: invalid symbolic link surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}
