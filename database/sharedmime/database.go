// Package sharedmime compiles the freedesktop.org Shared MIME-info lookup files.
package sharedmime

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

type database struct {
	XMLName xml.Name   `xml:"http://www.freedesktop.org/standards/shared-mime-info mime-info"`
	Types   []mimeType `xml:"mime-type"`
}

type mimeType struct {
	Name       string      `xml:"type,attr"`
	Globs      []glob      `xml:"glob"`
	Magic      []magic     `xml:"magic"`
	Aliases    []typeRef   `xml:"alias"`
	Parents    []typeRef   `xml:"sub-class-of"`
	Namespaces []namespace `xml:"root-XML"`
	Icon       icon        `xml:"icon"`
	Generic    icon        `xml:"generic-icon"`
}

type typeRef struct {
	Name string `xml:"type,attr"`
}

type icon struct {
	Name string `xml:"name,attr"`
}

type namespace struct {
	URI   string `xml:"namespaceURI,attr"`
	Local string `xml:"localName,attr"`
}

type glob struct {
	Pattern string `xml:"pattern,attr"`
	Weight  *int   `xml:"weight,attr"`
	Exact   bool   `xml:"case-sensitive,attr"`
}

type magic struct {
	Priority *int    `xml:"priority,attr"`
	Matches  []match `xml:"match"`
}

type match struct {
	Type     string  `xml:"type,attr"`
	Offset   string  `xml:"offset,attr"`
	Value    string  `xml:"value,attr"`
	Mask     string  `xml:"mask,attr"`
	Children []match `xml:"match"`
}

type namedMagic struct {
	name     string
	priority int
	matches  []match
}

// Compile builds the non-mmap lookup representation from a package XML stream.
// Consumers can use these files without the optional binary mime.cache.
func Compile(source io.Reader) (map[string][]byte, error) {
	var db database
	if err := xml.NewDecoder(source).Decode(&db); err != nil {
		return nil, fmt.Errorf("shared MIME-info: %w", err)
	}
	lines := map[string][]string{
		"aliases": nil, "subclasses": nil, "XMLnamespaces": nil,
		"globs": nil, "globs2": nil, "types": nil, "icons": nil, "generic-icons": nil,
	}
	var entries []namedMagic
	for _, mime := range db.Types {
		if !validType(mime.Name) {
			return nil, fmt.Errorf("shared MIME-info: invalid type %q", mime.Name)
		}
		lines["types"] = append(lines["types"], mime.Name)
		for _, alias := range mime.Aliases {
			if !validType(alias.Name) {
				return nil, fmt.Errorf("shared MIME-info: invalid alias %q", alias.Name)
			}
			lines["aliases"] = append(lines["aliases"], alias.Name+" "+mime.Name)
		}
		for _, parent := range mime.Parents {
			if !validType(parent.Name) {
				return nil, fmt.Errorf("shared MIME-info: invalid parent %q", parent.Name)
			}
			lines["subclasses"] = append(lines["subclasses"], mime.Name+" "+parent.Name)
		}
		for _, ns := range mime.Namespaces {
			if strings.ContainsAny(ns.URI+ns.Local, " \t\r\n\x00") {
				return nil, fmt.Errorf("shared MIME-info: invalid XML namespace for %s", mime.Name)
			}
			lines["XMLnamespaces"] = append(lines["XMLnamespaces"], ns.URI+" "+ns.Local+" "+mime.Name)
		}
		for _, pattern := range mime.Globs {
			weight, err := priority(pattern.Weight)
			if err != nil || pattern.Pattern == "" || strings.ContainsAny(pattern.Pattern, "\r\n\x00") {
				return nil, fmt.Errorf("shared MIME-info: invalid glob for %s", mime.Name)
			}
			value := mime.Name + ":" + pattern.Pattern
			lines["globs"] = append(lines["globs"], value)
			if pattern.Exact {
				value += ":cs"
			}
			lines["globs2"] = append(lines["globs2"], fmt.Sprintf("%d:%s", weight, value))
		}
		if mime.Icon.Name != "" {
			lines["icons"] = append(lines["icons"], mime.Name+":"+mime.Icon.Name)
		}
		if mime.Generic.Name != "" {
			lines["generic-icons"] = append(lines["generic-icons"], mime.Name+":"+mime.Generic.Name)
		}
		for _, rules := range mime.Magic {
			value, err := priority(rules.Priority)
			if err != nil {
				return nil, fmt.Errorf("shared MIME-info: invalid magic priority for %s", mime.Name)
			}
			entries = append(entries, namedMagic{name: mime.Name, priority: value, matches: rules.Matches})
		}
	}

	slices.SortStableFunc(entries, func(a, b namedMagic) int {
		if a.priority != b.priority {
			return b.priority - a.priority
		}
		return strings.Compare(a.name, b.name)
	})
	var magicBytes bytes.Buffer
	magicBytes.WriteString("MIME-Magic\x00\n")
	for _, entry := range entries {
		fmt.Fprintf(&magicBytes, "[%d:%s]\n", entry.priority, entry.name)
		if err := writeMatches(&magicBytes, 0, entry.matches); err != nil {
			return nil, fmt.Errorf("shared MIME-info: magic for %s: %w", entry.name, err)
		}
	}

	files := map[string][]byte{"magic": magicBytes.Bytes()}
	for name, values := range lines {
		slices.Sort(values)
		values = slices.Compact(values)
		files[name] = []byte(strings.Join(values, "\n"))
		if len(values) != 0 {
			files[name] = append(files[name], '\n')
		}
	}
	return files, nil
}

func validType(name string) bool {
	major, minor, ok := strings.Cut(name, "/")
	return ok && major != "" && minor != "" && !strings.ContainsAny(major+minor, "/:\r\n\x00 \t[]")
}

func priority(value *int) (int, error) {
	if value == nil {
		return 50, nil
	}
	if *value < 0 || *value > 100 {
		return 0, fmt.Errorf("priority %d is outside 0..100", *value)
	}
	return *value, nil
}

func writeMatches(out *bytes.Buffer, depth int, matches []match) error {
	if depth > 128 {
		return fmt.Errorf("nested matches exceed 128 levels")
	}
	for _, rule := range matches {
		first, last, ranged := strings.Cut(rule.Offset, ":")
		start, err := strconv.ParseUint(first, 10, 31)
		if err != nil {
			return fmt.Errorf("invalid offset %q", rule.Offset)
		}
		end := start
		if ranged {
			end, err = strconv.ParseUint(last, 10, 31)
			if err != nil || end < start {
				return fmt.Errorf("invalid offset range %q", rule.Offset)
			}
		}
		value, mask, word, err := matchBytes(rule)
		if err != nil {
			return err
		}
		if len(value) == 0 || len(value) > 65535 || (mask != nil && len(mask) != len(value)) {
			return fmt.Errorf("invalid lengths for %q and mask %q", rule.Value, rule.Mask)
		}
		if depth > 0 {
			out.WriteString(strconv.Itoa(depth))
		}
		fmt.Fprintf(out, ">%d=", start)
		out.Write(binary.BigEndian.AppendUint16(nil, uint16(len(value))))
		out.Write(value)
		if mask != nil {
			out.WriteByte('&')
			out.Write(mask)
		}
		if word > 1 {
			fmt.Fprintf(out, "~%d", word)
		}
		if end != start {
			fmt.Fprintf(out, "+%d", end-start+1)
		}
		out.WriteByte('\n')
		if err := writeMatches(out, depth+1, rule.Children); err != nil {
			return err
		}
	}
	return nil
}

func matchBytes(rule match) (value, mask []byte, word int, err error) {
	if rule.Type == "string" {
		value, err = unescape(rule.Value)
		if err == nil && rule.Mask != "" {
			if !strings.HasPrefix(rule.Mask, "0x") {
				return nil, nil, 0, fmt.Errorf("invalid string mask %q", rule.Mask)
			}
			digits := rule.Mask[2:]
			if len(digits) > 2*len(value) {
				return nil, nil, 0, fmt.Errorf("string mask is longer than its value")
			}
			mask, err = hex.DecodeString(digits + strings.Repeat("0", 2*len(value)-len(digits)))
		}
		return value, mask, 1, err
	}
	order := binary.ByteOrder(binary.BigEndian)
	word, width := 1, 1
	switch rule.Type {
	case "byte":
	case "host16":
		word, width = 2, 2
	case "host32":
		word, width = 4, 4
	case "big16":
		width = 2
	case "big32":
		width = 4
	case "little16":
		order, width = binary.LittleEndian, 2
	case "little32":
		order, width = binary.LittleEndian, 4
	default:
		return nil, nil, 0, fmt.Errorf("unsupported magic type %q", rule.Type)
	}
	value, err = numberBytes(rule.Value, width, order)
	if err == nil && rule.Mask != "" {
		mask, err = numberBytes(rule.Mask, width, order)
	}
	return value, mask, word, err
}

func numberBytes(text string, width int, order binary.ByteOrder) ([]byte, error) {
	n, err := strconv.ParseUint(text, 0, width*8)
	if err != nil {
		return nil, err
	}
	if width == 1 {
		return []byte{byte(n)}, nil
	}
	data := make([]byte, width)
	if width == 2 {
		order.PutUint16(data, uint16(n))
	} else {
		order.PutUint32(data, uint32(n))
	}
	return data, nil
}

func unescape(text string) ([]byte, error) {
	var value []byte
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b != '\\' {
			value = append(value, b)
			continue
		}
		i++
		if i >= len(text) {
			return nil, fmt.Errorf("trailing escape in %q", text)
		}
		b = text[i]
		switch b {
		case 'n':
			b = '\n'
		case 'r':
			b = '\r'
		case 't':
			b = '\t'
		case 'x':
			start := i + 1
			end := start
			for end < len(text) && end < start+2 && strings.ContainsRune("0123456789ABCDEFabcdef", rune(text[end])) {
				end++
			}
			n, err := strconv.ParseUint(text[start:end], 16, 8)
			if err != nil {
				return nil, err
			}
			b, i = byte(n), end-1
		default:
			if b >= '0' && b <= '7' {
				end := i
				for end < len(text) && end < i+3 && text[end] >= '0' && text[end] <= '7' {
					end++
				}
				n, err := strconv.ParseUint(text[i:end], 8, 16)
				if err != nil {
					return nil, err
				}
				b, i = byte(n), end-1
			}
		}
		value = append(value, b)
	}
	return value, nil
}
