// Package deb reads Debian control paragraphs, including dpkg's status file.
package deb

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/storage"
)

type Paragraph struct {
	Fields map[string]string
	Raw    []byte
}

func ReadControl(source storage.Reader, maximumBytes int64) ([]Paragraph, error) {
	if source == nil || source.Size() < 0 || source.Size() > maximumBytes {
		return nil, fmt.Errorf("Debian control: input exceeds byte limit")
	}
	data, err := io.ReadAll(io.NewSectionReader(source, 0, source.Size()))
	if err != nil {
		return nil, err
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("Debian control: unexpected NUL")
	}
	if bytes.Contains(data, []byte{'\r'}) {
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		if bytes.IndexByte(data, '\r') >= 0 {
			return nil, fmt.Errorf("Debian control: unexpected CR")
		}
	}
	result := make([]Paragraph, 0)
	for block := range bytes.SplitSeq(data, []byte("\n\n")) {
		block = bytes.Trim(block, "\n")
		if len(block) == 0 {
			continue
		}
		paragraph := Paragraph{Fields: make(map[string]string), Raw: block}
		current := ""
		for line := range bytes.SplitSeq(block, []byte{'\n'}) {
			if len(line) == 0 {
				return nil, fmt.Errorf("Debian control: empty line in paragraph")
			}
			if line[0] == '#' {
				continue
			}
			if line[0] == ' ' || line[0] == '\t' {
				if current == "" {
					return nil, fmt.Errorf("Debian control: continuation lacks a field")
				}
				paragraph.Fields[current] += "\n" + string(line)
				continue
			}
			field, value, found := bytes.Cut(line, []byte{':'})
			name := strings.ToLower(string(field))
			if !found || !validField(field) {
				return nil, fmt.Errorf("Debian control: invalid field %q", field)
			}
			if _, duplicate := paragraph.Fields[name]; duplicate {
				return nil, fmt.Errorf("Debian control: duplicate field %q", field)
			}
			current = name
			paragraph.Fields[current] = strings.TrimSpace(string(value))
		}
		if len(paragraph.Fields) != 0 {
			result = append(result, paragraph)
		}
	}
	return result, nil
}

func validField(field []byte) bool {
	if len(field) == 0 || field[0] == '#' || field[0] == '-' {
		return false
	}
	for _, b := range field {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}
