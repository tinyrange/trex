package windows

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// acmeTableBuiltin reads the tabular ACME format used by Office 4.x, 95 and
// 97. The complete object graph remains available, including unselected and
// custom actions; a decoded table is not a claim of installation completeness.
func acmeTableBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("acme_table", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	if file.Size() > 32<<20 {
		return nil, fmt.Errorf("acme_table: table exceeds 32 MiB")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return parseACMETable(data)
}

func parseACMETable(data []byte) (*starlark.Dict, error) {
	header, objects := starlark.NewDict(32), starlark.NewDict(1024)
	annotations := starlark.NewList(nil)
	columns := []string(nil)
	offset := 0
	for number, raw := range bytes.Split(data, []byte{'\n'}) {
		lineOffset := offset
		offset += len(raw) + 1
		raw = bytes.TrimSuffix(raw, []byte{'\r'})
		line, err := binaryapi.DecodeText(raw, "windows1252", false)
		if err != nil {
			return nil, err
		}
		fields := strings.Split(line, "\t")
		if strings.TrimSpace(fields[0]) == "" {
			continue
		}
		if strings.TrimSpace(fields[0]) == "ObjID" {
			columns = fields
			continue
		}
		if columns == nil {
			if len(fields) > 1 {
				_ = header.SetKey(starlark.String(strings.TrimSpace(fields[0])), starlark.String(strings.TrimSpace(fields[1])))
			}
			continue
		}
		id := strings.TrimSpace(fields[0])
		if _, err := strconv.ParseUint(id, 10, 32); err != nil {
			_ = annotations.Append(starlark.Tuple{starlark.MakeInt(number + 1), starlark.String(line)})
			continue
		}
		if _, found, _ := objects.Get(starlark.String(id)); found {
			return nil, fmt.Errorf("acme_table: duplicate object %s at line %d", id, number+1)
		}
		for len(fields) < 6 {
			fields = append(fields, "")
		}
		values := starlark.NewDict(len(columns))
		for index, name := range columns {
			value := ""
			if index < len(fields) {
				value = fields[index]
			}
			_ = values.SetKey(starlark.String(strings.TrimSpace(name)), starlark.String(value))
		}
		destination := ""
		if len(fields) > 10 {
			destination = strings.TrimSpace(fields[10])
		}
		kind := strings.TrimSpace(fields[4])
		arguments, err := acmeArguments(fields[5])
		if err != nil {
			return nil, fmt.Errorf("acme_table: object %s: %w", id, err)
		}
		argv := make([]starlark.Value, len(arguments))
		for i, value := range arguments {
			argv[i] = starlark.String(value)
		}
		row := starlark.NewDict(10)
		for name, value := range map[string]starlark.Value{
			"id": starlark.String(id), "batch": starlark.Bool(strings.EqualFold(strings.TrimSpace(fields[1]), "yes")),
			"title": starlark.String(fields[2]), "type": starlark.String(kind), "data": starlark.String(fields[5]),
			"destination": starlark.String(destination), "fields": values, "arguments": starlark.NewList(argv),
			"line": starlark.MakeInt(number + 1), "offset": starlark.MakeInt(lineOffset),
		} {
			_ = row.SetKey(starlark.String(name), value)
		}
		_ = objects.SetKey(starlark.String(id), row)
	}
	if columns == nil {
		return nil, fmt.Errorf("acme_table: missing ObjID header")
	}
	result := starlark.NewDict(3)
	_ = result.SetKey(starlark.String("annotations"), annotations)
	_ = result.SetKey(starlark.String("header"), header)
	_ = result.SetKey(starlark.String("objects"), objects)
	return result, nil
}

func acmeArguments(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) && len(value) >= 2 {
		value = strings.ReplaceAll(value[1:len(value)-1], `""`, `"`)
	}
	if value == "" {
		return nil, nil
	}
	// ACME permits quoted short names followed immediately by <long names>.
	// This is not RFC CSV: a quote can close before '<', not just before ','.
	fields := []string{}
	var field strings.Builder
	quoted := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '"' {
			if !quoted && strings.TrimSpace(field.String()) != "" {
				field.WriteByte(c)
			} else if quoted && i+1 < len(value) && value[i+1] == '"' {
				field.WriteByte('"')
				i++
			} else {
				quoted = !quoted
			}
		} else if c == ',' && !quoted {
			fields = append(fields, strings.TrimSpace(field.String()))
			field.Reset()
		} else {
			field.WriteByte(c)
		}
	}
	if quoted {
		return nil, fmt.Errorf("unterminated ACME quoted argument")
	}
	fields = append(fields, strings.TrimSpace(field.String()))
	return fields, nil
}
