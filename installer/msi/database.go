// Package msi decodes Windows Installer databases from portable compound files.
package msi

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/tinyrange/trex/archive/cfb"
	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Column struct {
	Name string
	Type uint16
}
type Database struct {
	container      *cfb.Archive
	streams        map[string]starfile.File
	strings        []string
	referenceWidth int
	Schema         map[string][]Column
	Tables         map[string][]map[string]starlark.Value
	Codepage       uint32
}

// Stream names pack pairs from a 64-character alphabet into UTF-16 codepoints.
// See the MIT go-msi format reference recorded in the format documentation.
func decodeName(name string) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 0x3800 && r < 0x4800:
			v := r - 0x3800
			b.WriteByte(alphabet[v&63])
			b.WriteByte(alphabet[v>>6])
		case r >= 0x4800 && r < 0x4840:
			b.WriteByte(alphabet[r-0x4800])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func Open(file starfile.File) (*Database, error) {
	container, err := cfb.Open(file)
	if err != nil {
		return nil, err
	}
	d := &Database{container: container, streams: map[string]starfile.File{}, Schema: map[string][]Column{}, Tables: map[string][]map[string]starlark.Value{}, referenceWidth: 2}
	for _, name := range container.Files() {
		decoded := strings.TrimPrefix(decodeName(name), "/")
		if _, found := d.streams[decoded]; found {
			return nil, fmt.Errorf("msi: duplicate decoded stream %q", decoded)
		}
		d.streams[decoded] = container.Lookup(name)
	}
	pool, err := d.read("\u4840_StringPool")
	if err != nil {
		return nil, err
	}
	data, err := d.read("\u4840_StringData")
	if err != nil {
		return nil, err
	}
	if len(pool) < 4 || len(pool)%4 != 0 {
		return nil, fmt.Errorf("msi: invalid string pool")
	}
	header := binary.LittleEndian.Uint32(pool)
	d.Codepage = header & 0x7fffffff
	if header&0x80000000 != 0 {
		d.referenceWidth = 3
	}
	encoding := ""
	switch d.Codepage {
	case 0, 1252:
		encoding = "windows1252"
	case 65001:
		encoding = "utf8"
	case 1200:
		encoding = "utf16le"
	default:
		return nil, fmt.Errorf("msi: unsupported codepage %d", d.Codepage)
	}
	d.strings = []string{""}
	cursor := uint64(0)
	for pos := 4; pos < len(pool); {
		size := uint64(binary.LittleEndian.Uint16(pool[pos:]))
		refs := binary.LittleEndian.Uint16(pool[pos+2:])
		pos += 4
		if size == 0 && refs != 0 {
			if pos+4 > len(pool) {
				return nil, fmt.Errorf("msi: truncated long string")
			}
			size = uint64(binary.LittleEndian.Uint32(pool[pos:]))
			pos += 4
		}
		if cursor+size > uint64(len(data)) {
			return nil, fmt.Errorf("msi: string exceeds data stream")
		}
		value := ""
		if refs != 0 {
			value, err = binaryapi.DecodeText(data[cursor:cursor+size], encoding, false)
			if err != nil {
				return nil, err
			}
		}
		d.strings = append(d.strings, value)
		cursor += size
	}
	if cursor != uint64(len(data)) {
		return nil, fmt.Errorf("msi: trailing string data")
	}
	d.Schema["_Tables"] = []Column{{"Name", 0x2d40}}
	d.Schema["_Columns"] = []Column{{"Table", 0x2d40}, {"Number", 0x2102}, {"Name", 0x0d40}, {"Type", 0x0102}}
	for _, name := range []string{"_Tables", "_Columns"} {
		rows, err := d.decodeTable(name, d.Schema[name])
		if err != nil {
			return nil, err
		}
		d.Tables[name] = rows
	}
	for _, row := range d.Tables["_Tables"] {
		name, ok := starlark.AsString(row["Name"])
		if !ok || name == "" {
			return nil, fmt.Errorf("msi: invalid table name")
		}
		if _, found := d.Schema[name]; !found {
			d.Schema[name] = nil
		}
	}
	indexed := map[string]map[int]Column{}
	for _, row := range d.Tables["_Columns"] {
		table, tableOK := starlark.AsString(row["Table"])
		name, nameOK := starlark.AsString(row["Name"])
		number, nerr := starlark.AsInt32(row["Number"])
		bits, berr := starlark.AsInt32(row["Type"])
		if !tableOK || !nameOK || nerr != nil || berr != nil || number < 1 || number > 256 || bits < 0 || bits > 65535 {
			return nil, fmt.Errorf("msi: invalid column metadata")
		}
		if _, ok := d.Schema[table]; !ok {
			return nil, fmt.Errorf("msi: column references absent table %s", table)
		}
		if indexed[table] == nil {
			indexed[table] = map[int]Column{}
		}
		if _, ok := indexed[table][number]; ok {
			return nil, fmt.Errorf("msi: duplicate column number")
		}
		indexed[table][number] = Column{name, uint16(bits)}
	}
	for name, columns := range indexed {
		if name == "_Tables" || name == "_Columns" {
			continue
		}
		schema := make([]Column, len(columns))
		for n := range schema {
			col, ok := columns[n+1]
			if !ok {
				return nil, fmt.Errorf("msi: noncontiguous schema in %s", name)
			}
			schema[n] = col
		}
		d.Schema[name] = schema
	}
	for name, schema := range d.Schema {
		if _, ok := d.Tables[name]; ok {
			continue
		}
		if len(schema) == 0 {
			return nil, fmt.Errorf("msi: no schema for %s", name)
		}
		rows, err := d.decodeTable(name, schema)
		if err != nil {
			return nil, err
		}
		d.Tables[name] = rows
	}
	return d, nil
}
func (d *Database) read(name string) ([]byte, error) {
	f := d.streams[name]
	if f == nil {
		return nil, fmt.Errorf("msi: missing stream %q", name)
	}
	if f.Size() > 256<<20 {
		return nil, fmt.Errorf("msi: table stream too large")
	}
	return starfile.ReadAll(f)
}
func (d *Database) decodeTable(name string, schema []Column) ([]map[string]starlark.Value, error) {
	file := d.streams["\u4840"+name]
	if file == nil {
		return nil, nil
	}
	data, err := d.read("\u4840" + name)
	if err != nil {
		return nil, err
	}
	widths := make([]int, len(schema))
	width := 0
	for i, col := range schema {
		n := int(col.Type & 0xff)
		if col.Type&0x0800 != 0 {
			n = 2
			if col.Type&0x0400 != 0 {
				n = d.referenceWidth
			}
		} else if n != 2 && n != 4 {
			return nil, fmt.Errorf("msi: invalid integer width in %s.%s", name, col.Name)
		}
		widths[i] = n
		width += n
	}
	if width == 0 || len(data)%width != 0 {
		return nil, fmt.Errorf("msi: partial row in %s", name)
	}
	count := len(data) / width
	rows := make([]map[string]starlark.Value, count)
	for i := range rows {
		rows[i] = map[string]starlark.Value{}
	}
	cursor := 0
	for colIndex, col := range schema {
		n := widths[colIndex]
		for row := range rows {
			raw := uint32(0)
			for b := 0; b < n; b++ {
				raw |= uint32(data[cursor+b]) << uint(b*8)
			}
			cursor += n
			var value starlark.Value = starlark.None
			if raw != 0 {
				switch {
				case col.Type&0x0c00 == 0x0c00:
					if int64(raw) >= int64(len(d.strings)) {
						return nil, fmt.Errorf("msi: invalid string reference in %s.%s", name, col.Name)
					}
					value = starlark.String(d.strings[raw])
				case col.Type&0x0800 != 0:
					value = starlark.True
				case n == 2:
					value = starlark.MakeInt(int(raw) - 32768)
				default:
					value = starlark.MakeInt64(int64(int32(raw ^ 0x80000000)))
				}
			}
			rows[row][col.Name] = value
		}
	}
	for _, row := range rows {
		keys := []string{name}
		for _, col := range schema {
			if col.Type&0x2000 != 0 {
				v := row[col.Name]
				s, ok := starlark.AsString(v)
				if !ok {
					s = v.String()
				}
				keys = append(keys, s)
			}
		}
		for _, col := range schema {
			if col.Type&0x0c00 == 0x0800 && row[col.Name] != starlark.None {
				streamName := strings.Join(keys, ".")
				f := d.streams[streamName]
				if f == nil {
					return nil, fmt.Errorf("msi: missing binary stream %s", streamName)
				}
				row[col.Name] = f
			}
		}
	}
	return rows, nil
}
func (d *Database) tableNames() []string {
	names := []string{}
	for name := range d.Tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
