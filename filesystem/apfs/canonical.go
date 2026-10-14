package apfs

import (
	"fmt"
	"sort"

	"go.starlark.net/starlark"
)

// CanonicalRecords normalizes portable filesystem metadata for a sealed tree.
// The timestamp is explicit APFS nanoseconds. Data hash records must already
// use APFS file-info keys and the hash algorithm selected by the tree builder.
// Physical extents are omitted because they belong in the separate fext tree.
func (v *Volume) CanonicalRecords(timestamp uint64, hashes []Record) ([]Record, error) {
	source, err := v.Records()
	if err != nil {
		return nil, err
	}
	rows := make([]Record, 0, len(source)+len(hashes))
	for _, r := range source {
		if len(r.Key) < 8 {
			return nil, fmt.Errorf("apfs: truncated filesystem key")
		}
		kind := le.Uint64(r.Key) >> 60
		switch kind {
		case 8:
			continue
		case 3:
			r.Value, err = canonicalInode(r.Value, timestamp)
			if err != nil {
				return nil, err
			}
		case 9:
			if len(r.Value) < 18 {
				return nil, fmt.Errorf("apfs: truncated canonical directory entry")
			}
			le.PutUint64(r.Value[8:], timestamp)
		case 4:
			if len(r.Value) < 4 {
				return nil, fmt.Errorf("apfs: truncated canonical xattr")
			}
			if le.Uint16(r.Value)&3 == 1 {
				if len(r.Value) != 52 {
					return nil, fmt.Errorf("apfs: invalid canonical xattr stream")
				}
				le.PutUint64(r.Value[36:], 1)
				le.PutUint64(r.Value[44:], 1)
			}
		}
		rows = append(rows, r)
	}
	// Existing record order is significant for names and other filesystem key
	// suffixes. Insert hashes with a stable ID/type sort, preserving that order.
	for _, r := range hashes {
		if len(r.Key) != 16 || le.Uint64(r.Key)>>60 != 13 || le.Uint64(r.Key[8:])>>56 != 1 || len(r.Value) < 3 || le.Uint16(r.Value) == 0 || (r.Value[2] != 32 && r.Value[2] != 48 && r.Value[2] != 64) || int(r.Value[2])+3 != len(r.Value) {
			return nil, fmt.Errorf("apfs: invalid canonical data hash")
		}
		rows = append(rows, Record{append([]byte(nil), r.Key...), append([]byte(nil), r.Value...)})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := le.Uint64(rows[i].Key), le.Uint64(rows[j].Key)
		if a&0x0fffffffffffffff != b&0x0fffffffffffffff {
			return a&0x0fffffffffffffff < b&0x0fffffffffffffff
		}
		if a>>60 != b>>60 {
			return a>>60 < b>>60
		}
		if a>>60 == 13 {
			return le.Uint64(rows[i].Key[8:]) < le.Uint64(rows[j].Key[8:])
		}
		return false
	})
	for i, r := range rows {
		if i > 0 && le.Uint64(r.Key)>>60 == 13 && string(r.Key) == string(rows[i-1].Key) {
			return nil, fmt.Errorf("apfs: duplicate canonical data hash")
		}
	}
	return rows, nil
}

func canonicalInode(b []byte, timestamp uint64) ([]byte, error) {
	if len(b) < 92 {
		return nil, fmt.Errorf("apfs: truncated canonical inode")
	}
	result := append([]byte(nil), b[:92]...)
	for off := 16; off < 48; off += 8 {
		le.PutUint64(result[off:], timestamp)
	}
	flags := le.Uint64(result[48:])
	le.PutUint64(result[48:], flags & ^uint64(8|512|65536))
	le.PutUint32(result[60:], 0)
	le.PutUint32(result[64:], 1)
	if len(b) == 92 {
		return result, nil
	}
	if len(b) < 96 {
		return nil, fmt.Errorf("apfs: truncated canonical inode fields")
	}
	count := int(le.Uint16(b[92:]))
	pos := 96 + count*4
	if pos > len(b) {
		return nil, fmt.Errorf("apfs: invalid inode field table")
	}
	type field struct{ header, data []byte }
	fields := make([]field, 0, count)
	seen := map[byte]bool{}
	for i := 0; i < count; i++ {
		header := b[96+i*4 : 100+i*4]
		size := int(le.Uint16(header[2:]))
		padded := (size + 7) &^ 7
		if seen[header[0]] || padded > len(b)-pos {
			return nil, fmt.Errorf("apfs: invalid inode field extent")
		}
		seen[header[0]] = true
		data := make([]byte, padded)
		copy(data, b[pos:pos+size])
		pos += padded
		if header[0] == 13 && flags&512 != 0 {
			continue
		}
		if header[0] == 8 {
			if size != 40 {
				return nil, fmt.Errorf("apfs: invalid canonical inode stream")
			}
			le.PutUint64(data[24:], 1)
			le.PutUint64(data[32:], 1)
		}
		fields = append(fields, field{append([]byte(nil), header...), data})
	}
	if pos != len(b) {
		return nil, fmt.Errorf("apfs: trailing inode field data")
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].header[0] < fields[j].header[0] })
	used := 0
	for _, f := range fields {
		used += len(f.data)
	}
	if used > 65535 {
		return nil, fmt.Errorf("apfs: excessive canonical inode fields")
	}
	result = le.AppendUint16(result, uint16(len(fields)))
	result = le.AppendUint16(result, uint16(used))
	for _, f := range fields {
		result = append(result, f.header...)
	}
	for _, f := range fields {
		result = append(result, f.data...)
	}
	return result, nil
}

func canonicalRecordsBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.canonical_records", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var timestamp uint64
		var hashes *starlark.List
		if err := starlark.UnpackArgs("canonical_records", args, kwargs, "time_ns", &timestamp, "hashes", &hashes); err != nil {
			return nil, err
		}
		if hashes.Len() > 1000000 {
			return nil, fmt.Errorf("apfs: excessive data hashes")
		}
		input := make([]Record, hashes.Len())
		for i := range input {
			p, ok := hashes.Index(i).(starlark.Tuple)
			if !ok || len(p) != 2 {
				return nil, fmt.Errorf("apfs: expected hash (key,value) tuple")
			}
			k, kok := p[0].(starlark.Bytes)
			b, bok := p[1].(starlark.Bytes)
			if !kok || !bok || len(k) != 16 || len(b) > 67 {
				return nil, fmt.Errorf("apfs: invalid data hash bytes")
			}
			input[i] = Record{[]byte(k), []byte(b)}
		}
		records, err := v.CanonicalRecords(timestamp, input)
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(records))
		for i, r := range records {
			out[i] = starlark.Tuple{starlark.Bytes(r.Key), starlark.Bytes(r.Value)}
		}
		return starlark.NewList(out), nil
	})
}
