// Package bru reads the classic, uncompressed BRU backup format. Each 2 KiB
// record has a 256-byte ASCII-hex header and an independently checked checksum.
package bru

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	blockSize     = 2048
	headerSize    = 256
	payloadSize   = blockSize - headerSize
	archiveRecord = 0x1234
	fileRecord    = 0x2345
	dataRecord    = 0x3456
	endRecord     = 0x7890
)

type Entry struct {
	Path, Kind, Link string
	Mode, UID, GID   uint32
	Size             int64
	Data             starfile.File
}

func number(data []byte) (uint32, error) {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, fmt.Errorf("bru: empty numeric field")
	}
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("bru: invalid hexadecimal field %q", s)
	}
	return uint32(n), nil
}

func name(data []byte) string {
	if n := bytes.IndexByte(data, 0); n >= 0 {
		data = data[:n]
	}
	return string(data)
}

type reader struct {
	file        starfile.File
	offset      int64
	archiveTime uint32
}

func (r *reader) block() ([]byte, uint32, error) {
	data := make([]byte, blockSize)
	if _, err := starfile.ReadFullAt(r.file, data, r.offset); err != nil {
		return nil, 0, fmt.Errorf("bru: record at %d: %w", r.offset, err)
	}
	if err := verifyChecksum(data); err != nil {
		return nil, 0, fmt.Errorf("bru: record at %d: %w", r.offset, err)
	}
	sequence, err := number(data[136:144])
	if err != nil || int64(sequence) != r.offset/blockSize {
		return nil, 0, fmt.Errorf("bru: invalid archive record sequence at %d", r.offset)
	}
	stamp, err := number(data[152:160])
	if err != nil {
		return nil, 0, err
	}
	if r.offset == 0 {
		r.archiveTime = stamp
	} else if stamp != r.archiveTime {
		return nil, 0, fmt.Errorf("bru: record belongs to another archive")
	}
	kind, err := number(data[176:180])
	if err != nil {
		return nil, 0, err
	}
	r.offset += blockSize
	return data, kind, nil
}

func verifyChecksum(data []byte) error {
	want, err := number(data[128:136])
	if err != nil {
		return err
	}
	// Classic BRU sums signed characters, substituting "       0" for its
	// checksum field. Binary payload bytes therefore differ from an unsigned
	// byte sum; arithmetic wraps to the stored 32-bit hexadecimal value.
	var sum uint32 = 7*' ' + '0'
	for i, b := range data {
		if i < 128 || i >= 136 {
			sum += uint32(int32(int8(b)))
		}
	}
	if sum != want {
		return fmt.Errorf("bru: checksum got %x, expected %x", sum, want)
	}
	return nil
}

// Open returns ordered entries and in-memory extent views. It validates every
// record, including data, before publishing the archive. Compressed records and
// incomplete/multivolume input fail explicitly rather than exposing raw data.
func Open(file starfile.File, maximumEntries int) ([]Entry, error) {
	if maximumEntries <= 0 || file.Size()%blockSize != 0 {
		return nil, fmt.Errorf("bru: invalid entry limit or unaligned input")
	}
	r := reader{file: file}
	_, kind, err := r.block()
	if err != nil {
		return nil, err
	}
	if kind != archiveRecord {
		return nil, fmt.Errorf("bru: missing archive header")
	}
	var entries []Entry
	for {
		data, kind, err := r.block()
		if err != nil {
			return nil, err
		}
		if kind == endRecord {
			var padding [blockSize]byte
			for r.offset < file.Size() {
				if _, err := starfile.ReadFullAt(file, padding[:], r.offset); err != nil {
					return nil, err
				}
				if !bytes.Equal(padding[:], make([]byte, blockSize)) {
					// The unused part of a BRU output buffer contains checked
					// padding blocks: blank name, sequence and record type,
					// but an ASCII volume and a checksum covering even unused
					// payload bytes. Some originals retain nonzero buffer data.
					if !bytes.Equal(padding[:128], make([]byte, 128)) || !bytes.Equal(padding[136:180], make([]byte, 44)) || !bytes.Equal(padding[184:256], make([]byte, 72)) {
						return nil, fmt.Errorf("bru: unexpected record after archive end")
					}
					if _, err := number(padding[180:184]); err != nil {
						return nil, err
					}
					if err := verifyChecksum(padding[:]); err != nil {
						return nil, err
					}
				}
				r.offset += blockSize
			}
			return entries, nil
		}
		if kind != fileRecord || len(entries) >= maximumEntries {
			return nil, fmt.Errorf("bru: expected file header or entry limit exceeded")
		}
		e := Entry{Path: name(data[:128]), Link: name(data[256:384])}
		if e.Path == "" {
			return nil, fmt.Errorf("bru: empty member name")
		}
		var fields [13]uint32
		for i := range fields {
			fields[i], err = number(data[384+8*i : 392+8*i])
			if err != nil {
				return nil, err
			}
		}
		e.Mode, e.UID, e.GID, e.Size = fields[0], fields[5], fields[6], int64(fields[7])
		if fields[11] != 0 || fields[12] != 0 {
			return nil, fmt.Errorf("bru: compressed or extended file %s is not supported", e.Path)
		}
		switch e.Mode & 0170000 {
		case 0100000:
			e.Kind = "file"
		case 0040000:
			e.Kind = "directory"
		case 0120000:
			e.Kind = "symlink"
		case 0020000:
			e.Kind = "character_device"
		case 0060000:
			e.Kind = "block_device"
		case 0010000:
			e.Kind = "fifo"
		default:
			return nil, fmt.Errorf("bru: unsupported file mode %o", e.Mode)
		}
		if e.Link != "" && e.Kind == "file" {
			e.Kind = "hardlink"
		}
		if e.Kind == "file" {
			if (e.Size+payloadSize-1)/payloadSize > (file.Size()-r.offset)/blockSize {
				return nil, fmt.Errorf("bru: file %s exceeds remaining records", e.Path)
			}
			var extents []filesystem.ExtentSpec
			for copied, sequence := int64(0), uint32(1); copied < e.Size; sequence++ {
				offset := r.offset
				payload, kind, err := r.block()
				if err != nil {
					return nil, err
				}
				fileSequence, err := number(payload[144:152])
				if err != nil || kind != dataRecord || fileSequence != sequence || name(payload[:128]) != e.Path {
					return nil, fmt.Errorf("bru: mismatched data record for %s", e.Path)
				}
				n := min(int64(payloadSize), e.Size-copied)
				extents = append(extents, filesystem.ExtentSpec{Start: copied, Size: n, File: file, Offset: offset + headerSize})
				copied += n
			}
			e.Data = filesystem.NewGeneratedImage(e.Path, e.Size, extents)
		}
		entries = append(entries, e)
	}
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("bru", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("bru: expected file")
	}
	entries, err := Open(file, maximum)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(entries))
	for i, entry := range entries {
		var data starlark.Value = starlark.None
		if entry.Data != nil {
			data = entry.Data
		}
		values[i] = starfile.NewRecord(starlark.StringDict{
			"path": starlark.String(entry.Path), "entry_type": starlark.String(entry.Kind), "link_target": starlark.String(entry.Link),
			"size": starlark.MakeInt64(entry.Size), "mode": starlark.MakeUint(uint(entry.Mode)),
			"uid": starlark.MakeUint(uint(entry.UID)), "gid": starlark.MakeUint(uint(entry.GID)), "data": data,
		})
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(values)}), nil
}
