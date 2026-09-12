package vmsbackup

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
)

// Entry preserves the saved name and attributes without imposing host path
// semantics. Size is the declared logical EOF; StoredSize includes block slack.
// MissingContents means the save set contains metadata but no payload bytes for
// a nonempty file. Data is nil in that case, never synthesized zero bytes.
// This describes absence, not its cause or whether the omission was intended.
type Entry struct {
	Name            []byte
	Attributes      []Attribute
	Flags           uint32
	Size            int64
	StoredSize      int64
	MissingContents bool
	Data            storage.Reader
}

// Files reconstructs ordinary file-data chains from validated ReadBlocks
// results. Metadata-only entries are retained explicitly. A partly stored file,
// missing/repeated VBN, data before a file header, or an unknown record kind is
// an error. Volume and file-ID records remain available in the original blocks;
// this function does not interpret them or translate RMS records.
func Files(blocks []Block, maximumFiles, maximumAttributes int) ([]Entry, error) {
	if maximumFiles < 1 || maximumAttributes < 1 {
		return nil, fmt.Errorf("vms backup: invalid file limits")
	}
	entries := []Entry{}
	var current *Entry
	var data *fileView
	finish := func() error {
		if current == nil {
			return nil
		}
		if current.StoredSize == 0 && current.Size > 0 {
			current.MissingContents = true
		} else {
			if current.StoredSize < current.Size {
				return fmt.Errorf("vms backup: partially stored file %q", current.Name)
			}
			data.size = current.Size
			current.Data = data
		}
		entries = append(entries, *current)
		return nil
	}
	for _, block := range blocks {
		for _, record := range block.Records {
			switch record.Kind {
			case 0, 1, 2, 7: // Padding, summary, volume attributes, file-ID records.
			case 3:
				if err := finish(); err != nil {
					return nil, err
				}
				if len(entries) >= maximumFiles {
					return nil, fmt.Errorf("vms backup: file limit")
				}
				if record.Data == nil || record.Data.Size() < 2 || record.Data.Size() > 65535 {
					return nil, fmt.Errorf("vms backup: invalid file attribute record size")
				}
				raw := make([]byte, int(record.Data.Size()))
				if err := readExact(record.Data, raw, 0); err != nil {
					return nil, err
				}
				attrs, err := ParseAttributes(raw, maximumAttributes)
				if err != nil {
					return nil, err
				}
				current = &Entry{Attributes: attrs, Flags: record.Flags}
				data = &fileView{}
				var rms []byte
				for _, a := range attrs {
					switch a.Kind {
					case 42:
						if current.Name != nil || len(a.Data) == 0 {
							return nil, fmt.Errorf("vms backup: duplicate or empty file name")
						}
						current.Name = a.Data
					case 52:
						if rms != nil || len(a.Data) != 32 {
							return nil, fmt.Errorf("vms backup: duplicate or invalid RMS attributes")
						}
						rms = a.Data
					}
				}
				if current.Name == nil || rms == nil {
					return nil, fmt.Errorf("vms backup: missing name or RMS attributes")
				}
				eof := int64(binary.LittleEndian.Uint16(rms[8:]))<<16 | int64(binary.LittleEndian.Uint16(rms[10:]))
				free := int64(binary.LittleEndian.Uint16(rms[12:]))
				// VAX page/swap-file metadata also uses the end-of-block
				// representation FFBYTE=512, equivalent to next VBN/byte0.
				if free > 512 || eof == 0 && free != 0 {
					return nil, fmt.Errorf("vms backup: invalid RMS EOF")
				}
				if eof > 0 {
					current.Size = (eof-1)*512 + free
				}
			case 4:
				if current == nil || record.Data == nil || record.Data.Size() < 0 || record.Data.Size() > 65535 {
					return nil, fmt.Errorf("vms backup: invalid or orphan file data")
				}
				if record.Address == 0 || int64(record.Address-1)*512 != current.StoredSize {
					return nil, fmt.Errorf("vms backup: nonconsecutive file VBN for %q", current.Name)
				}
				if record.Data.Size() > 0 {
					data.parts = append(data.parts, filePart{start: current.StoredSize, data: record.Data})
				}
				current.StoredSize += record.Data.Size()
			default:
				return nil, fmt.Errorf("vms backup: unsupported file-stream record kind %d", record.Kind)
			}
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	return entries, nil
}

type filePart struct {
	start int64
	data  storage.Reader
}

type fileView struct {
	parts []filePart
	size  int64
}

func (f *fileView) Size() int64 { return f.size }
func (f *fileView) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("vms backup: negative file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	if int64(len(p)) > f.size-offset {
		p = p[:f.size-offset]
	}
	total := 0
	index := sort.Search(len(f.parts), func(i int) bool { return f.parts[i].start+f.parts[i].data.Size() > offset })
	for len(p) > 0 {
		if index >= len(f.parts) {
			return total, io.ErrUnexpectedEOF
		}
		part := f.parts[index]
		rel := offset - part.start
		length := min(int64(len(p)), part.data.Size()-rel)
		n, err := part.data.ReadAt(p[:length], rel)
		total += n
		if int64(n) != length {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return total, err
		}
		if err != nil && err != io.EOF {
			return total, err
		}
		p = p[n:]
		offset += int64(n)
		index++
	}
	if total != wanted {
		return total, io.EOF
	}
	return total, nil
}
