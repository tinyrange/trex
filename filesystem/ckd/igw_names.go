package ckd

import (
	"bytes"
	"fmt"
)

type NameCell struct {
	Flags byte
	Name  []byte // Fixed-width EBCDIC name, with padding preserved.
	Value []byte
}
type NamePage struct {
	Level byte
	Cells []NameCell
}

func ParseNamePage(b []byte) (*NamePage, error) {
	bad := func(s string) (*NamePage, error) { return nil, fmt.Errorf("IGW name page: %s", s) }
	if len(b) != 4096 || b[0] != 52 || b[1] != 1 || !bytes.Equal(b[11:13], []byte{0xd5, 0xc4}) || be.Uint16(b[4094:]) != 0xa55a {
		return bad("unsupported framing")
	}
	width := int(b[25])
	if width != 64 && width != 255 {
		return bad("unsupported name width")
	}
	free, limit := int(be.Uint16(b[48:])), int(be.Uint16(b[50:]))
	if limit > 4094 || free > limit || limit-free < 52+width {
		return bad("invalid free space")
	}
	end := limit - free
	previous := bytes.Clone(b[52 : 52+width])
	out := &NamePage{Level: b[30]}
	for pos := 52 + width; pos < end; {
		if end-pos < 5 {
			return bad("short group")
		}
		size := int(be.Uint16(b[pos:]))
		if size < 5 || size > end-pos || int(be.Uint16(b[pos+2:])) != size || b[pos+4] == 0 {
			return bad("unsupported group")
		}
		cell := pos + 5
		for i := 0; i < int(b[pos+4]); i++ {
			if pos+size-cell < 5 {
				return bad("short cell")
			}
			length := int(be.Uint16(b[cell:]))
			prefix, padding := int(b[cell+3]), int(b[cell+4])
			suffix := width - prefix - padding
			if length < 5 || length > pos+size-cell || prefix > width || suffix < 0 || suffix > length-5 || b[cell+2] != 0xc0 {
				return bad("unsupported cell")
			}
			name := bytes.Repeat([]byte{0x40}, width)
			copy(name[:prefix], previous[:prefix])
			copy(name[prefix:], b[cell+5:cell+5+suffix])
			if bytes.Compare(name, previous) < 0 {
				return bad("unordered name")
			}
			out.Cells = append(out.Cells, NameCell{b[cell+2], name, bytes.Clone(b[cell+5+suffix : cell+length])})
			previous = name
			cell += length
		}
		if cell != pos+size {
			return bad("group slack")
		}
		pos += size
	}
	return out, nil
}

// PDSEMember preserves stored programs or data-record payloads and boundaries.
type PDSEMember struct {
	Name          string
	Alias         bool
	Object        [6]byte
	Data          *Content
	DeclaredSize  uint32
	RecordLengths []uint32
}

// ProgramMember is retained for callers of ProgramMembers.
type ProgramMember = PDSEMember

// ProgramMembers resolves observed PDSE program libraries. Data preserves the
// complete stored IEWPLMH file, not a relinked or gap-expanded image. Unsupported
// data-member layouts and allocation variants fail explicitly.
func (ds *Dataset) ProgramMembers(maxMembers int) ([]ProgramMember, error) {
	if ds.SMSFlags&0x0a != 8 || ds.RecordFormat != 0xc0 || maxMembers <= 0 {
		return nil, fmt.Errorf("IGW: not a supported PDSE program library")
	}
	pages, err := ds.OpenPages(4096)
	if err != nil {
		return nil, err
	}
	g, err := OpenIGW(pages)
	if err != nil {
		return nil, err
	}
	return g.programMembers(maxMembers)
}
func (g *IGW) programMembers(limit int) ([]ProgramMember, error) {
	return g.pdseMembers(limit, 0xc0, 0)
}

func (g *IGW) pdseMembers(limit int, recordFormat byte, recordLength uint16) ([]PDSEMember, error) {
	program := recordFormat == 0xc0
	recordsLeft := 1000000
	// Attribute budgets are separate from member counts.
	rows, err := g.Attributes(1000000)
	if err != nil {
		return nil, err
	}
	attrs := map[[20]byte][]byte{}
	sparseDirectory := false
	for _, c := range rows {
		allowed := c.Flags == 0xc0 || (c.Flags == 0xe5 && c.Key == igwKey(1, [6]byte{0, 0, 0, 0, 0, 3}, 0x7003))
		if !program {
			allowed = allowed || (c.Flags == 0xe6 && c.Key == igwKey(1, [6]byte{0, 0, 0, 0, 0, 3}, 0x4002)) || (c.Flags == 0xd6 && bytes.Equal(c.Key[:6], []byte{0, 0, 0, 0, 0, 3}) && be.Uint16(c.Key[14:]) == 0x7003)
		}
		if !allowed {
			return nil, fmt.Errorf("IGW: unsupported program attribute flags")
		}
		if _, exists := attrs[c.Key]; exists {
			return nil, fmt.Errorf("IGW: duplicate attribute key")
		}
		attrs[c.Key] = c.Value
		if c.Flags == 0xe5 {
			sparseDirectory = true
		}
	}
	key := func(namespace uint64, object [6]byte, kind uint16) [20]byte {
		var k [20]byte
		for i := 5; i >= 0; i-- {
			k[i] = byte(namespace)
			namespace >>= 8
		}
		copy(k[6:12], object[:])
		be.PutUint16(k[14:16], kind)
		return k
	}
	directory := [6]byte{0, 0, 0, 0, 0, 3}
	descriptor := attrs[key(1, directory, 0x4002)]
	if len(descriptor) != 64 || descriptor[0] != 1 {
		return nil, fmt.Errorf("IGW: missing PDSE name-directory descriptor")
	}
	allocation, err := g.objectAllocation(attrs, 1, directory, sparseDirectory)
	if err != nil {
		return nil, err
	}
	cells, err := readNameDirectory(allocation, descriptor, 64, 1000000)
	if err != nil {
		return nil, err
	}
	out := []ProgramMember{}
	names := map[string]bool{}
	for _, c := range cells {
		if c.Name[0] == 255 {
			continue
		} // Reverse-index keys, not member names.
		if len(c.Value) != 20 {
			return nil, fmt.Errorf("IGW: invalid name value")
		}
		n := int(be.Uint16(c.Value[14:16]))
		if n < 1 || n > len(c.Name) || !bytes.Equal(c.Name[n:], bytes.Repeat([]byte{0x40}, len(c.Name)-n)) {
			return nil, fmt.Errorf("IGW: invalid member name length")
		}
		name := Identifier(c.Name[:n])
		if names[name] || name == "." || name == ".." {
			return nil, fmt.Errorf("IGW: invalid or duplicate member name")
		}
		names[name] = true
		var object [6]byte
		copy(object[:], c.Value[6:12])
		canonical := attrs[key(3, object, 0x1001)]
		if len(canonical) < 4 || canonical[0] != 1 {
			return nil, fmt.Errorf("IGW: missing member identity")
		}
		clen := int(canonical[1])<<16 | int(canonical[2])<<8 | int(canonical[3])
		if clen != len(canonical)-4 {
			return nil, fmt.Errorf("IGW: invalid canonical name")
		}
		data, err := g.objectAllocation(attrs, 3, object, false)
		if err != nil {
			return nil, err
		}
		storageInfo := attrs[key(3, object, 0x4004)]
		member := PDSEMember{Name: name, Alias: !bytes.Equal(c.Name[:n], bytes.TrimRight(canonical[4:], "\x40")), Object: object}
		if program {
			if len(storageInfo) != 85 || storageInfo[0] != 1 || uint64(be.Uint32(storageInfo[56:]))*4096 != uint64(data.Size()) || uint64(be.Uint32(storageInfo[52:]))+1 != uint64(be.Uint32(storageInfo[56:])) {
				return nil, fmt.Errorf("IGW member %s: inconsistent stored page count", name)
			}
			data, err = OpenStoredProgramObject(data)
			if err != nil {
				return nil, fmt.Errorf("IGW member %s: %w", name, err)
			}
			var declared [4]byte
			if _, err := data.ReadAt(declared[:], 16); err != nil {
				return nil, err
			}
			member.DeclaredSize = be.Uint32(declared[:])
		} else {
			data, member.RecordLengths, err = OpenPDSEData(data, storageInfo, recordFormat, recordLength, recordsLeft)
			if err != nil {
				return nil, fmt.Errorf("IGW member %s: %w", name, err)
			}
			recordsLeft -= len(member.RecordLengths)
		}
		member.Data = data
		if len(out) >= limit {
			return nil, fmt.Errorf("IGW: member limit exceeded")
		}
		out = append(out, member)
	}
	return out, nil
}
