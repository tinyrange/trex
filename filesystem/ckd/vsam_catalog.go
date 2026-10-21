package ckd

import (
	"bytes"
	"fmt"
)

type CatalogCell struct {
	Kind     byte
	Raw      []byte
	Name     string
	Children []CatalogCell
}
type CatalogRecord struct {
	References []string // Ordered names in observed type-03 relationship cells.
	Kind       byte
	Name       string
	Key        []byte
	Cells      []CatalogCell
}

// ParseCatalogRecord parses the observed BCS key header and nested component
// cells. Unknown attribute kinds are preserved, not silently discarded.
func ParseCatalogRecord(b []byte) (*CatalogRecord, error) {
	if len(b) < 54 || int(be.Uint16(b)) != len(b) || be.Uint16(b[2:]) != 52 || b[8] != 45 {
		return nil, fmt.Errorf("BCS: unsupported record header")
	}
	out := &CatalogRecord{Kind: b[4], Name: Identifier(b[9:53]), Key: bytes.Clone(b[9:54])}
	var references []string
	var parse func([]byte, int) ([]CatalogCell, error)
	parse = func(data []byte, depth int) ([]CatalogCell, error) {
		if depth > 8 {
			return nil, fmt.Errorf("BCS: nesting limit")
		}
		var cells []CatalogCell
		for len(data) > 0 {
			if len(data) < 3 {
				return nil, fmt.Errorf("BCS: short cell")
			}
			n := int(be.Uint16(data))
			if n < 3 || n > len(data) {
				return nil, fmt.Errorf("BCS: cell outside record")
			}
			c := CatalogCell{Kind: data[2], Raw: bytes.Clone(data[:n])}
			if c.Kind == 3 {
				if n < 5 {
					return nil, fmt.Errorf("BCS: short relationship cell")
				}
				count, pos := int(be.Uint16(data[3:])), 5
				for i := 0; i < count; i++ {
					if n-pos < 2 {
						return nil, fmt.Errorf("BCS: short relationship name")
					}
					size := int(be.Uint16(data[pos:]))
					pos += 2
					if size < 2 || size > 45 || size > n-pos || data[pos+size-1] != 0 {
						return nil, fmt.Errorf("BCS: invalid relationship name")
					}
					references = append(references, Identifier(data[pos:pos+size-1]))
					pos += size
				}
				if pos != n {
					return nil, fmt.Errorf("BCS: relationship cell slack")
				}
			}
			step := n
			if c.Kind == 0xc4 || c.Kind == 0xc9 {
				if n < 8 || int(be.Uint16(data[5:])) != n-7 || data[n-1] != 0 {
					return nil, fmt.Errorf("BCS: invalid component name")
				}
				c.Name = Identifier(data[7 : n-1])
				step = int(be.Uint16(data[3:]))
				if step < n || step > len(data) {
					return nil, fmt.Errorf("BCS: component subtree outside record")
				}
				var err error
				c.Children, err = parse(data[n:step], depth+1)
				if err != nil {
					return nil, err
				}
			}
			cells = append(cells, c)
			data = data[step:]
		}
		return cells, nil
	}
	var err error
	out.Cells, err = parse(b[54:], 0)
	if err != nil {
		return nil, err
	}
	out.References = references
	if bytes.Equal(out.Key, make([]byte, 45)) {
		out.Name = ""
	}
	return out, nil
}

// VVR preserves the VSAM volume record and the decoded component geometry.
// Some VVR types (including non-VSAM NVRs) have different headers and are not
// inferred from arbitrary bytes. This reader covers the observed Z primary VVR.
type VVR struct {
	Name                      string
	Cluster                   string
	Catalog                   string
	Flags                     byte
	Cells                     map[byte][]byte
	CIBytes                   uint32
	MaximumRecordLength       uint32
	UsedBytes, AllocatedBytes uint64
	CIsPerTrack, TracksPerCA  uint16
	KeyOffset, KeyLength      uint16
	CIAddressed               bool
	Index                     bool
	DataFlags                 byte
	IndexRootRBA              uint64
}

func ParseVVR(b []byte) (*VVR, error) {
	bad := func(s string) (*VVR, error) { return nil, fmt.Errorf("VVDS VVR: %s", s) }
	if len(b) < 12 || int(be.Uint16(b)) != len(b) || b[4] != 0xe9 {
		return bad("unsupported header")
	}
	end := int(be.Uint16(b[2:])) + 2
	if end < 12 || end > len(b) {
		return bad("invalid header length")
	}
	n := int(b[10])
	if n < 2 || n > 45 || 10+n >= end {
		return bad("invalid component name")
	}
	out := &VVR{Name: Identifier(b[11 : 10+n]), Flags: b[5], Cells: map[byte][]byte{}}
	// Primary VVR names include a one-byte terminator after component/cluster.
	pos := 10 + n + 1
	if pos >= end {
		return bad("missing cluster name")
	}
	n = int(b[pos])
	if n < 2 || n > 45 || pos+n >= end {
		return bad("invalid cluster name")
	}
	out.Cluster = Identifier(b[pos+1 : pos+n])
	pos += n + 1
	if pos >= end {
		return bad("missing catalog name")
	}
	n = int(b[pos])
	pos++
	if n > 44 || pos+n > end {
		return bad("invalid catalog name")
	}
	out.Catalog = Identifier(b[pos : pos+n])
	for pos = end; pos < len(b); {
		if len(b)-pos < 3 {
			return bad("short cell")
		}
		n = int(be.Uint16(b[pos:]))
		if n < 3 || n > len(b)-pos {
			return bad("cell outside record")
		}
		kind := b[pos+2]
		if _, exists := out.Cells[kind]; exists {
			return bad("duplicate cell")
		}
		out.Cells[kind] = bytes.Clone(b[pos : pos+n])
		pos += n
	}
	base, component, volume := out.Cells[0x21], out.Cells[0x60], out.Cells[0x23]
	if (len(base) != 85 && len(base) != 153) || len(component) < 98 || len(volume) < 42 {
		return bad("unsupported component cells")
	}
	out.Index = out.Flags&0x08 != 0
	if out.Index {
		out.IndexRootRBA = uint64(be.Uint32(component[30:]))
	}
	out.DataFlags = component[3]
	out.MaximumRecordLength = be.Uint32(component[26:])
	out.KeyOffset, out.KeyLength = be.Uint16(component[8:]), be.Uint16(component[10:])
	out.UsedBytes, out.AllocatedBytes = uint64(be.Uint32(volume[9:])), uint64(be.Uint32(volume[13:]))
	out.CIBytes = be.Uint32(volume[17:])
	out.CIAddressed = volume[3]&4 != 0
	if out.CIAddressed {
		out.UsedBytes *= uint64(out.CIBytes)
		out.AllocatedBytes *= uint64(out.CIBytes)
		if out.Index {
			return bad("CI-addressed index root is not yet resolved")
		}
	}
	out.CIsPerTrack, out.TracksPerCA = be.Uint16(volume[21:]), be.Uint16(volume[23:])
	if out.CIBytes < 512 || out.CIBytes > 32768 || out.CIBytes%512 != 0 || out.UsedBytes > out.AllocatedBytes || out.UsedBytes%uint64(out.CIBytes) != 0 || out.AllocatedBytes%uint64(out.CIBytes) != 0 || out.CIsPerTrack == 0 || out.TracksPerCA == 0 {
		return bad("unsupported geometry")
	}
	return out, nil
}
