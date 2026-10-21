package ckd

import (
	"bytes"
	"fmt"

	"github.com/tinyrange/trex/storage"
)

// IGW provides mapped attribute pages and extent-backed reads. Source must be a
// 4096-byte allocated-page view, not a CKD track stream.
type IGW struct {
	source  storage.Reader
	mapping []uint64
}

func OpenIGW(source storage.Reader) (*IGW, error) {
	if source.Size() < 4096 || source.Size()%4096 != 0 {
		return nil, fmt.Errorf("IGW: invalid page view size")
	}
	g := &IGW{source: source}
	b := make([]byte, 4096)
	pages := uint64(source.Size() / 4096)
	seen := map[uint64]bool{}
	current := uint64(0)
	address := func(token uint64) (uint64, error) {
		if token&255 != 0 || token>>8 < 256 || (token>>8)-256 >= pages {
			return 0, fmt.Errorf("IGW: invalid map address")
		}
		return (token >> 8) - 256, nil
	}
	for {
		if seen[current] {
			return nil, fmt.Errorf("IGW: cyclic map continuation")
		}
		seen[current] = true
		if _, err := source.ReadAt(b, int64(current)*4096); err != nil {
			return nil, err
		}
		if !bytes.Equal(b[:8], []byte{0xc9, 0xc7, 0xe6, 0xe5, 0xc4, 0xc6, 0x40, 0x40}) || be.Uint32(b[8:]) != 4096 || b[12] != 1 || be.Uint16(b[4094:]) != 0xa55a {
			return nil, fmt.Errorf("IGW: unsupported VDF map framing")
		}
		n := int(be.Uint32(b[100:]))
		if n < 1 || n > 498 || n > 1000000-len(g.mapping) {
			return nil, fmt.Errorf("IGW: attribute map count or budget exceeded")
		}
		for i := 0; i < n; i++ {
			token := be.Uint64(b[104+8*i:])
			if token == 0 {
				g.mapping = append(g.mapping, ^uint64(0))
				continue
			}
			page, err := address(token)
			if err != nil {
				return nil, err
			}
			g.mapping = append(g.mapping, page)
		}
		next := be.Uint64(b[16:])
		if next == 0 {
			break
		}
		if n != 498 {
			return nil, fmt.Errorf("IGW: short nonterminal map page")
		}
		var err error
		current, err = address(next)
		if err != nil {
			return nil, err
		}
	}
	for _, page := range g.mapping {
		if seen[page] {
			return nil, fmt.Errorf("IGW: attribute map points into map chain")
		}
	}
	if g.mapping[0] == ^uint64(0) {
		return nil, fmt.Errorf("IGW: missing attribute root")
	}
	return g, nil
}

func (g *IGW) Attributes(maxCells int) ([]AttributeCell, error) {
	if maxCells <= 0 {
		return nil, fmt.Errorf("IGW: invalid cell limit")
	}
	type pending struct {
		id     uint32
		parent byte
		lower  []byte
	}
	stack := []pending{{}}
	seen := map[uint32]bool{}
	physical := map[uint64]bool{}
	out := []AttributeCell{}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if uint64(item.id) >= uint64(len(g.mapping)) || seen[item.id] {
			return nil, fmt.Errorf("IGW: invalid or cyclic attribute child %d", item.id)
		}
		seen[item.id] = true
		index := g.mapping[item.id]
		if index == ^uint64(0) || physical[index] {
			return nil, fmt.Errorf("IGW: missing or duplicate mapped page")
		}
		physical[index] = true
		b := make([]byte, 4096)
		if _, err := g.source.ReadAt(b, int64(index)*4096); err != nil {
			return nil, err
		}
		page, err := ParseAttributePage(b)
		if err != nil {
			return nil, err
		}
		if page.Level < 1 || page.Level > 32 || (item.parent != 0 && page.Level != item.parent-1) {
			return nil, fmt.Errorf("IGW: invalid attribute-tree level")
		}
		for _, c := range page.Cells {
			if item.lower != nil && bytes.Compare(c.Key[:], item.lower) < 0 {
				return nil, fmt.Errorf("IGW: key outside parent range")
			}
		}
		if page.Level == 1 {
			if len(page.Cells) > maxCells-len(out) {
				return nil, fmt.Errorf("IGW: attribute cell limit exceeded")
			}
			// Separators can be shortened prefixes, not strict upper bounds.
			// Check actual leaf order instead of excluding valid boundary keys.
			if len(out) > 0 && len(page.Cells) > 0 && bytes.Compare(out[len(out)-1].Key[:], page.Cells[0].Key[:]) >= 0 {
				return nil, fmt.Errorf("IGW: overlapping or unordered leaf keys")
			}
			out = append(out, page.Cells...)
		} else {
			if len(page.Cells) == 0 {
				return nil, fmt.Errorf("IGW: empty internal page")
			}
			for i := len(page.Cells) - 1; i >= 0; i-- {
				c := page.Cells[i]
				if len(c.Value) != 4 {
					return nil, fmt.Errorf("IGW: invalid child value")
				}
				stack = append(stack, pending{be.Uint32(c.Value), page.Level, bytes.Clone(c.Key[:])})
			}
		}
	}
	return out, nil
}

// Allocation decodes observed type-7003 run lists. Unknown placement flags fail
// explicitly; sparse logical files must not be guessed by concatenating runs.
func (g *IGW) Allocation(value []byte) (*Content, error) {
	return g.allocation(value, false)
}

// Zero descriptors in the observed E5 name-directory allocation retain one
// logical page each. They must not shift subsequent child identifiers.
func (g *IGW) allocation(value []byte, holes bool) (*Content, error) {
	if len(value) < 13 || value[0] > 1 {
		return nil, fmt.Errorf("IGW: unsupported allocation record")
	}
	n := int(be.Uint16(value[1:3]))
	if len(value) != 13+10*n {
		return nil, fmt.Errorf("IGW: invalid run count")
	}
	out := &Content{source: g.source}
	for i := 0; i < n; i++ {
		b := value[13+10*i:]
		token := be.Uint64(b[:8])
		if holes && token == 0 && be.Uint16(b[8:10]) == 0 {
			out.spans = append(out.spans, span{-1, 4096, out.size})
			out.size += 4096
			continue
		}
		page := token >> 8
		count := (token & 255) + 1
		if page < 256 || be.Uint16(b[8:10]) != 0 {
			return nil, fmt.Errorf("IGW: unsupported run address or placement")
		}
		page -= 256
		if page >= uint64(g.source.Size()/4096) || count > uint64(g.source.Size()/4096)-page {
			return nil, fmt.Errorf("IGW: allocation run outside dataset")
		}
		out.spans = append(out.spans, span{int64(page) * 4096, int64(count) * 4096, out.size})
		out.size += int64(count) * 4096
	}
	return out, nil
}
