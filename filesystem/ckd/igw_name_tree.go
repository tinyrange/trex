package ckd

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/storage"
)

// readNameDirectory follows active child identifiers, never stale allocated
// leaves. Separators are shortened prefixes; actual leaf ordering is checked.
func readNameDirectory(source storage.Reader, descriptor []byte, width byte, limit int) ([]NameCell, error) {
	if len(descriptor) != 64 || descriptor[0] != 1 || limit <= 0 {
		return nil, fmt.Errorf("IGW: invalid name descriptor or limit")
	}
	type pending struct {
		id     uint32
		parent byte
		lower  []byte
	}
	stack := []pending{{id: be.Uint32(descriptor[32:])}}
	seen := map[uint32]bool{}
	var out []NameCell
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if int64(item.id) >= source.Size()/4096 || seen[item.id] || len(seen) >= limit {
			return nil, fmt.Errorf("IGW: invalid, cyclic or over-limit name child")
		}
		seen[item.id] = true
		b := make([]byte, 4096)
		if _, err := source.ReadAt(b, int64(item.id)*4096); err != nil {
			return nil, err
		}
		if !bytes.Equal(b[2:21], descriptor[1:20]) || b[25] != width {
			return nil, fmt.Errorf("IGW: name directory identity mismatch")
		}
		page, err := ParseNamePage(b)
		if err != nil {
			return nil, err
		}
		if page.Level < 1 || page.Level > 32 || (item.parent != 0 && page.Level != item.parent-1) {
			return nil, fmt.Errorf("IGW: invalid name-tree level")
		}
		for _, c := range page.Cells {
			if item.lower != nil && bytes.Compare(c.Name, item.lower) < 0 {
				return nil, fmt.Errorf("IGW: name below parent separator")
			}
		}
		if page.Level == 1 {
			if len(page.Cells) > limit-len(out) {
				return nil, fmt.Errorf("IGW: name cell limit exceeded")
			}
			if len(out) > 0 && len(page.Cells) > 0 && bytes.Compare(out[len(out)-1].Name, page.Cells[0].Name) >= 0 {
				return nil, fmt.Errorf("IGW: overlapping name leaves")
			}
			out = append(out, page.Cells...)
		} else {
			if len(page.Cells) == 0 {
				return nil, fmt.Errorf("IGW: empty internal name page")
			}
			for i := len(page.Cells) - 1; i >= 0; i-- {
				c := page.Cells[i]
				if len(c.Value) != 4 {
					return nil, fmt.Errorf("IGW: invalid name child value")
				}
				stack = append(stack, pending{be.Uint32(c.Value), page.Level, bytes.Clone(c.Name)})
			}
		}
	}
	return out, nil
}
