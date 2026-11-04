package windows

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A patch transaction indexes each visited sibling list once, and publishes
// changed lists only at commit. Readers never see the private uncommitted bytes.
// This avoids a full-tree import and quadratic list rewriting for large batches.
type hiveChildBatch struct {
	cells map[string]uint32
	dirty bool
}

func (h *mutableHive) childBatch(parent uint32) (*hiveChildBatch, error) {
	if batch := h.childBatches[parent]; batch != nil {
		return batch, nil
	}
	key, err := h.cellBody(parent)
	if err != nil {
		return nil, err
	}
	if len(key) < 0x4c || string(key[:2]) != "nk" {
		return nil, fmt.Errorf("patch_hive: cell is not a key")
	}
	batch := &hiveChildBatch{cells: map[string]uint32{}}
	count := binary.LittleEndian.Uint32(key[0x14:0x18])
	if count > 0 {
		cells, err := h.subkeyCells(binary.LittleEndian.Uint32(key[0x1c:0x20]))
		if err != nil {
			return nil, err
		}
		for _, cell := range cells {
			name, err := h.subkeyName(cell)
			if err != nil {
				return nil, err
			}
			folded := foldHiveBatchName(name)
			if _, ok := batch.cells[folded]; ok {
				return nil, fmt.Errorf("patch_hive: duplicate subkey %q", name)
			}
			batch.cells[folded] = cell
		}
	}
	h.childBatches[parent] = batch
	return batch, nil
}
func (h *mutableHive) addBatchedSubkey(parent, child uint32) error {
	batch, err := h.childBatch(parent)
	if err != nil {
		return err
	}
	name, err := h.subkeyName(child)
	if err != nil {
		return err
	}
	folded := foldHiveBatchName(name)
	if _, ok := batch.cells[folded]; ok {
		return fmt.Errorf("patch_hive: duplicate subkey %q", name)
	}
	batch.cells[folded] = child
	batch.dirty = true
	p, err := h.cellBody(parent)
	if err != nil {
		return err
	}
	c, err := h.cellBody(child)
	if err != nil {
		return err
	}
	updateKeyMaxSubkeyName(p, c)
	return nil
}
func (h *mutableHive) finishChildBatches() error {
	parents := make([]uint32, 0, len(h.childBatches))
	for parent, batch := range h.childBatches {
		if batch.dirty {
			parents = append(parents, parent)
		}
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i] < parents[j] })
	for _, parent := range parents {
		batch := h.childBatches[parent]
		type namedCell struct {
			cell        uint32
			name, upper string
		}
		named := make([]namedCell, 0, len(batch.cells))
		for _, cell := range batch.cells {
			name, err := h.subkeyName(cell)
			if err != nil {
				return err
			}
			named = append(named, namedCell{cell: cell, name: name, upper: strings.ToUpper(name)})
		}
		sort.Slice(named, func(i, j int) bool {
			if named[i].upper != named[j].upper {
				return named[i].upper < named[j].upper
			}
			if named[i].name != named[j].name {
				return named[i].name < named[j].name
			}
			return named[i].cell < named[j].cell
		})
		cells := make([]uint32, len(named))
		for i, item := range named {
			cells[i] = item.cell
		}
		p, err := h.cellBody(parent)
		if err != nil {
			return err
		}
		old := binary.LittleEndian.Uint32(p[0x1c:0x20])
		oldCount := binary.LittleEndian.Uint32(p[0x14:0x18])
		list, err := h.writeSubkeyList(cells)
		if err != nil {
			return err
		}
		p, err = h.cellBody(parent)
		if err != nil {
			return err
		}
		// Deletion can remove the longest child name or class. Recompute
		// these header maxima from the final children, not historical edits.
		// The upper half contains UserFlags and other packed metadata.
		binary.LittleEndian.PutUint16(p[0x34:0x36], 0)
		binary.LittleEndian.PutUint32(p[0x38:0x3c], 0)
		for _, cell := range cells {
			child, err := h.cellBody(cell)
			if err != nil {
				return err
			}
			updateKeyMaxSubkeyName(p, child)
			classSize := uint32(binary.LittleEndian.Uint16(child[0x4a:0x4c]))
			if classSize > binary.LittleEndian.Uint32(p[0x38:0x3c]) {
				binary.LittleEndian.PutUint32(p[0x38:0x3c], classSize)
			}
		}
		binary.LittleEndian.PutUint32(p[0x14:0x18], uint32(len(cells)))
		binary.LittleEndian.PutUint32(p[0x1c:0x20], list)
		if oldCount > 0 && old != 0xffffffff {
			if err := h.freeSubkeyIndex(old); err != nil {
				return err
			}
		}
	}
	h.childBatches = nil
	return nil
}

// Preserve EqualFold lookup semantics, including non-ASCII simple-fold cycles.
// The overwhelmingly common ASCII names retain the allocation-light fast path.
func foldHiveBatchName(name string) string {
	ascii := true
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToUpper(name)
	}
	return strings.Map(func(r rune) rune {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		return smallest
	}, name)
}
