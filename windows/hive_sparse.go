package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go.starlark.net/starlark"
)

// Sparse operations run on the transaction's owned bytes. No partial edit is
// published on failure. Paths are literal component lists when supplied as such.
func hiveEditParts(value starlark.Value) ([]string, error) {
	if text, ok := starlark.AsString(value); ok {
		return mutableHivePathParts(text), nil
	}
	if record, ok := value.(*starlark.Dict); ok {
		parts, _, err := registryPathFromDict(record)
		return parts, err
	}
	return nil, fmt.Errorf("patch_hive: expected non-empty string or key/key_parts record")
}

func (h *mutableHive) deleteKeyParts(parts []string) error {
	if len(parts) == 0 {
		return fmt.Errorf("patch_hive: cannot delete the hive root")
	}
	parent, err := h.lookupKeyParts(parts[:len(parts)-1])
	if err != nil {
		return err
	}
	batch, err := h.childBatch(parent)
	if err != nil {
		return err
	}
	name := foldHiveBatchName(parts[len(parts)-1])
	cell, ok := batch.cells[name]
	if !ok {
		return fmt.Errorf("patch_hive: deleted key does not exist")
	}
	seen := make(map[uint32]bool)
	var remove func(uint32, int) error
	remove = func(cell uint32, depth int) error {
		if depth > 512 || len(seen) >= 1<<20 || seen[cell] {
			return fmt.Errorf("patch_hive: cyclic or oversized deletion")
		}
		seen[cell] = true
		key, err := h.cellBody(cell)
		if err != nil {
			return err
		}
		if len(key) < 0x4c || string(key[:2]) != "nk" {
			return fmt.Errorf("patch_hive: invalid deleted key")
		}
		if binary.LittleEndian.Uint32(key[0x18:]) != 0 {
			return fmt.Errorf("patch_hive: volatile deleted subkeys unsupported")
		}
		count := binary.LittleEndian.Uint32(key[0x14:])
		list := binary.LittleEndian.Uint32(key[0x1c:])
		if count > 0 {
			children, err := h.subkeyCells(list)
			if err != nil {
				return err
			}
			if uint32(len(children)) != count {
				return fmt.Errorf("patch_hive: deleted child count mismatch")
			}
			for _, child := range children {
				if err := remove(child, depth+1); err != nil {
					return err
				}
			}
			if err := h.freeSubkeyIndex(list); err != nil {
				return err
			}
		}
		valueCount := binary.LittleEndian.Uint32(key[0x24:])
		valueList := binary.LittleEndian.Uint32(key[0x28:])
		if valueCount > 0 {
			cells, err := h.valueCells(valueList, int(valueCount))
			if err != nil {
				return err
			}
			for _, value := range cells {
				if err := h.freeValue(value); err != nil {
					return err
				}
			}
			if err := h.freeCell(valueList); err != nil {
				return err
			}
		}
		if binary.LittleEndian.Uint16(key[0x4a:]) != 0 {
			if err := h.freeCell(binary.LittleEndian.Uint32(key[0x30:])); err != nil {
				return err
			}
		}
		if err := h.releaseSecurity(binary.LittleEndian.Uint32(key[0x2c:])); err != nil {
			return err
		}
		delete(h.childBatches, cell)
		return h.freeCell(cell)
	}
	if err := remove(cell, 0); err != nil {
		return err
	}
	delete(batch.cells, name)
	batch.dirty = true
	return nil
}

// ri index nodes own their leaves too. Freeing only the ri cell leaks allocated
// leaf cells every time a wide sibling list is rewritten.
func (h *mutableHive) freeSubkeyIndex(cell uint32) error {
	seen := make(map[uint32]bool)
	var visit func(uint32, int) error
	visit = func(cell uint32, depth int) error {
		if depth > 32 || len(seen) >= 1<<20 || seen[cell] {
			return fmt.Errorf("patch_hive: cyclic subkey index")
		}
		seen[cell] = true
		data, err := h.cellBody(cell)
		if err != nil {
			return err
		}
		if len(data) < 4 {
			return fmt.Errorf("patch_hive: short subkey index")
		}
		count := int(binary.LittleEndian.Uint16(data[2:]))
		switch string(data[:2]) {
		case "ri":
			if count > (len(data)-4)/4 {
				return fmt.Errorf("patch_hive: short ri index")
			}
			for i := 0; i < count; i++ {
				if err := visit(binary.LittleEndian.Uint32(data[4+i*4:]), depth+1); err != nil {
					return err
				}
			}
		case "li":
			if count > (len(data)-4)/4 {
				return fmt.Errorf("patch_hive: short li index")
			}
		case "lf", "lh":
			if count > (len(data)-4)/8 {
				return fmt.Errorf("patch_hive: short leaf index")
			}
		default:
			return fmt.Errorf("patch_hive: invalid subkey index signature")
		}
		return h.freeCell(cell)
	}
	return visit(cell, 0)
}

func (h *mutableHive) freeValue(cell uint32) error {
	value, err := h.cellBody(cell)
	if err != nil {
		return err
	}
	if len(value) < 0x14 || string(value[:2]) != "vk" {
		return fmt.Errorf("patch_hive: invalid deleted value")
	}
	length := binary.LittleEndian.Uint32(value[4:])
	if length != 0 && length&0x80000000 == 0 {
		dataCell := binary.LittleEndian.Uint32(value[8:])
		data, err := h.cellBody(dataCell)
		if err != nil {
			return err
		}
		if length > hiveBigDataSegmentSize && binary.LittleEndian.Uint32(h.data[0x18:]) >= 4 {
			if len(data) < 8 || string(data[:2]) != "db" {
				return fmt.Errorf("patch_hive: invalid deleted big data")
			}
			count := int(binary.LittleEndian.Uint16(data[2:]))
			if uint64(count) != (uint64(length)+hiveBigDataSegmentSize-1)/hiveBigDataSegmentSize {
				return fmt.Errorf("patch_hive: deleted big-data count mismatch")
			}
			listCell := binary.LittleEndian.Uint32(data[4:])
			list, err := h.cellBody(listCell)
			if err != nil {
				return err
			}
			if count > len(list)/4 {
				return fmt.Errorf("patch_hive: short deleted big-data list")
			}
			for i := 0; i < count; i++ {
				if err := h.freeCell(binary.LittleEndian.Uint32(list[4*i:])); err != nil {
					return err
				}
			}
			if err := h.freeCell(listCell); err != nil {
				return err
			}
		} else if uint64(length) > uint64(len(data)) {
			return fmt.Errorf("patch_hive: truncated deleted value")
		}
		if err := h.freeCell(dataCell); err != nil {
			return err
		}
	} else if length&0x80000000 != 0 && length&0x7fffffff > 4 {
		return fmt.Errorf("patch_hive: invalid inline value")
	}
	return h.freeCell(cell)
}

func (h *mutableHive) securityCell(cell uint32) ([]byte, error) {
	data, err := h.cellBody(cell)
	if err != nil {
		return nil, err
	}
	if len(data) < 20 || string(data[:2]) != "sk" || uint64(binary.LittleEndian.Uint32(data[16:])) > uint64(len(data)-20) {
		return nil, fmt.Errorf("patch_hive: invalid security cell")
	}
	return data, nil
}

func (h *mutableHive) releaseSecurity(cell uint32) error {
	if cell == 0xffffffff {
		return nil
	}
	data, err := h.securityCell(cell)
	if err != nil {
		return err
	}
	refs := binary.LittleEndian.Uint32(data[12:])
	if refs == 0 {
		return fmt.Errorf("patch_hive: security reference underflow")
	}
	if refs > 1 {
		binary.LittleEndian.PutUint32(data[12:], refs-1)
		return nil
	}
	next, previous := binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:])
	n, err := h.securityCell(next)
	if err != nil {
		return err
	}
	p, err := h.securityCell(previous)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(n[8:]) != cell || binary.LittleEndian.Uint32(p[4:]) != cell {
		return fmt.Errorf("patch_hive: broken security ring")
	}
	binary.LittleEndian.PutUint32(n[8:], previous)
	binary.LittleEndian.PutUint32(p[4:], next)
	descriptor := string(data[20 : 20+int(binary.LittleEndian.Uint32(data[16:]))])
	if h.securityCells[descriptor] == cell {
		delete(h.securityCells, descriptor)
	}
	return h.freeCell(cell)
}

func (h *mutableHive) setKeySecurity(cell uint32, descriptor []byte) error {
	if err := validateSelfRelativeSecurityDescriptor(descriptor); err != nil {
		return err
	}
	key, err := h.cellBody(cell)
	if err != nil {
		return err
	}
	old := binary.LittleEndian.Uint32(key[0x2c:])
	if old != 0xffffffff {
		oldData, err := h.securityCell(old)
		if err != nil {
			return err
		}
		if bytes.Equal(descriptor, oldData[20:20+int(binary.LittleEndian.Uint32(oldData[16:]))]) {
			return nil
		}
	}
	root, err := h.cellBody(h.rootCell())
	if err != nil {
		return err
	}
	anchor := binary.LittleEndian.Uint32(root[0x2c:])
	if h.securityCells == nil {
		h.securityCells = make(map[string]uint32)
		seen := make(map[uint32]bool)
		for current := anchor; current != 0xffffffff; {
			if seen[current] || len(seen) >= 1<<20 {
				return fmt.Errorf("patch_hive: cyclic security ring")
			}
			seen[current] = true
			data, err := h.securityCell(current)
			if err != nil {
				return err
			}
			h.securityCells[string(data[20:20+int(binary.LittleEndian.Uint32(data[16:]))])] = current
			current = binary.LittleEndian.Uint32(data[4:])
			if current == anchor {
				break
			}
		}
	}
	replacement, found := h.securityCells[string(descriptor)]
	if found {
		if err := h.incrementSecurityReference(replacement); err != nil {
			return err
		}
	} else {
		data := make([]byte, 20+len(descriptor))
		copy(data, "sk")
		binary.LittleEndian.PutUint32(data[12:], 1)
		binary.LittleEndian.PutUint32(data[16:], uint32(len(descriptor)))
		copy(data[20:], descriptor)
		replacement, err = h.allocateCell(data)
		if err != nil {
			return err
		}
		data, _ = h.cellBody(replacement)
		if anchor == 0xffffffff {
			binary.LittleEndian.PutUint32(data[4:], replacement)
			binary.LittleEndian.PutUint32(data[8:], replacement)
		} else {
			a, err := h.securityCell(anchor)
			if err != nil {
				return err
			}
			next := binary.LittleEndian.Uint32(a[4:])
			n, err := h.securityCell(next)
			if err != nil {
				return err
			}
			if binary.LittleEndian.Uint32(n[8:]) != anchor {
				return fmt.Errorf("patch_hive: broken security ring")
			}
			binary.LittleEndian.PutUint32(data[4:], next)
			binary.LittleEndian.PutUint32(data[8:], anchor)
			binary.LittleEndian.PutUint32(a[4:], replacement)
			binary.LittleEndian.PutUint32(n[8:], replacement)
		}
		h.securityCells[string(descriptor)] = replacement
	}
	key, err = h.cellBody(cell)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(key[0x2c:], replacement)
	return h.releaseSecurity(old)
}

func (h *mutableHive) applyKeyRecord(value starlark.Value) error {
	if text, ok := starlark.AsString(value); ok && text == "" {
		return fmt.Errorf("patch_hive: key must not be empty")
	}
	parts, err := hiveEditParts(value)
	if err != nil {
		return err
	}
	cell, err := h.ensureKeyParts(parts)
	if err != nil {
		return err
	}
	record, ok := value.(*starlark.Dict)
	if !ok {
		return nil
	}
	for _, key := range record.Keys() {
		if key != starlark.String("key") && key != starlark.String("key_parts") && key != starlark.String("security") {
			return fmt.Errorf("patch_hive: unsupported key metadata %s", key)
		}
	}
	if security, found, err := record.Get(starlark.String("security")); err != nil {
		return err
	} else if found {
		data, err := bytesForValue(security)
		if err != nil {
			return err
		}
		return h.setKeySecurity(cell, data)
	}
	return nil
}
