package repo

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// During a physical recovery scan, replay one ref change against the previous
// immutable index. Verify only freshly path-copied pages and their canonical
// identities; reloading every historical full catalog would be quadratic.
// This encoding is the same bounded index encoding used by saveIndex.
func (r *Repository) verifyRefTransition(n *childIndex) (ID, error) {
	if n == nil {
		return "", nil
	}
	if n.id != "" {
		return n.id, nil
	}
	var data []byte
	if n.slots == nil {
		if !fitsLeaf(n.size, n.weight) {
			return "", fmt.Errorf("invalid ref leaf")
		}
		data = binary.BigEndian.AppendUint16([]byte{0}, uint16(n.size))
		for _, e := range n.entries {
			data = binary.BigEndian.AppendUint16(data, uint16(len(e.name)))
			data = append(data, e.name...)
			data = append(data, 1, 0, 0)
			var err error
			data, err = appendRawID(data, e.value.id)
			if err != nil {
				return "", err
			}
		}
	} else {
		var bitmap uint16
		for i, c := range n.slots {
			if c != nil {
				bitmap |= 1 << i
			}
		}
		data = binary.BigEndian.AppendUint16([]byte{1}, bitmap)
		for _, c := range n.slots {
			if c == nil {
				continue
			}
			id, err := r.verifyRefTransition(c)
			if err != nil {
				return "", err
			}
			data, err = appendRawID(data, id)
			if err != nil {
				return "", err
			}
		}
	}
	id := digest(indexKind, data)
	stored, err := r.get(id, indexKind)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(stored, data) {
		return "", fmt.Errorf("invalid ref transition page")
	}
	if n.slots == nil {
		for _, e := range n.entries {
			if !r.earlier(e.value.id, id) {
				return "", fmt.Errorf("ref target must precede index")
			}
		}
	} else {
		for _, c := range n.slots {
			if c != nil && !r.earlier(c.id, id) {
				return "", fmt.Errorf("ref child must precede index")
			}
		}
	}
	n.id = id
	return id, nil
}
