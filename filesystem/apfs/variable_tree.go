package apfs

import "fmt"

// encodeVariableVirtualTree constructs ordinary mutable filesystem nodes.
// Child references and OMAP keys are virtual; allocation supplies their physical
// storage separately. Input ordering belongs to the filesystem key comparator.
func encodeVariableVirtualTree(rows []Record, blockSize uint32, rootID, xid uint64, nextID *uint64, allocate func() (uint64, error), write func(uint64, []byte) error) ([]Record, error) {
	type node struct {
		id, pa uint64
		level  uint16
		rows   []Record
	}
	if len(rows) == 0 || len(rows) > 16384 || blockSize < 4096 || blockSize > 65536 {
		return nil, fmt.Errorf("apfs: invalid variable tree bounds")
	}
	var nodes []*node
	partition := func(input []Record, level uint16) ([]*node, error) {
		var result []*node
		for start := 0; start < len(input); {
			end, used := start, 0
			for end < len(input) {
				r := input[end]
				count := end - start + 1
				table := max(8, (count+7)/8*8) * 8
				if 96+table+used+len(r.Key)+len(r.Value) > int(blockSize) {
					break
				}
				used += len(r.Key) + len(r.Value)
				end++
			}
			if end == start {
				return nil, fmt.Errorf("apfs: variable tree record exceeds node")
			}
			pa, err := allocate()
			if err != nil {
				return nil, err
			}
			n := &node{pa: pa, level: level, rows: input[start:end]}
			result = append(result, n)
			nodes = append(nodes, n)
			start = end
		}
		if len(result) == 1 {
			result[0].id = rootID
		} else {
			for _, n := range result {
				if *nextID == ^uint64(0) {
					return nil, fmt.Errorf("apfs: variable tree identifier overflow")
				}
				n.id = *nextID
				*nextID++
			}
		}
		return result, nil
	}
	current, err := partition(rows, 0)
	if err != nil {
		return nil, err
	}
	for len(current) > 1 {
		index := make([]Record, len(current))
		for i, n := range current {
			index[i] = Record{n.rows[0].Key, le.AppendUint64(nil, n.id)}
		}
		current, err = partition(index, current[0].level+1)
		if err != nil {
			return nil, err
		}
	}
	root := current[0]
	var longestKey, longestValue uint32
	for _, r := range rows {
		longestKey = max(longestKey, uint32(len(r.Key)))
		longestValue = max(longestValue, uint32(len(r.Value)))
	}
	mappings := make([]Record, 0, len(nodes))
	for _, n := range nodes {
		b, err := encodeVariablePhysicalLeaf(n.rows, blockSize, 14, n.pa, xid)
		if err != nil {
			return nil, err
		}
		le.PutUint64(b[8:], n.id)
		le.PutUint16(b[34:], n.level)
		le.PutUint32(b[24:], 3)
		le.PutUint16(b[32:], 0)
		if n.level == 0 {
			le.PutUint16(b[32:], 2)
		}
		if n == root {
			le.PutUint32(b[24:], 2)
			le.PutUint16(b[32:], le.Uint16(b[32:])|1)
			info := b[len(b)-40:]
			le.PutUint32(info, 0x42)
			le.PutUint32(info[16:], longestKey)
			le.PutUint32(info[20:], longestValue)
			le.PutUint64(info[24:], uint64(len(rows)))
			le.PutUint64(info[32:], uint64(len(nodes)))
		} else {
			// Non-root nodes have no footer; move their packed values to
			// the physical end while retaining end-relative ToC offsets.
			vp := len(b) - 40
			for _, r := range n.rows {
				vp -= len(r.Value)
			}
			copy(b[vp+40:], b[vp:len(b)-40])
			clear(b[vp : vp+40])
			le.PutUint16(b[46:], le.Uint16(b[46:])+40)
		}
		le.PutUint64(b, checksum(b))
		if err := write(n.pa, b); err != nil {
			return nil, err
		}
		key := le.AppendUint64(le.AppendUint64(nil, n.id), xid)
		value := le.AppendUint64(le.AppendUint32(le.AppendUint32(nil, 0), blockSize), n.pa)
		mappings = append(mappings, Record{key, value})
	}
	return mappings, nil
}
