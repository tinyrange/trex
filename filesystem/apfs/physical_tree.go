package apfs

import "fmt"

type physicalNode struct {
	address uint64
	level   uint16
	rows    []Record
}

// encodePhysicalTree writes ordinary fixed-key/value B-trees used by object
// maps and sealed-volume file-extent trees. Placement belongs to the caller;
// child references are physical addresses, independently of allocation order.
func encodePhysicalTree(rows []Record, blockSize, subtype uint32, xid uint64, allocate func() (uint64, error), write func(uint64, []byte) error) (uint64, uint64, error) {
	return encodeFixedPhysicalTree(rows, blockSize, subtype, 16, xid, allocate, write)
}

func encodeFixedPhysicalTree(rows []Record, blockSize, subtype, keySize uint32, xid uint64, allocate func() (uint64, error), write func(uint64, []byte) error) (uint64, uint64, error) {
	if blockSize < 4096 || blockSize > 65536 || blockSize&(blockSize-1) != 0 || len(rows) > 1000000 || allocate == nil || write == nil {
		return 0, 0, fmt.Errorf("apfs: invalid physical tree geometry")
	}
	if keySize != 8 && keySize != 16 {
		return 0, 0, fmt.Errorf("apfs: unsupported fixed key width")
	}
	for i, r := range rows {
		if len(r.Key) != int(keySize) || len(r.Value) != 16 {
			return 0, 0, fmt.Errorf("apfs: invalid physical tree key/value width")
		}
		if i > 0 {
			a, b := rows[i-1].Key, r.Key
			if le.Uint64(a) > le.Uint64(b) || le.Uint64(a) == le.Uint64(b) && (keySize == 8 || le.Uint64(a[8:]) >= le.Uint64(b[8:])) {
				return 0, 0, fmt.Errorf("apfs: unordered/duplicate physical tree key")
			}
		}
	}
	// Fixed nodes reserve the complete ToC, including unused slots. Its size
	// depends on the node geometry, not the number of live records or footer.
	// Each slot is four bytes and the table is rounded down to eight bytes.
	leafTable := ((int(blockSize) - 56) / (int(keySize) + 20) &^ 1) * 4
	indexTable := ((int(blockSize) - 56) / (int(keySize) + 12) &^ 1) * 4
	// Partition conservatively with footer space at every level, so either a
	// leaf or an index can become the root without changing its ToC geometry.
	leafCapacity := min(leafTable/4, (int(blockSize)-96-leafTable)/(int(keySize)+16))
	indexCapacity := min(indexTable/4, (int(blockSize)-96-indexTable)/(int(keySize)+8))
	var nodes []*physicalNode
	seen := map[uint64]bool{}
	newNode := func(level uint16, rows []Record) (*physicalNode, error) {
		address, err := allocate()
		if err != nil {
			return nil, err
		}
		if seen[address] || uint64(len(nodes)+1)*uint64(blockSize) > 256<<20 {
			return nil, fmt.Errorf("apfs: duplicate/excessive physical tree allocation")
		}
		seen[address] = true
		n := &physicalNode{address, level, rows}
		nodes = append(nodes, n)
		return n, nil
	}
	var current []*physicalNode
	for start := 0; start < len(rows) || len(current) == 0; {
		end := min(start+leafCapacity, len(rows))
		n, err := newNode(0, rows[start:end])
		if err != nil {
			return 0, 0, err
		}
		current = append(current, n)
		start = end
	}
	for len(current) > 1 {
		var next []*physicalNode
		for start := 0; start < len(current); start += indexCapacity {
			end := min(start+indexCapacity, len(current))
			index := make([]Record, end-start)
			for i, child := range current[start:end] {
				index[i] = Record{child.rows[0].Key, le.AppendUint64(nil, child.address)}
			}
			n, err := newNode(current[start].level+1, index)
			if err != nil {
				return 0, 0, err
			}
			next = append(next, n)
		}
		current = next
	}
	root := current[0]
	for _, n := range nodes {
		b := make([]byte, blockSize)
		le.PutUint64(b[8:], n.address)
		le.PutUint64(b[16:], xid)
		kind, flags := uint32(0x40000003), uint16(4)
		end := len(b)
		if n == root {
			kind, flags = 0x40000002, flags|1
			end -= 40
			info := b[end:]
			treeFlags := uint32(0x10)
			if keySize == 8 {
				treeFlags |= 1
			}
			le.PutUint32(info, treeFlags)
			le.PutUint32(info[4:], blockSize)
			le.PutUint32(info[8:], keySize)
			le.PutUint32(info[12:], 16)
			le.PutUint32(info[16:], keySize)
			le.PutUint32(info[20:], 16)
			le.PutUint64(info[24:], uint64(len(rows)))
			le.PutUint64(info[32:], uint64(len(nodes)))
		}
		if n.level == 0 {
			flags |= 2
		}
		le.PutUint32(b[24:], kind)
		le.PutUint32(b[28:], subtype)
		le.PutUint16(b[32:], flags)
		le.PutUint16(b[34:], n.level)
		le.PutUint32(b[36:], uint32(len(n.rows)))
		tableSize := leafTable
		if n.level != 0 {
			tableSize = indexTable
		}
		le.PutUint16(b[42:], uint16(tableSize))
		le.PutUint16(b[48:], 65535)
		le.PutUint16(b[52:], 65535)
		keyBase := 56 + tableSize
		kp, vp := keyBase, end
		for i, r := range n.rows {
			vp -= len(r.Value)
			le.PutUint16(b[56+i*4:], uint16(kp-keyBase))
			le.PutUint16(b[58+i*4:], uint16(end-vp))
			copy(b[kp:], r.Key)
			copy(b[vp:], r.Value)
			kp += len(r.Key)
		}
		if kp > vp {
			return 0, 0, fmt.Errorf("apfs: physical tree encoding overflow")
		}
		le.PutUint16(b[44:], uint16(kp-keyBase))
		le.PutUint16(b[46:], uint16(vp-kp))
		le.PutUint64(b, checksum(b))
		if err := write(n.address, b); err != nil {
			return 0, 0, err
		}
	}
	return root.address, uint64(len(nodes)), nil
}
