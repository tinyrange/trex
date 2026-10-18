package windows

import "encoding/binary"

// An offset-ordered treap with subtree maximum free sizes preserves the old
// first-fit allocation policy without rescanning every allocated hive cell.
// It is private to a mutable hive and built lazily; on-disk bytes are unchanged.
type hiveFreeIndex struct {
	root *hiveFreeNode
	bins []int
}
type hiveFreeNode struct {
	offset, bin, size, maximum int
	priority                   uint64
	left, right                *hiveFreeNode
}

func hiveFreeMax(n *hiveFreeNode) int {
	if n == nil {
		return 0
	}
	return n.maximum
}
func (n *hiveFreeNode) update() { n.maximum = max(n.size, hiveFreeMax(n.left), hiveFreeMax(n.right)) }
func (f *hiveFreeIndex) add(bin, offset, size int) {
	// Stable mixing avoids a degenerate tree for sequential cell offsets.
	x := uint64(offset) + 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	x ^= x >> 31
	f.root = insertHiveFree(f.root, &hiveFreeNode{offset: offset, bin: bin, size: size, maximum: size, priority: x})
}
func insertHiveFree(root, n *hiveFreeNode) *hiveFreeNode {
	if root == nil {
		return n
	}
	if n.offset < root.offset {
		root.left = insertHiveFree(root.left, n)
		if root.left.priority < root.priority {
			p := root.left
			root.left = p.right
			p.right = root
			root.update()
			root = p
		}
	} else if n.offset > root.offset {
		root.right = insertHiveFree(root.right, n)
		if root.right.priority < root.priority {
			p := root.right
			root.right = p.left
			p.left = root
			root.update()
			root = p
		}
	} else {
		root.size = n.size
		root.bin = n.bin
	}
	root.update()
	return root
}
func mergeHiveFree(a, b *hiveFreeNode) *hiveFreeNode {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.priority < b.priority {
		a.right = mergeHiveFree(a.right, b)
		a.update()
		return a
	}
	b.left = mergeHiveFree(a, b.left)
	b.update()
	return b
}
func removeHiveFree(n *hiveFreeNode, offset int) *hiveFreeNode {
	if n == nil {
		return nil
	}
	if offset < n.offset {
		n.left = removeHiveFree(n.left, offset)
	} else if offset > n.offset {
		n.right = removeHiveFree(n.right, offset)
	} else {
		return mergeHiveFree(n.left, n.right)
	}
	n.update()
	return n
}
func (f *hiveFreeIndex) firstFit(size int) *hiveFreeNode {
	n := f.root
	for n != nil {
		if hiveFreeMax(n.left) >= size {
			n = n.left
		} else if n.size >= size {
			return n
		} else if hiveFreeMax(n.right) >= size {
			n = n.right
		} else {
			return nil
		}
	}
	return nil
}
func (h *mutableHive) indexFreeCells() {
	f := &hiveFreeIndex{}
	h.freeCells = f
	hiveSize := int(binary.LittleEndian.Uint32(h.data[0x28:0x2c]))
	for binRel := 0; binRel+0x20 <= hiveSize; {
		binOff := hiveBaseBlockSize + binRel
		if binOff+0x20 > len(h.data) || string(h.data[binOff:binOff+4]) != "hbin" {
			return
		}
		binSize := int(binary.LittleEndian.Uint32(h.data[binOff+8 : binOff+12]))
		if binSize <= 0 || binSize > len(h.data)-binOff {
			return
		}
		f.bins = append(f.bins, binOff)
		for cellOff := binOff + 0x20; cellOff+4 <= binOff+binSize; {
			raw := int32(binary.LittleEndian.Uint32(h.data[cellOff : cellOff+4]))
			size := int(raw)
			if size < 0 {
				size = -size
			}
			if size < 8 || size > binOff+binSize-cellOff {
				break
			}
			if raw > 0 {
				f.add(binOff, cellOff, size)
			}
			cellOff += size
		}
		binRel += binSize
	}
}
