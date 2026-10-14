package apfs

import (
	"bytes"
	"fmt"
	"sort"
)

// walkTree traverses physical or explicitly resolved virtual nodes. Keys and
// values are valid only during the callback. Layout allocations are bounded.
func (c *Container) walkTree(root uint64, resolveNode func(uint64) (uint64, error), visit func([]byte, []byte) error) error {
	return c.walkTreeHash(root, resolveNode, 0, nil, visit)
}

// walkTreeHash verifies every node against its parent before exposing records.
// Headerless sealed trees use root-relative child object identifiers, which keeps
// their hashes independent of the placement of the installed filesystem.
func (c *Container) walkTreeHash(root uint64, resolveNode func(uint64) (uint64, error), hashType uint32, rootHash []byte, visit func([]byte, []byte) error) error {
	return c.walkTreeNodes(root, resolveNode, hashType, rootHash, visit, nil)
}

// walkTreeNodes additionally exposes authenticated/checksummed node addresses
// to image construction, so replaced metadata can be accounted for exactly.
func (c *Container) walkTreeNodes(root uint64, resolveNode func(uint64) (uint64, error), hashType uint32, rootHash []byte, visit func([]byte, []byte) error, visitNode func(uint64, []byte) error) error {
	rootBlock, err := c.raw(root)
	if err != nil {
		return err
	}
	info := rootBlock[len(rootBlock)-40:]
	treeFlags, keySize, valueSize := le.Uint32(info), int(le.Uint32(info[8:])), int(le.Uint32(info[12:]))
	hashSize := 0
	if treeFlags&0x80 != 0 {
		h, err := sealHasher(hashType)
		if err != nil {
			return err
		}
		hashSize = h.Size()
		if len(rootHash) != hashSize {
			return fmt.Errorf("apfs: missing root seal hash")
		}
	} else if hashType != 0 || treeFlags&0x100 != 0 {
		return fmt.Errorf("apfs: inconsistent hashed B-tree flags")
	}
	if le.Uint32(info[4:]) != c.BlockSize || keySize > int(c.BlockSize) || valueSize > int(c.BlockSize) {
		return fmt.Errorf("apfs: invalid B-tree sizes")
	}
	seen := map[uint64]bool{}
	count := 0
	var walk func(uint64, int, int, []byte) error
	walk = func(address uint64, depth, expectedLevel int, expectedHash []byte) error {
		if depth > 32 || len(seen) >= 100000 || seen[address] {
			return fmt.Errorf("apfs: cyclic or excessive B-tree")
		}
		seen[address] = true
		b, err := c.raw(address)
		if err != nil {
			return err
		}
		flags, level, nkeys := le.Uint16(b[32:]), int(le.Uint16(b[34:])), int(le.Uint32(b[36:]))
		if flags & ^uint16(31) != 0 || (depth == 0) != (flags&1 != 0) || (level == 0) != (flags&2 != 0) || (expectedLevel >= 0 && level != expectedLevel) || (flags&8 != 0) != (hashSize != 0) || (flags&16 != 0) != (treeFlags&0x100 != 0) {
			return fmt.Errorf("apfs: inconsistent B-tree node at %d", address)
		}
		if hashSize != 0 {
			h, _ := sealHasher(hashType)
			h.Write(b)
			if !bytes.Equal(h.Sum(nil), expectedHash) {
				return fmt.Errorf("apfs: B-tree seal hash mismatch at %d", address)
			}
		}
		if flags&16 != 0 {
			if !bytes.Equal(b[:32], make([]byte, 32)) {
				return fmt.Errorf("apfs: nonzero headerless object header")
			}
		} else {
			if err := verify(b); err != nil {
				return fmt.Errorf("apfs: B-tree block %d: %w", address, err)
			}
			if kind := le.Uint32(b[24:]) & 0xffff; (depth == 0 && kind != 2) || (depth != 0 && kind != 3) {
				return fmt.Errorf("apfs: invalid B-tree object type")
			}
		}
		if visitNode != nil {
			if err := visitNode(address, b); err != nil {
				return err
			}
		}
		table := 56 + int(le.Uint16(b[40:]))
		tableSize := int(le.Uint16(b[42:]))
		keyBase, end := table+tableSize, len(b)
		if depth == 0 {
			end -= 40
		}
		width := 8
		if flags&4 != 0 {
			width = 4
		}
		if table < 56 || keyBase > end || nkeys > (tableSize/width) {
			return fmt.Errorf("apfs: invalid B-tree table")
		}
		type span struct{ start, end int }
		spans := make([]span, 0, 2*nkeys)
		for i := 0; i < nkeys; i++ {
			toc := b[table+i*width:]
			ko, kl, vo, vl := int(le.Uint16(toc)), keySize, 0, valueSize
			if width == 4 {
				vo = int(le.Uint16(toc[2:]))
				if level > 0 {
					vl = 8
					if hashSize != 0 {
						vl += hashSize
					}
				}
			} else {
				kl = int(le.Uint16(toc[2:]))
				vo = int(le.Uint16(toc[4:]))
				vl = int(le.Uint16(toc[6:]))
			}
			ks, vs := keyBase+ko, end-vo
			if ko == 65535 || vo == 65535 || kl <= 0 || vl <= 0 || ks < keyBase || ks > end-kl || vs < keyBase || vs > end-vl || ks+kl > vs {
				return fmt.Errorf("apfs: invalid B-tree key/value extent at %d", address)
			}
			k, v := b[ks:ks+kl], b[vs:vs+vl]
			spans = append(spans, span{ks, ks + kl}, span{vs, vs + vl})
			if level == 0 {
				count++
				if count > 1000000 {
					return fmt.Errorf("apfs: excessive B-tree records")
				}
				if err := visit(k, v); err != nil {
					return err
				}
			} else {
				if len(v) != 8+hashSize && !(hashSize != 0 && len(v) == 72) {
					return fmt.Errorf("apfs: truncated child reference")
				}
				child := le.Uint64(v)
				if resolveNode != nil {
					child, err = resolveNode(child)
					if err != nil {
						return err
					}
				} else if flags&16 != 0 {
					if child >= c.Blocks-root {
						return fmt.Errorf("apfs: relative child outside container")
					}
					child += root
				}
				if err := walk(child, depth+1, level-1, v[8:8+hashSize]); err != nil {
					return err
				}
			}
		}
		sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
		for i := 1; i < len(spans); i++ {
			if spans[i].start < spans[i-1].end {
				return fmt.Errorf("apfs: overlapping B-tree records")
			}
		}
		return nil
	}
	return walk(root, 0, -1, rootHash)
}
