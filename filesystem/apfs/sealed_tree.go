package apfs

import (
	"bytes"
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Record contains one filesystem B-tree key and value in traversal order.
type Record struct{ Key, Value []byte }

// Records copies the live filesystem metadata, verifying sealed nodes before
// exposing their records. File extents in a sealed volume's separate extent
// tree are not part of these authenticated metadata records.
func (v *Volume) Records() ([]Record, error) {
	if v.Flags&1 == 0 {
		return nil, fmt.Errorf("apfs: encrypted volume unsupported")
	}
	root, err := v.rootAddress(v.RootTree, v.RootTreeType)
	if err != nil {
		return nil, err
	}
	resolver := func(id uint64) (uint64, error) { return v.rootAddress(id, v.RootTreeType) }
	var hashType uint32
	var rootHash []byte
	if v.Incompatible&0x20 != 0 {
		s, err := v.SealInformation()
		if err != nil {
			return nil, err
		}
		if s.Flags != 0 {
			return nil, fmt.Errorf("apfs: volume seal is broken")
		}
		hashType, rootHash, resolver = s.HashType, s.RootHash, v.sealedResolver(s)
	}
	var records []Record
	var size uint64
	err = v.container.walkTreeHash(root, resolver, hashType, rootHash, func(k, b []byte) error {
		size += uint64(len(k) + len(b))
		if size > 256<<20 {
			return fmt.Errorf("apfs: metadata records exceed 256 MiB")
		}
		records = append(records, Record{append([]byte(nil), k...), append([]byte(nil), b...)})
		return nil
	})
	return records, err
}

type sealedNode struct {
	id           uint64
	level        uint16
	records      []Record
	children     []*sealedNode
	maxKey       int
	tableSlots   int
	deleted      *Record
	deletedChild *sealedNode
}

// SealedTree is a relocatable, headerless, authenticated filesystem B-tree.
// Node identifiers are relative to the root (node zero); installers must map
// all node IDs through the volume object map. It contains no file extents.
type SealedTree struct {
	File           storage.Reader
	RootHash       []byte
	Nodes, Records uint64
}

// EncodeSealedTree constructs the packed sequential-insertion layout used by
// sealed APFS filesystems. Input records must already be in APFS key order.
// The complete returned tree stays in memory, independently of disk placement.
func EncodeSealedTree(records []Record, blockSize, hashType uint32) (*SealedTree, error) {
	if blockSize < 4096 || blockSize > 65536 || blockSize&(blockSize-1) != 0 || len(records) == 0 || len(records) > 1000000 {
		return nil, fmt.Errorf("apfs: invalid sealed tree geometry/record count")
	}
	h, err := sealHasher(hashType)
	if err != nil {
		return nil, err
	}
	hashSize := h.Size()
	root := &sealedNode{}
	nodes := []*sealedNode{root}
	var total uint64
	var longestKey, longestValue uint32
	for _, r := range records {
		if len(r.Key) < 8 || len(r.Key) > 65535 || len(r.Value) == 0 || len(r.Value) > 65535 {
			return nil, fmt.Errorf("apfs: invalid sealed record length")
		}
		total += uint64(len(r.Key) + len(r.Value))
		if total > 256<<20 {
			return nil, fmt.Errorf("apfs: sealed metadata exceeds 256 MiB")
		}
		longestKey = max(longestKey, uint32(len(r.Key)))
		longestValue = max(longestValue, uint32(len(r.Value)))
	}
	newNode := func(level uint16) *sealedNode {
		n := &sealedNode{id: uint64(len(nodes)), level: level}
		nodes = append(nodes, n)
		return n
	}
	// Internal values have an OID followed by the actual digest size, rather
	// than the 64-byte hash capacity described by the older format reference.
	indexRecord := func(child *sealedNode) Record { return Record{child.records[0].Key, make([]byte, 8+hashSize)} }
	fits := func(n *sealedNode, r Record) bool {
		count := len(n.records) + 1
		size := 56 + max(n.tableSlots, ((count+7)/8)*8)*8 + len(r.Key) + len(r.Value)
		if n == root {
			size += 40
		}
		for _, r := range n.records {
			size += len(r.Key) + len(r.Value)
		}
		return size <= int(blockSize)
	}
	indexFits := func(n *sealedNode, first, second int) bool {
		size := 56 + max(n.tableSlots, ((len(n.records)+2+7)/8)*8)*8 + first + second + 2*(8+hashSize)
		if n == root {
			size += 40
		}
		for _, r := range n.records {
			size += len(r.Key) + len(r.Value)
		}
		return size <= int(blockSize)
	}
	growRoot := func(right *sealedNode) error {
		if root.level >= 32 {
			return fmt.Errorf("apfs: sealed tree exceeds depth limit")
		}
		left := newNode(root.level)
		left.records, left.children = root.records, root.children
		left.maxKey = root.maxKey
		left.tableSlots = ((len(root.records) + 7) / 8) * 8
		root.level++
		root.records = []Record{indexRecord(left), indexRecord(right)}
		root.children = []*sealedNode{left, right}
		root.tableSlots = 8
		root.deleted, root.deletedChild = nil, nil
		root.maxKey = max(len(root.records[0].Key), len(root.records[1].Key))
		return nil
	}
	var insert func(*sealedNode, Record) (*sealedNode, error)
	insert = func(n *sealedNode, r Record) (*sealedNode, error) {
		var child *sealedNode
		if n.level != 0 {
			last := len(n.children) - 1
			lastChild := n.children[last]
			first := lastChild.maxKey
			if n.level >= 2 {
				first = max(first, len(r.Key))
			}
			childFits := fits(lastChild, r)
			if n.level >= 2 {
				childFits = indexFits(lastChild, len(r.Key), len(r.Key))
			}
			// A failed parent reservation alone does not require a split:
			// the child may accept this insertion without another separator.
			if !indexFits(n, first, len(r.Key)) && !childFits {
				if last == 0 {
					return nil, fmt.Errorf("apfs: index reservation cannot fit a node")
				}
				right := newNode(n.level)
				right.records = []Record{n.records[last]}
				right.children = []*sealedNode{n.children[last]}
				right.maxKey = len(n.records[last].Key)
				right.tableSlots = 8
				copyRecord := n.records[last]
				n.deleted, n.deletedChild = &copyRecord, n.children[last]
				n.records, n.children = n.records[:last], n.children[:last]
				n.maxKey = 0
				for _, existing := range n.records {
					n.maxKey = max(n.maxKey, len(existing.Key))
				}
				if n == root {
					// Allocate the left clone before descending into the right
					// subtree, which may allocate another leaf of its own.
					if err := growRoot(right); err != nil {
						return nil, err
					}
					return insert(root, r)
				}
				if extra, err := insert(right, r); err != nil {
					return nil, err
				} else if extra != nil {
					return nil, fmt.Errorf("apfs: sequential index split overflow")
				}
				return right, nil
			}
			var e error
			child, e = insert(n.children[len(n.children)-1], r)
			if e != nil {
				return nil, e
			}
			if child == nil {
				return nil, nil
			}
			r = indexRecord(child)
		}
		if fits(n, r) {
			requested := len(n.records) + 1
			n.tableSlots = max(n.tableSlots, ((requested+7)/8)*8)
			n.records = append(n.records, r)
			n.maxKey = max(n.maxKey, len(r.Key))
			if child != nil {
				n.children = append(n.children, child)
			}
			return nil, nil
		}
		if len(n.records) == 0 {
			// An empty root still needs its footer. Splitting it would leave
			// no first key from which to construct the left separator.
			return nil, fmt.Errorf("apfs: sealed record cannot fit a node")
		}
		right := newNode(n.level)
		if !fits(right, r) {
			return nil, fmt.Errorf("apfs: sealed record cannot fit a node")
		}
		right.records = []Record{r}
		right.maxKey = len(r.Key)
		right.tableSlots = 8
		if child != nil {
			return nil, fmt.Errorf("apfs: index reservation did not cover insertion")
		}
		return right, nil
	}
	for _, r := range records {
		right, e := insert(root, r)
		if e != nil {
			return nil, e
		}
		if right != nil {
			if err := growRoot(right); err != nil {
				return nil, err
			}
		}
		if uint64(len(nodes))*uint64(blockSize) > 256<<20 {
			return nil, fmt.Errorf("apfs: sealed tree exceeds 256 MiB")
		}
	}
	data := make([]byte, len(nodes)*int(blockSize))
	var encode func(*sealedNode) ([]byte, error)
	encode = func(n *sealedNode) ([]byte, error) {
		b := data[n.id*uint64(blockSize) : (n.id+1)*uint64(blockSize)]
		flags := uint16(0x18)
		end := len(b)
		if n.level == 0 {
			flags |= 2
		}
		if n == root {
			flags |= 1
			end -= 40
		}
		le.PutUint16(b[32:], flags)
		le.PutUint16(b[34:], n.level)
		le.PutUint32(b[36:], uint32(len(n.records)))
		tableSize := n.tableSlots * 8
		le.PutUint16(b[42:], uint16(tableSize))
		le.PutUint16(b[48:], 65535)
		le.PutUint16(b[52:], 65535)
		keyBase := 56 + tableSize
		kp, vp := keyBase, end
		encodedRecords := n.records
		if n.deleted != nil {
			encodedRecords = append(append([]Record(nil), n.records...), *n.deleted)
		}
		for i, r := range encodedRecords {
			value := r.Value
			if n.level != 0 {
				child := n.deletedChild
				if i < len(n.children) {
					child = n.children[i]
				}
				// Hashes are finalized only for live separators. A freed value
				// retains its zero digest placeholder from insertion time.
				sum := make([]byte, hashSize)
				if i < len(n.records) {
					var e error
					sum, e = encode(child)
					if e != nil {
						return nil, e
					}
				}
				value = le.AppendUint64(nil, child.id)
				value = append(value, sum...)
			}
			vp -= len(value)
			toc := b[56+i*8:]
			le.PutUint16(toc, uint16(kp-keyBase))
			le.PutUint16(toc[2:], uint16(len(r.Key)))
			le.PutUint16(toc[4:], uint16(end-vp))
			le.PutUint16(toc[6:], uint16(len(value)))
			copy(b[kp:], r.Key)
			copy(b[vp:], value)
			if i == len(n.records) {
				le.PutUint16(b[48:], uint16(kp-keyBase))
				le.PutUint16(b[50:], uint16(len(r.Key)))
				le.PutUint16(b[52:], uint16(end-vp))
				le.PutUint16(b[54:], uint16(len(value)))
				le.PutUint16(b[kp:], 65535)
				le.PutUint16(b[kp+2:], uint16(len(r.Key)))
				le.PutUint16(b[vp:], 65535)
				le.PutUint16(b[vp+2:], uint16(len(value)))
			}
			kp += len(r.Key)
		}
		if kp > vp {
			return nil, fmt.Errorf("apfs: sealed node encoding overflow")
		}
		le.PutUint16(b[44:], uint16(kp-keyBase))
		le.PutUint16(b[46:], uint16(vp-kp))
		if n == root {
			info := b[end:]
			le.PutUint32(info, 0x1c2)
			le.PutUint32(info[4:], blockSize)
			le.PutUint32(info[16:], longestKey)
			le.PutUint32(info[20:], longestValue)
			le.PutUint64(info[24:], uint64(len(records)))
			le.PutUint64(info[32:], uint64(len(nodes)))
		}
		h.Reset()
		h.Write(b)
		return h.Sum(nil), nil
	}
	sum, err := encode(root)
	if err != nil {
		return nil, err
	}
	return &SealedTree{File: bytes.NewReader(data), RootHash: sum, Nodes: uint64(len(nodes)), Records: uint64(len(records))}, nil
}

func recordsBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.records", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("records", args, kwargs); err != nil {
			return nil, err
		}
		records, err := v.Records()
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(records))
		for i, r := range records {
			out[i] = starlark.Tuple{starlark.Bytes(r.Key), starlark.Bytes(r.Value)}
		}
		return starlark.NewList(out), nil
	})
}

func SealedTreeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	blockSize, hashType := 4096, 1
	if err := starlark.UnpackArgs("apfs_sealed_tree", args, kwargs, "records", &values, "block_size?", &blockSize, "hash_type?", &hashType); err != nil {
		return nil, err
	}
	if blockSize < 4096 || blockSize > 65536 || hashType < 1 || hashType > 4 {
		return nil, fmt.Errorf("apfs: invalid sealed tree parameters")
	}
	records, err := recordsFromList(values)
	if err != nil {
		return nil, err
	}
	tree, err := EncodeSealedTree(records, uint32(blockSize), uint32(hashType))
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{"file": starfile.NewReader("APFS sealed tree", tree.File), "root_hash": starlark.Bytes(tree.RootHash), "nodes": starlark.MakeUint64(tree.Nodes), "records": starlark.MakeUint64(tree.Records)}), nil
}

func recordsFromList(values *starlark.List) ([]Record, error) {
	if values.Len() > 1000000 {
		return nil, fmt.Errorf("apfs: excessive sealed records")
	}
	records := make([]Record, values.Len())
	var total uint64
	for i := range records {
		p, ok := values.Index(i).(starlark.Tuple)
		if !ok || len(p) != 2 {
			return nil, fmt.Errorf("apfs: expected (key,value) record tuple")
		}
		k, kok := p[0].(starlark.Bytes)
		b, bok := p[1].(starlark.Bytes)
		if !kok || !bok {
			return nil, fmt.Errorf("apfs: record key and value must be bytes")
		}
		total += uint64(len(k) + len(b))
		if len(k) < 8 || len(k) > 65535 || len(b) == 0 || len(b) > 65535 || total > 256<<20 {
			return nil, fmt.Errorf("apfs: invalid or excessive sealed metadata")
		}
		records[i] = Record{[]byte(k), []byte(b)}
	}
	return records, nil
}
