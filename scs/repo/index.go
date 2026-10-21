package repo

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"path"
	"sort"
)

const (
	indexLeafEntries = 32
	indexTargetBytes = 4096
	indexEntryBytes  = 37                         // name length, kind, mode, raw object ID; excludes name
	maxIndexBytes    = 3 + indexEntryBytes + 4096 // one maximum-length name
)

type namedNode struct {
	name  string
	value *node
}

// childIndex is both the persistent in-memory directory index and an on-disk
// page. A SHA-256(name) radix trie gives a canonical shape independent of edit
// order. Only a bounded leaf and its radix ancestors are copied on mutation.
// Branch pages use 16 slots. Leaves are sorted by name. id is memoized under r.mu.
type childIndex struct {
	entries      []namedNode
	slots        *[16]*childIndex
	size, weight int // entry count and total encoded entry bytes (without header)
	id           ID
}

func count(n *childIndex) int {
	if n == nil {
		return 0
	}
	return n.size
}
func weight(n *childIndex) int {
	if n == nil {
		return 0
	}
	return n.weight
}
func fitsLeaf(size, weight int) bool {
	return size <= indexLeafEntries && (size <= 1 || weight+3 <= indexTargetBytes)
}
func hashSlot(hash [32]byte, depth int) byte {
	if depth%2 == 0 {
		return hash[depth/2] >> 4
	}
	return hash[depth/2] & 15
}
func leaf(entries []namedNode) *childIndex {
	if len(entries) == 0 {
		return nil
	}
	n := &childIndex{entries: entries, size: len(entries)}
	for _, e := range entries {
		n.weight += indexEntryBytes + len(e.name)
	}
	return n
}
func lookup(n *childIndex, name string) *node {
	hash := sha256.Sum256([]byte(name))
	for depth := 0; n != nil; depth++ {
		if n.slots != nil {
			n = n.slots[hashSlot(hash, depth)]
			continue
		}
		i := sort.Search(len(n.entries), func(i int) bool { return n.entries[i].name >= name })
		if i < len(n.entries) && n.entries[i].name == name {
			return n.entries[i].value
		}
		break
	}
	return nil
}
func setChild(n *childIndex, name string, value *node) *childIndex {
	return setIndex(n, name, value, sha256.Sum256([]byte(name)), 0)
}
func setIndex(n *childIndex, name string, value *node, hash [32]byte, depth int) *childIndex {
	if n == nil {
		if value == nil {
			return nil
		}
		return leaf([]namedNode{{name, value}})
	}
	if n.slots != nil {
		slot := hashSlot(hash, depth)
		old := n.slots[slot]
		next := setIndex(old, name, value, hash, depth+1)
		if next == old {
			return n
		}
		slots := *n.slots
		slots[slot] = next
		out := &childIndex{slots: &slots, size: n.size - count(old) + count(next), weight: n.weight - weight(old) + weight(next)}
		if fitsLeaf(out.size, out.weight) {
			return leaf(sortedEntries(out))
		}
		return out
	}
	i := sort.Search(len(n.entries), func(i int) bool { return n.entries[i].name >= name })
	found := i < len(n.entries) && n.entries[i].name == name
	if !found && value == nil {
		return n
	}
	if found && n.entries[i].value == value {
		return n
	}
	entries := make([]namedNode, 0, len(n.entries)+1)
	entries = append(entries, n.entries[:i]...)
	if value != nil {
		entries = append(entries, namedNode{name, value})
	}
	if found {
		i++
	}
	entries = append(entries, n.entries[i:]...)
	return partition(entries, depth)
}

// partition receives sorted entries. Filtering preserves order within buckets.
func partition(entries []namedNode, depth int) *childIndex {
	n := leaf(entries)
	if n == nil || fitsLeaf(n.size, n.weight) || depth == 64 {
		return n
	}
	var buckets [16][]namedNode
	for _, e := range entries {
		slot := hashSlot(sha256.Sum256([]byte(e.name)), depth)
		buckets[slot] = append(buckets[slot], e)
	}
	n.entries = nil
	n.slots = new([16]*childIndex)
	for i := range buckets {
		n.slots[i] = partition(buckets[i], depth+1)
	}
	return n
}
func collectEntries(n *childIndex, out *[]namedNode) {
	if n == nil {
		return
	}
	if n.slots == nil {
		*out = append(*out, n.entries...)
		return
	}
	for _, c := range n.slots {
		collectEntries(c, out)
	}
}
func sortedEntries(n *childIndex) []namedNode {
	entries := make([]namedNode, 0, count(n))
	collectEntries(n, &entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries
}
func eachChild(n *childIndex, visit func(string, *node) error) error {
	if n == nil {
		return nil
	}
	entries := n.entries
	if n.slots != nil {
		entries = sortedEntries(n)
	}
	for _, e := range entries {
		if err := visit(e.name, e.value); err != nil {
			return err
		}
	}
	return nil
}

// Index payloads are binary: tag:u8, count/bitmap:u16 big endian, then entries
// or raw 32-byte page IDs. File/directory descriptors remain JSON in v2.
func appendRawID(data []byte, id ID) ([]byte, error) {
	if len(id) != 64 {
		return nil, errors.New("invalid index object ID")
	}
	start := len(data)
	data = append(data, make([]byte, 32)...)
	if _, err := hex.Decode(data[start:], []byte(id)); err != nil {
		return nil, err
	}
	return data, nil
}
func (r *Repository) saveIndex(n *childIndex, base string, depth int) (ID, error) {
	if n == nil {
		return "", nil
	}
	if n.id != "" {
		return n.id, nil
	}
	var data []byte
	var err error
	if n.slots == nil {
		if !fitsLeaf(n.size, n.weight) {
			return "", errors.New("directory hash collision exceeds leaf capacity")
		}
		data = make([]byte, 0, n.weight+3)
		data = append(data, 0)
		data = binary.BigEndian.AppendUint16(data, uint16(n.size))
		for _, e := range n.entries {
			id, err := r.saveNodeAt(e.value, path.Join(base, e.name), depth+1)
			if err != nil {
				return "", err
			}
			data = binary.BigEndian.AppendUint16(data, uint16(len(e.name)))
			data = append(data, e.name...)
			var kind byte
			switch e.value.entry.Kind {
			case "file":
				kind = 1
			case "dir":
				kind = 2
			case "symlink":
				kind = 3
			case "gitlink":
				kind = 4
			default:
				return "", errors.New("invalid index entry kind")
			}
			data = append(data, kind)
			data = binary.BigEndian.AppendUint16(data, uint16(e.value.entry.Mode))
			data, err = appendRawID(data, id)
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
		data = make([]byte, 0, 3+32*bits.OnesCount16(bitmap))
		data = append(data, 1)
		data = binary.BigEndian.AppendUint16(data, bitmap)
		for _, c := range n.slots {
			if c == nil {
				continue
			}
			id, err := r.saveIndex(c, base, depth)
			if err != nil {
				return "", err
			}
			data, err = appendRawID(data, id)
			if err != nil {
				return "", err
			}
		}
	}
	id, err := r.append(indexKind, data)
	if err == nil {
		n.id = id
	}
	return id, err
}

func (r *Repository) earlier(child, parent ID) bool {
	return r.earlierKey(key(child), key(parent))
}
func (r *Repository) earlierKey(child, parent objectKey) bool {
	c, cok := r.lookupObject(child)
	p, pok := r.lookupObject(parent)
	return cok && pok && c.offset < p.offset
}

// loadIndex validates lengths, canonical partitioning, sorted unique names,
// graph ordering, and leaf bounds before installing any shared page.
func (r *Repository) loadIndex(id ID, depth int, prefix [32]byte, loadChild func(child) (*node, error)) (*childIndex, error) {
	loc, ok := r.lookupObject(key(id))
	if !ok || loc.kind != indexKind || loc.size > maxIndexBytes {
		return nil, errors.New("invalid directory index record")
	}
	data, err := r.get(id, indexKind)
	if err != nil {
		return nil, err
	}
	if len(data) < 3 {
		return nil, errors.New("truncated directory index")
	}
	tag, field := data[0], binary.BigEndian.Uint16(data[1:3])
	data = data[3:]
	n := &childIndex{id: id}
	switch tag {
	case 0:
		if field == 0 || field > indexLeafEntries {
			return nil, errors.New("invalid directory leaf count")
		}
		previous := ""
		for i := 0; i < int(field); i++ {
			if len(data) < 2 {
				return nil, errors.New("truncated directory name")
			}
			length := int(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
			if length == 0 || len(data) < length+35 {
				return nil, errors.New("invalid directory name length")
			}
			name := string(data[:length])
			data = data[length:]
			if name <= previous {
				return nil, errors.New("unsorted or duplicate directory name")
			}
			previous = name
			hash := sha256.Sum256([]byte(name))
			for d := 0; d < depth; d++ {
				if hashSlot(hash, d) != hashSlot(prefix, d) {
					return nil, errors.New("mispartitioned directory entry")
				}
			}
			var kind string
			switch data[0] {
			case 1:
				kind = "file"
			case 2:
				kind = "dir"
			case 3:
				kind = "symlink"
			case 4:
				kind = "gitlink"
			default:
				return nil, errors.New("invalid directory entry kind")
			}
			mode := uint32(binary.BigEndian.Uint16(data[1:3]))
			childID := ID(hex.EncodeToString(data[3:35]))
			data = data[35:]
			if r.fast == nil && !r.earlier(childID, id) {
				return nil, errors.New("directory entry must reference an earlier object")
			}
			v, err := loadChild(child{parent: id, Name: name, Kind: kind, Mode: mode, ID: childID})
			if err != nil {
				return nil, err
			}
			n.entries = append(n.entries, namedNode{name, v})
			n.size++
			n.weight += indexEntryBytes + length
		}
		if len(data) != 0 || !fitsLeaf(n.size, n.weight) {
			return nil, errors.New("invalid directory leaf bounds")
		}
	case 1:
		if depth >= 64 || field == 0 || len(data) != 32*bits.OnesCount16(field) {
			return nil, errors.New("invalid directory branch")
		}
		n.slots = new([16]*childIndex)
		for i := 0; i < 16; i++ {
			if field&(1<<i) == 0 {
				continue
			}
			childID := ID(hex.EncodeToString(data[:32]))
			data = data[32:]
			if !r.earlier(childID, id) {
				return nil, errors.New("directory branch must reference an earlier page")
			}
			next := prefix
			if depth%2 == 0 {
				next[depth/2] = byte(i << 4)
			} else {
				next[depth/2] |= byte(i)
			}
			c, err := r.loadIndex(childID, depth+1, next, loadChild)
			if err != nil {
				return nil, err
			}
			n.slots[i] = c
			n.size += c.size
			n.weight += c.weight
		}
		if fitsLeaf(n.size, n.weight) {
			return nil, errors.New("noncanonical directory branch: must be a leaf")
		}
	default:
		return nil, fmt.Errorf("unknown directory page tag %d", tag)
	}
	return n, nil
}
