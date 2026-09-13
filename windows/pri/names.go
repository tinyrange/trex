package pri

import (
	"fmt"
	"strings"
)

// Names retains a hierarchical-name table and its pools. Raw pools alias the
// immutable input. Item indexes are resource indexes, distinct from node indexes.
type Names struct {
	nodes               []NameNode
	items, scopes       []uint32
	utf16Pool, bytePool []byte
}

// ParseNames parses the old or extended hierarchical-name payload (without a
// section header). Extended selects the 28-byte header instead of 24 bytes;
// flags bit0 independently selects large node/scope/item records.
func ParseNames(data []byte, extended bool) (*Names, error) {
	header := 24
	if extended {
		header = 28
	}
	if len(data) < header {
		return nil, fmt.Errorf("pri: truncated names header")
	}
	size := uint64(le.Uint32(data[20:]))
	if size < uint64(header) || size > uint64(len(data)) {
		return nil, fmt.Errorf("pri: invalid names size")
	}
	nodes, scopes, items := uint64(le.Uint32(data[4:])), uint64(le.Uint32(data[8:])), uint64(le.Uint32(data[12:]))
	large := le.Uint16(data[2:])&1 != 0
	limit := uint64(65535)
	nw, sw, iw := uint64(12), uint64(8), uint64(2)
	if large {
		limit = 0x7fffffff
		nw, sw, iw = 20, 16, 4
	}
	if nodes == 0 || scopes == 0 || scopes > limit || items > limit || scopes+items > limit || nodes < scopes+items {
		return nil, fmt.Errorf("pri: invalid names counts")
	}
	utfBytes := uint64(le.Uint32(data[16:])) * 2
	byteCount := uint64(0)
	if extended {
		byteCount = uint64(le.Uint32(data[24:]))
	}
	needed := uint64(header) + nodes*nw + scopes*sw + items*iw + utfBytes + byteCount
	if needed > size {
		return nil, fmt.Errorf("pri: truncated names tables/pools")
	}
	// All allocations follow input extent checks; counts cannot allocate storage
	// disproportional to the supplied file.
	n := &Names{nodes: make([]NameNode, int(nodes)), scopes: make([]uint32, int(scopes)), items: make([]uint32, int(items))}
	off := uint64(header)
	for i := range n.nodes {
		node, err := ParseNameNode(data[off:off+nw], large)
		if err != nil {
			return nil, err
		}
		n.nodes[i] = node
		off += nw
	}
	readIndex := func(b []byte) uint32 {
		if large {
			return le.Uint32(b)
		}
		return uint32(le.Uint16(b))
	}
	for i := range n.scopes {
		n.scopes[i] = readIndex(data[off:])
		off += sw
	}
	for i := range n.items {
		n.items[i] = readIndex(data[off:])
		off += iw
	}
	n.utf16Pool = data[off : off+utfBytes : off+utfBytes]
	off += utfBytes
	n.bytePool = data[off : off+byteCount : off+byteCount]
	for i, index := range n.scopes {
		if uint64(index) >= nodes || !n.nodes[index].Scope || n.nodes[index].Index != uint32(i) {
			return nil, fmt.Errorf("pri: invalid scope %d ownership", i)
		}
	}
	for i, index := range n.items {
		if uint64(index) >= nodes || n.nodes[index].Scope || n.nodes[index].Index != uint32(i) {
			return nil, fmt.Errorf("pri: invalid item %d ownership", i)
		}
	}
	if n.scopes[0] != 0 || n.nodes[0].Parent != 0 || n.nodes[0].FullLength != 0 || n.nodes[0].SegmentLength != 0 {
		return nil, fmt.Errorf("pri: invalid root scope")
	}
	return n, nil
}

func (n *Names) ItemCount() int { return len(n.items) }

// ItemName returns a resource's full slash-separated name without interpreting
// it as a URI or applying case-insensitive matching. Parent traversal is bounded
// by node count and the strictly decreasing recorded full-name lengths.
func (n *Names) ItemName(index uint32) (string, error) {
	if uint64(index) >= uint64(len(n.items)) {
		return "", fmt.Errorf("pri: item index out of range")
	}
	current := n.items[index]
	parts := []string{}
	for steps := 0; current != 0; steps++ {
		if steps >= len(n.nodes) || uint64(current) >= uint64(len(n.nodes)) {
			return "", fmt.Errorf("pri: invalid name parent chain")
		}
		node := n.nodes[current]
		if uint64(node.Parent) >= uint64(len(n.nodes)) {
			return "", fmt.Errorf("pri: parent out of range")
		}
		parent := n.nodes[node.Parent]
		expected := uint32(parent.FullLength) + uint32(node.SegmentLength)
		if node.Parent != 0 {
			expected++
		}
		if !parent.Scope || node.SegmentLength == 0 || uint32(node.FullLength) != expected || parent.FullLength >= node.FullLength {
			return "", fmt.Errorf("pri: inconsistent name parent/length")
		}
		segment, err := node.Segment(n.utf16Pool, n.bytePool)
		if err != nil {
			return "", err
		}
		parts = append(parts, segment)
		current = node.Parent
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/"), nil
}
