package dmr

import "fmt"

const GraphTag uint32 = 0x47504544 // DEPG
const maxNodes = 641

// NodeProperties preserves the native optional property record. Value8 and
// Value16 are packed OSMinVersion and OSMaxVersionTested respectively. Strings
// are DisplayName, PublisherDisplayName, Description, and Logo, corresponding
// to KernelBase GetPackageProperty selectors 11..14. These are original property
// strings; resolved MRM blobs belong in the separate resource section.
type NodeProperties struct {
	Value8, Value16 uint64
	Strings         [4]string
}

// Node is an ordered package-graph entry. InstallationPath is a Windows guest
// path, never a host path. A nil Properties pointer means the record is absent.
type Node struct {
	Identity         Identity
	InstallationPath string
	Properties       *NodeProperties
}

func align4(n int) int { return (n + 3) &^ 3 }

func encodeNode(node Node) ([]byte, error) {
	id, err := EncodeIdentity(node.Identity)
	if err != nil {
		return nil, err
	}
	path, err := identityString(node.InstallationPath)
	if err != nil {
		return nil, err
	}
	basicSize := 8 + len(id) + len(path)
	size := basicSize
	propertiesOffset := 0
	var fields [4][]byte
	if node.Properties != nil {
		if node.Properties.Strings[0] == "" {
			return nil, fmt.Errorf("dmr: properties require first string")
		}
		propertiesOffset = align4(basicSize)
		if propertiesOffset > 65535 {
			return nil, fmt.Errorf("dmr: properties offset exceeds u16")
		}
		size = propertiesOffset + 32
		for i, value := range node.Properties.Strings {
			fields[i], err = identityString(value)
			if err != nil {
				return nil, err
			}
			size += len(fields[i])
		}
	}
	out := make([]byte, align4(size))
	le.PutUint32(out, uint32(size))
	le.PutUint16(out[4:], uint16(len(path)))
	le.PutUint16(out[6:], uint16(propertiesOffset))
	copy(out[8:], id)
	copy(out[8+len(id):], path)
	if node.Properties != nil {
		p := out[propertiesOffset:]
		le.PutUint32(p, uint32(size-propertiesOffset))
		le.PutUint64(p[8:], node.Properties.Value8)
		le.PutUint64(p[16:], node.Properties.Value16)
		offset := 32
		for i, field := range fields {
			le.PutUint16(p[24+2*i:], uint16(len(field)))
			copy(p[offset:], field)
			offset += len(field)
		}
	}
	return out, nil
}

func zeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func parseNode(data []byte) (Node, error) {
	var node Node
	if len(data) < 40 {
		return node, fmt.Errorf("dmr: short node")
	}
	size := uint64(le.Uint32(data))
	if size < 40 || size > uint64(len(data)) || uint64(align4(int(size))) != uint64(len(data)) || !zeroBytes(data[int(size):]) {
		return node, fmt.Errorf("dmr: invalid node size/padding")
	}
	idSize := uint64(le.Uint32(data[8:]))
	pathSize := uint64(le.Uint16(data[4:]))
	basicEnd := 8 + idSize + pathSize
	if idSize < 32 || basicEnd > size {
		return node, fmt.Errorf("dmr: invalid node identity/path extents")
	}
	id, err := ParseIdentity(data[8 : 8+int(idSize)])
	if err != nil {
		return node, err
	}
	path, err := parseIdentityString(data[8+int(idSize) : int(basicEnd)])
	if err != nil {
		return node, err
	}
	node = Node{Identity: id, InstallationPath: path}
	propertiesOffset := int(le.Uint16(data[6:]))
	if propertiesOffset == 0 {
		if basicEnd != size {
			return Node{}, fmt.Errorf("dmr: trailing node bytes without properties")
		}
		return node, nil
	}
	if propertiesOffset != align4(int(basicEnd)) || uint64(propertiesOffset)+32 > size || !zeroBytes(data[int(basicEnd):propertiesOffset]) {
		return Node{}, fmt.Errorf("dmr: invalid properties offset/padding")
	}
	p := data[propertiesOffset:int(size)]
	if uint64(le.Uint32(p)) != uint64(len(p)) || le.Uint32(p[4:]) != 0 {
		return Node{}, fmt.Errorf("dmr: invalid properties header")
	}
	properties := &NodeProperties{Value8: le.Uint64(p[8:]), Value16: le.Uint64(p[16:])}
	offset := 32
	for i := range properties.Strings {
		n := int(le.Uint16(p[24+2*i:]))
		if n > len(p)-offset {
			return Node{}, fmt.Errorf("dmr: properties string outside extent")
		}
		properties.Strings[i], err = parseIdentityString(p[offset : offset+n])
		if err != nil {
			return Node{}, err
		}
		offset += n
	}
	if offset != len(p) || properties.Strings[0] == "" {
		return Node{}, fmt.Errorf("dmr: invalid properties strings")
	}
	node.Properties = properties
	return node, nil
}

// EncodeGraph serializes an explicitly resolved, ordered graph. It does not
// resolve dependencies or invent a root node. The native format requires 1..641
// entries. Repeated identities/order are preserved, not silently deduplicated.
func EncodeGraph(nodes []Node) ([]byte, error) {
	if len(nodes) == 0 || len(nodes) > maxNodes {
		return nil, fmt.Errorf("dmr: graph requires 1..%d nodes", maxNodes)
	}
	out := make([]byte, 16)
	le.PutUint32(out, GraphTag)
	le.PutUint32(out[12:], uint32(len(nodes)))
	for i, node := range nodes {
		encoded, err := encodeNode(node)
		if err != nil {
			return nil, fmt.Errorf("dmr: node %d: %w", i, err)
		}
		if len(encoded) > maxSize-len(out) {
			return nil, fmt.Errorf("dmr: graph too large")
		}
		out = append(out, encoded...)
	}
	le.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// ParseGraph validates the complete node sequence, including identity, property
// and alignment extents, rather than only the shallow native graph header check.
func ParseGraph(data []byte) ([]Node, error) {
	if len(data) < 16 || len(data) > maxSize || len(data)%4 != 0 || le.Uint32(data) != GraphTag ||
		uint64(le.Uint32(data[4:])) != uint64(len(data)) || le.Uint32(data[8:]) != 0 {
		return nil, fmt.Errorf("dmr: invalid graph header")
	}
	count := le.Uint32(data[12:])
	if count == 0 || count > maxNodes {
		return nil, fmt.Errorf("dmr: invalid graph count")
	}
	nodes := make([]Node, 0, int(count))
	offset := 16
	for i := uint32(0); i < count; i++ {
		if len(data)-offset < 4 {
			return nil, fmt.Errorf("dmr: missing node %d", i)
		}
		size := uint64(le.Uint32(data[offset:]))
		aligned := (size + 3) &^ uint64(3)
		if size < 40 || aligned > uint64(len(data)-offset) {
			return nil, fmt.Errorf("dmr: node %d outside graph", i)
		}
		node, err := parseNode(data[offset : offset+int(aligned)])
		if err != nil {
			return nil, fmt.Errorf("dmr: node %d: %w", i, err)
		}
		nodes = append(nodes, node)
		offset += int(aligned)
	}
	if offset != len(data) {
		return nil, fmt.Errorf("dmr: trailing graph bytes")
	}
	return nodes, nil
}
