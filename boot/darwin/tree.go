package darwin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

// DecodeNode reads Apple's flattened device tree with the same bounded layout
// as Node.Encode. It does not interpret platform-specific property values.
func DecodeNode(r storage.Reader) (Node, error) {
	if r.Size() < 8 || r.Size() > 1<<20 {
		return Node{}, fmt.Errorf("darwin: device tree size outside bounds")
	}
	b := make([]byte, r.Size())
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, r.Size()), b); err != nil {
		return Node{}, err
	}
	position, nodes := 0, 0
	var visit func(int) (Node, error)
	visit = func(depth int) (Node, error) {
		if depth > 32 || nodes >= 4096 || position > len(b)-8 {
			return Node{}, fmt.Errorf("darwin: device tree node bounds")
		}
		nodes++
		properties, children := binary.LittleEndian.Uint32(b[position:]), binary.LittleEndian.Uint32(b[position+4:])
		position += 8
		if properties > 1024 || children > 1024 {
			return Node{}, fmt.Errorf("darwin: device tree count bounds")
		}
		n := Node{Properties: make(map[string][]byte), PropertyFlags: make(map[string]uint32)}
		for i := uint32(0); i < properties; i++ {
			if position > len(b)-36 {
				return Node{}, fmt.Errorf("darwin: truncated device tree property")
			}
			name := b[position : position+32]
			end := bytes.IndexByte(name, 0)
			if end < 1 {
				return Node{}, fmt.Errorf("darwin: invalid device tree property name")
			}
			key := string(name[:end])
			if _, ok := n.Properties[key]; ok {
				return Node{}, fmt.Errorf("darwin: duplicate device tree property %q", key)
			}
			length := uint64(binary.LittleEndian.Uint32(b[position+32:]))
			if length&0x80000000 != 0 {
				n.PropertyFlags[key] = 0x80000000
				length &^= 0x80000000
			}
			position += 36
			padded := (length + 3) &^ uint64(3)
			if padded > uint64(len(b)-position) {
				return Node{}, fmt.Errorf("darwin: device tree property exceeds input")
			}
			n.Properties[key] = append([]byte(nil), b[position:position+int(length)]...)
			position += int(padded)
		}
		for i := uint32(0); i < children; i++ {
			child, err := visit(depth + 1)
			if err != nil {
				return Node{}, err
			}
			n.Children = append(n.Children, child)
		}
		return n, nil
	}
	n, err := visit(0)
	if err == nil && position != len(b) {
		err = fmt.Errorf("darwin: trailing device tree data")
	}
	return n, err
}
