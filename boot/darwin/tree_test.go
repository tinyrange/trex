package darwin

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type treeSource struct{ *bytes.Reader }

func (s treeSource) Size() int64 { return s.Reader.Size() }
func TestTemplateTreeRoundTripAndBounds(t *testing.T) {
	n := Node{Properties: map[string][]byte{"name": CString("/"), "model": CString("syscfg/Model")}, PropertyFlags: map[string]uint32{"model": 0x80000000}, Children: []Node{{Properties: map[string][]byte{"reg": U64(0x10010000)}}}}
	b, e := n.Encode()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeNode(treeSource{bytes.NewReader(b)})
	if e != nil {
		t.Fatal(e)
	}
	if decoded.PropertyFlags["model"] != 0x80000000 || !bytes.Equal(decoded.Properties["model"], n.Properties["model"]) || len(decoded.Children) != 1 {
		t.Fatal("lost template flag, value or child")
	}
	again, e := decoded.Encode()
	if e != nil || !bytes.Equal(b, again) {
		t.Fatalf("round trip: %v", e)
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0), make([]byte, 7)} {
		if _, e := DecodeNode(treeSource{bytes.NewReader(bad)}); e == nil {
			t.Fatal("accepted malformed tree")
		}
	}
	bad := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(bad, 0xffffffff)
	if _, e := DecodeNode(treeSource{bytes.NewReader(bad)}); e == nil {
		t.Fatal("unbounded count")
	}
	bad = append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(bad[40:], 0x7fffffff)
	if _, e := DecodeNode(treeSource{bytes.NewReader(bad)}); e == nil {
		t.Fatal("unbounded value")
	}
}
