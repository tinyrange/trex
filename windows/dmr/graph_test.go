package dmr

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// Independent graph layout vector: 104 bytes, one node of actual size 86,
// 38-byte identity, two alignment bytes before properties at node offset 48,
// 38-byte properties and two final node-alignment bytes.
const graphGolden = "44455047680000000000000001000000" +
	"5600000000003000" +
	"2600000000000000000000000000000009000000060000000000000000000000" +
	"4100420000000000" +
	"2600000000000000010000000000000002000000000000000600000000000000" +
	"4300440000000000"

func graphFixture(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(graphGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGraphGolden(t *testing.T) {
	nodes := []Node{{Identity: Identity{Name: "AB", Architecture: 9}, Properties: &NodeProperties{Value8: 1, Value16: 2, Strings: [4]string{"CD"}}}}
	want := graphFixture(t)
	got, err := EncodeGraph(nodes)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoded %x, want %x: %v", got, want, err)
	}
	parsed, err := ParseGraph(want)
	if err != nil || !reflect.DeepEqual(parsed, nodes) {
		t.Fatalf("parsed %#v: %v", parsed, err)
	}
}

func TestGraphOrderedNodes(t *testing.T) {
	first := Node{Identity: Identity{Name: "Root", FullName: "Root_1.0.0.0_x64__publisher"}, InstallationPath: `C:\Windows\SystemApps\Root`}
	second := Node{Identity: Identity{Name: "Framework", ResourceID: "res"}, Properties: &NodeProperties{Strings: [4]string{"Name", "Publisher", "説明😀", "Logo"}}}
	nodes := []Node{first, second, first}
	b, err := EncodeGraph(nodes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseGraph(b)
	if err != nil || !reflect.DeepEqual(nodes, got) {
		t.Fatalf("ordered round trip: %v", err)
	}
	container, err := EncodeContainer([]Section{{GraphTag, b}})
	if err != nil {
		t.Fatal(err)
	}
	sections, err := ParseContainer(container)
	if err != nil || !bytes.Equal(sections[0].Data, b) {
		t.Fatalf("container: %v", err)
	}
}

func TestGraphMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"magic", 0, 0}, {"size", 4, 100}, {"reserved", 8, 1}, {"count", 12, 0},
		{"missing_node", 12, 2}, {"count_overflow", 12, 0xffffffff},
		{"node_size", 16, 84}, {"node_overflow", 16, 0xffffffff},
		{"identity_overflow", 24, 0xffffffff}, {"identity_short", 24, 28},
		{"property_offset_in_identity", 20, 0x00200000},
		{"property_offset_past_end", 20, 0xfffc0000},
		{"missing_properties", 20, 0}, {"property_size", 64, 36},
		{"property_reserved", 68, 1}, {"property_string_size", 88, 8},
		{"empty_first_property", 88, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := graphFixture(t)
			le.PutUint32(b[tc.offset:], tc.value)
			if _, err := ParseGraph(b); err == nil {
				t.Fatal("accepted malformed graph")
			}
		})
	}
	for _, offset := range []int{62, 102} {
		b := graphFixture(t)
		b[offset] = 1
		if _, err := ParseGraph(b); err == nil {
			t.Fatalf("accepted nonzero padding %d", offset)
		}
	}
	b := graphFixture(t)
	for i := range b {
		if _, err := ParseGraph(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}

func TestGraphEncodingLimits(t *testing.T) {
	if _, err := EncodeGraph(nil); err == nil {
		t.Fatal("accepted empty graph")
	}
	nodes := make([]Node, maxNodes)
	for i := range nodes {
		nodes[i].Identity.Name = "A"
	}
	b, err := EncodeGraph(nodes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseGraph(b)
	if err != nil || len(got) != maxNodes {
		t.Fatalf("maximum count: %v", err)
	}
	if _, err := EncodeGraph(append(nodes, nodes[0])); err == nil {
		t.Fatal("accepted excess nodes")
	}
	node := Node{Identity: Identity{Name: "A"}, Properties: &NodeProperties{}}
	if _, err := EncodeGraph([]Node{node}); err == nil {
		t.Fatal("accepted empty properties")
	}
	node.Properties.Strings[0] = "P"
	node.InstallationPath = strings.Repeat("a", 32766)
	if _, err := EncodeGraph([]Node{node}); err == nil {
		t.Fatal("accepted property offset overflow")
	}
	node.Properties = nil
	if _, err := EncodeGraph([]Node{node}); err != nil {
		t.Fatalf("long path without properties: %v", err)
	}
}

func FuzzGraph(f *testing.F) {
	f.Add(graphFixture(f))
	minimal, err := EncodeGraph([]Node{{Identity: Identity{Name: "A"}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(minimal)
	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := ParseGraph(data)
		if err != nil {
			return
		}
		b, err := EncodeGraph(nodes)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("round trip mismatch: %v", err)
		}
	})
}
