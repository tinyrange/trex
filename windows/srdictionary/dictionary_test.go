package srdictionary

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestNestedDictionaryWire(t *testing.T) {
	child := Dictionary{{"#text", "1"}}
	input := Dictionary{{"LaunchPolicy", child}, {"Capabilities", []Dictionary{{{"Name", "a"}}, {{"Name", "b"}}}}}
	wire, err := Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(wire[16:]) != 21 {
		t.Fatal("nested map type")
	}
	firstSize := int(binary.LittleEndian.Uint32(wire[12:]))
	second := wire[12+firstSize:]
	if binary.LittleEndian.Uint32(second[4:]) != 42 || binary.LittleEndian.Uint32(second[8:]) != 2 {
		t.Fatal("map array type/count")
	}
	// The producer emits each child as an independent complete SRD1 value.
	keyBytes := int(binary.LittleEndian.Uint16(wire[20:]))
	nested := wire[12+14+keyBytes : 12+firstSize]
	wantChild, _ := EncodeStrings([]StringPair{{"#text", "1"}})
	if !bytes.Equal(nested, wantChild) {
		t.Fatalf("nested payload %x", nested)
	}
	got, err := Decode(wire)
	if err != nil || !reflect.DeepEqual(input, got) {
		t.Fatalf("roundtrip %#v: %v", got, err)
	}
	for n := range len(wire) {
		if _, err := Decode(wire[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}

func TestDictionaryLimitsAndTypes(t *testing.T) {
	for _, input := range []Dictionary{
		{{"bad", 1}}, {{"same", "a"}, {"same", Dictionary{}}},
		{{"maps", make([]Dictionary, maxPairs+1)}},
	} {
		if _, err := Encode(input); err == nil {
			t.Fatal("accepted unsupported type or limit violation")
		}
	}
	deep := Dictionary{{"leaf", "value"}}
	for range maximumDepth {
		deep = Dictionary{{"child", deep}}
	}
	if _, err := Encode(deep); err == nil {
		t.Fatal("accepted excessive nesting")
	}
	for _, d := range []Dictionary{{}, {{"empty map", Dictionary{}}}, {{"empty array", []Dictionary{}}}} {
		wire, err := Encode(d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(wire)
		if err != nil || !reflect.DeepEqual(got, d) {
			t.Fatalf("empty container: %#v %v", got, err)
		}
	}
}

func TestNestedExtentValidation(t *testing.T) {
	good, _ := Encode(Dictionary{{"m", Dictionary{{"k", "v"}}}})
	for _, off := range []int{12, 22 + 4, 30 + 4, 34 + 4} {
		bad := bytes.Clone(good)
		binary.LittleEndian.PutUint32(bad[off:], 0xffffffff)
		if _, err := Decode(bad); err == nil {
			t.Fatalf("accepted invalid nested extent at %d", off)
		}
	}
	array, _ := Encode(Dictionary{{"a", []Dictionary{{{"k", "v"}}}}})
	binary.LittleEndian.PutUint32(array[20:], 0xffffffff)
	if _, err := Decode(array); err == nil {
		t.Fatal("accepted huge array count")
	}
}

func FuzzDecodeDictionary(f *testing.F) {
	seed, _ := Encode(Dictionary{{"LaunchPolicy", Dictionary{{"#text", "1"}}}, {"List", []Dictionary{{{"Name", "test"}}}}})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Decode(data)
		if err != nil {
			return
		}
		encoded, err := Encode(d)
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatalf("noncanonical accepted dictionary: %v", err)
		}
	})
}
