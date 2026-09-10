package srdictionary

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestStringWireLayout(t *testing.T) {
	// Independent layout from the matched 26100 SRClient reader/writer:
	// SRD1, extent34, count1; pair22/type14/key4/A-NUL/value4/B-NUL.
	want, err := hex.DecodeString("535244312200000001000000160000000e0000000400410000000400000042000000")
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeStrings([]StringPair{{"A", "B"}})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("wire = %x, %v", got, err)
	}
	decoded, err := DecodeStrings(want)
	if err != nil || !reflect.DeepEqual(decoded, []StringPair{{"A", "B"}}) {
		t.Fatalf("decode = %#v, %v", decoded, err)
	}
}

func TestStringRoundTrip(t *testing.T) {
	for _, pairs := range [][]StringPair{
		{}, {{"", ""}}, {{"LaunchPolicy", "1"}, {"ProcessPath", `%SYSTEMROOT%\system32\shellhost.exe`}},
		{{"astral😀", "text𐐷"}, {"a", "lower"}, {"A", "upper"}},
	} {
		encoded, err := EncodeStrings(pairs)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeStrings(encoded)
		if err != nil || !reflect.DeepEqual(decoded, pairs) {
			t.Fatalf("round trip %#v: %#v, %v", pairs, decoded, err)
		}
	}
}

func TestStringInvalidInput(t *testing.T) {
	for _, pairs := range [][]StringPair{
		{{"same", "a"}, {"same", "b"}}, {{"bad\x00key", "value"}}, {{"key", "bad\x00value"}},
		{{"\xff", "value"}}, {{strings.Repeat("x", maxKeyBytes/2), "value"}},
		{{"key", strings.Repeat("x", maxValueBytes/2)}}, make([]StringPair, maxPairs+1),
	} {
		if _, err := EncodeStrings(pairs); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}

func TestStringMalformedWire(t *testing.T) {
	good, _ := EncodeStrings([]StringPair{{"A", "B"}})
	for n := range len(good) {
		if _, err := DecodeStrings(good[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"magic":            func(b []byte) { b[0] ^= 1 },
		"total":            func(b []byte) { b[4]++ },
		"count":            func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 1025) },
		"zero-count":       func(b []byte) { b[8] = 0 },
		"pair-size":        func(b []byte) { b[12] = 0xff },
		"type":             func(b []byte) { b[16] = 15 },
		"key-size":         func(b []byte) { b[20] = 0xff },
		"key-terminator":   func(b []byte) { b[24] = 1 },
		"key-surrogate":    func(b []byte) { b[23] = 0xd8 },
		"value-size":       func(b []byte) { b[26]++ },
		"value-terminator": func(b []byte) { b[32] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(good)
			mutate(b)
			if _, err := DecodeStrings(b); err == nil {
				t.Fatal("accepted malformed wire")
			}
		})
	}
	duplicate := append(bytes.Clone(good), good[12:]...)
	binary.LittleEndian.PutUint32(duplicate[4:], uint32(len(duplicate)))
	binary.LittleEndian.PutUint32(duplicate[8:], 2)
	if _, err := DecodeStrings(duplicate); err == nil {
		t.Fatal("accepted duplicate wire key")
	}
}

func FuzzDecodeStrings(f *testing.F) {
	seed, _ := EncodeStrings([]StringPair{{"LaunchPolicy", "1"}})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		pairs, err := DecodeStrings(data)
		if err != nil {
			return
		}
		encoded, err := EncodeStrings(pairs)
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatalf("noncanonical accepted dictionary: %v", err)
		}
	})
}
