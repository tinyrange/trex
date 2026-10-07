package plist

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Explicit object bytes exercise the external format rather than our encoder.
func fixture(objects ...string) []byte {
	raw := []byte("bplist00")
	offsets := []byte{}
	for _, object := range objects {
		offsets = append(offsets, byte(len(raw)))
		data, e := hex.DecodeString(object)
		if e != nil {
			panic(e)
		}
		raw = append(raw, data...)
	}
	table := len(raw)
	raw = append(raw, offsets...)
	trailer := make([]byte, 32)
	trailer[6] = 1
	trailer[7] = 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	return append(raw, trailer...)
}
func TestBinaryTypedValues(t *testing.T) {
	// {user:[501,true,"😀",<0001ff>,-1,1.5,2001-01-01T00:00:00Z]}
	raw := fixture("d10102", "5475736572", "a703040506070809", "1101f5", "09", "62d83dde00", "430001ff", "13ffffffffffffffff", "233ff8000000000000", "330000000000000000")
	got, e := Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	want := map[string]any{"user": []any{int64(501), true, "😀", []byte{0, 1, 255}, int64(-1), 1.5, Date{time.Unix(978307200, 0).UTC()}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
	xml, e := EncodeXML(got)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Decode(xml)
	if e != nil || !reflect.DeepEqual(again, want) {
		t.Fatalf("roundtrip %#v %v", again, e)
	}
}
func TestXMLSemantics(t *testing.T) {
	raw := `<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>a&amp;b</key><array><string>&lt;x&gt;</string><integer>08</integer><data> AA H/ </data><false/></array></dict></plist>`
	got, e := Decode([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	want := map[string]any{"a&b": []any{"<x>", int64(8), []byte{0, 1, 255}, false}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v", got)
	}
	encoded, e := EncodeXML(want)
	if e != nil {
		t.Fatal(e)
	}
	got, e = Decode(encoded)
	if e != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v %v", got, e)
	}
}
func TestRejectMalformedGraphAndXML(t *testing.T) {
	cases := [][]byte{
		fixture("a100"),                     // self-cycle
		fixture("d201010202", "516b", "09"), // duplicate keys
		fixture("d10102", "1001", "09"),     // non-string key
		fixture("a1ff"),                     // invalid ref
		fixture("4f13ffffffffffffffff"),     // overflowing extended length
		fixture("51ff"),                     // marker5 must be ASCII
		fixture("61d800"),                   // unpaired surrogate
		fixture("80ff"),                     // UID is not a plist1.0 scalar
		[]byte(`<plist><dict><key>a</key><true/><key>a</key><false/></dict></plist>`),
		[]byte(`<plist><dict><key>a</key></dict></plist>`),
		[]byte(`<plist><true/><false/></plist>`),
		[]byte(`<plist><string>x<true/></string></plist>`),
		[]byte(`<plist><real>NaN</real></plist>`),
		[]byte(`<plist><true>yes</true></plist>`),
		[]byte(`<plist><data>!</data></plist>`),
		[]byte(`<plist><array>` + strings.Repeat(`<array>`, 129) + strings.Repeat(`</array>`, 129) + `</array></plist>`),
	}
	for i, raw := range cases {
		if _, e := Decode(raw); e == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, v := range []any{math.NaN(), math.Inf(1), "\x00", nil} {
		if _, e := EncodeXML(v); e == nil {
			t.Errorf("accepted %v", v)
		}
	}
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if _, e := EncodeXML(cyclic); e == nil {
		t.Fatal("encoded cycle")
	}
}
func TestRejectBadOffsetsAndExpansion(t *testing.T) {
	raw := fixture("09")
	binary.BigEndian.PutUint64(raw[len(raw)-24:], math.MaxUint64)
	if _, e := Decode(raw); e == nil {
		t.Fatal("accepted object count")
	}
	raw = fixture("09")
	raw[9] = 1
	if _, e := Decode(raw); e == nil {
		t.Fatal("accepted header object offset")
	}
	raw = fixture("a101", "09")
	raw[9] = 2
	if _, e := Decode(raw); e == nil {
		t.Fatal("accepted invalid reference")
	}
	// An acyclic doubling DAG must not expand exponentially without a bound.
	objects := []string{}
	for i := 0; i < 19; i++ {
		objects = append(objects, "a2"+hex.EncodeToString([]byte{byte(i + 1), byte(i + 1)}))
	}
	objects = append(objects, "09")
	if _, e := Decode(fixture(objects...)); e == nil {
		t.Fatal("accepted exponential DAG")
	}
}
func FuzzDecode(f *testing.F) {
	f.Add(fixture("09"))
	f.Add([]byte(`<plist><dict/></plist>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		v, e := Decode(raw)
		if e == nil {
			encoded, e := EncodeXML(v)
			if e == nil {
				if _, e = Decode(encoded); e != nil {
					t.Fatal(e)
				}
			}
		}
	})
}

func TestAllocationBudgetsAndDateEpoch(t *testing.T) {
	// UTF16 U+0800 expands two encoded bytes into three decoded UTF8 bytes.
	raw := []byte{0x61, 0x08, 0x00}
	p := binaryParser{raw: raw, offsets: []uint64{0}, end: 3, active: map[uint64]bool{}, budget: budget{bytes: MaxBytes - 2}}
	if _, err := p.value(0, 0); err == nil {
		t.Fatal("UTF16 expansion bypassed decoded byte budget")
	}
	p = binaryParser{raw: []byte{0xa2, 0, 0}, offsets: []uint64{0}, end: 3, refSize: 1, active: map[uint64]bool{}, budget: budget{nodes: maxNodes - 1}}
	if _, err := p.value(0, 0); err == nil {
		t.Fatal("container bypassed remaining node budget")
	}
	for _, seconds := range []float64{-63113904000, 252423993599} {
		encoded := make([]byte, 9)
		encoded[0] = 0x33
		binary.BigEndian.PutUint64(encoded[1:], math.Float64bits(seconds))
		got, err := Decode(fixture(hex.EncodeToString(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		year := got.(Date).Year()
		if year != 1 && year != 9999 {
			t.Fatalf("wrong CF epoch year: %d", year)
		}
		xml, err := EncodeXML(got)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(xml); err != nil {
			t.Fatal(err)
		}
	}
	for _, seconds := range []float64{-63113904001, 252423993600} {
		encoded := make([]byte, 9)
		encoded[0] = 0x33
		binary.BigEndian.PutUint64(encoded[1:], math.Float64bits(seconds))
		if _, err := Decode(fixture(hex.EncodeToString(encoded))); err == nil {
			t.Fatal("accepted date outside XML representable range")
		}
	}
}
