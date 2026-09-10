package dmr

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// Independent vector: index 2, one 15-byte record with a binary payload and
// one alignment byte. The payload contains an embedded NUL and odd byte count.
const resourceGolden = "52455350200000000200010000000000" + "0f00000001000200030000004100ff00"

func resourceFixture(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(resourceGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestResourcesGolden(t *testing.T) {
	r := Resources{Index: 2, Entries: []NamedResource{{Value4: 1, Value6: 2, Data: []byte{0x41, 0, 0xff}}}}
	for _, application := range []bool{false, true} {
		r.Application = application
		want := resourceFixture(t)
		if application {
			le.PutUint32(want, ApplicationResourcesTag)
		}
		got, err := EncodeResources(r)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encoded %x: %v", got, err)
		}
		parsed, err := ParseResources(want)
		if err != nil || !reflect.DeepEqual(parsed, r) {
			t.Fatalf("parsed %#v: %v", parsed, err)
		}
		if cap(parsed.Entries[0].Data) != len(parsed.Entries[0].Data) {
			t.Fatal("payload capacity crosses record")
		}
	}
}

func TestResourcesMalformed(t *testing.T) {
	for _, tc := range []struct {
		offset int
		value  uint32
	}{
		{0, 0}, {4, 28}, {8, 0}, {8, 0x04010000}, {8, 0x00010281},
		{12, 1}, {16, 0xffffffff}, {16, 12}, {24, 4}, {24, 0x00010003}, {28, 0x01ff0041},
	} {
		b := resourceFixture(t)
		le.PutUint32(b[tc.offset:], tc.value)
		if _, err := ParseResources(b); err == nil {
			t.Fatalf("accepted mutation %d/%x", tc.offset, tc.value)
		}
	}
	b := resourceFixture(t)
	for i := range b {
		if _, err := ParseResources(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}

func TestResourcesLimits(t *testing.T) {
	r := Resources{Index: 640, Entries: make([]NamedResource, maxResources)}
	r.Entries[0].Data = make([]byte, 65535)
	b, err := EncodeResources(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseResources(b)
	if err != nil || len(parsed.Entries) != maxResources {
		t.Fatalf("maximum count: %v", err)
	}
	for _, invalid := range []Resources{{}, {Index: 641, Entries: r.Entries}, {Entries: append(r.Entries, NamedResource{})}, {Entries: []NamedResource{{Data: make([]byte, 65536)}}}} {
		if _, err := EncodeResources(invalid); err == nil {
			t.Fatal("accepted invalid resources")
		}
	}
}

func FuzzResources(f *testing.F) {
	f.Add(resourceFixture(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseResources(data)
		if err != nil {
			return
		}
		b, err := EncodeResources(r)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
