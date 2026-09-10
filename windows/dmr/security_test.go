package dmr

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// Independent layout vector: flag 1, package S-1-15-2-1, capability S-1-15-3-1.
// This checks the serializer contract, not package SID derivation/registration.
const securityGolden = "5345435534000000010000001000010010000000" +
	"010200000000000f0200000001000000" +
	"010200000000000f0300000001000000"

func securityFixture(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(securityGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSecurityGolden(t *testing.T) {
	b := securityFixture(t)
	context := SecurityContext{Flags: 1, PackageSID: b[20:36], Capabilities: [][]byte{b[36:]}}
	encoded, err := EncodeSecurityContext(context)
	if err != nil || !bytes.Equal(encoded, b) {
		t.Fatalf("encoded %x: %v", encoded, err)
	}
	parsed, err := ParseSecurityContext(b)
	if err != nil || !reflect.DeepEqual(parsed, context) {
		t.Fatalf("parsed %#v: %v", parsed, err)
	}
	container, err := EncodeContainer([]Section{{SecurityTag, encoded}})
	if err != nil {
		t.Fatal(err)
	}
	sections, err := ParseContainer(container)
	if err != nil || len(sections) != 1 || !bytes.Equal(sections[0].Data, b) {
		t.Fatalf("container: %v", err)
	}
}

func TestSecurityMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"magic", 0, 0}, {"size", 4, 48}, {"package_size", 12, 12},
		{"count", 14, 0}, {"too_many", 14, 129}, {"cap_extent", 16, 12},
		{"reserved", 18, 1}, {"package_revision", 20, 2},
		{"package_subauth", 21, 3}, {"cap_revision", 36, 0}, {"cap_subauth", 37, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := securityFixture(t)
			b[tc.offset] = tc.value
			if _, err := ParseSecurityContext(b); err == nil {
				t.Fatal("accepted malformed SECU")
			}
		})
	}
	b := securityFixture(t)
	for i := 0; i < len(b); i++ {
		if _, err := ParseSecurityContext(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}

func TestSecurityLimits(t *testing.T) {
	maximumSID := make([]byte, 68)
	maximumSID[0], maximumSID[1] = 1, 15
	context := SecurityContext{PackageSID: maximumSID, Capabilities: make([][]byte, 128)}
	for i := range context.Capabilities {
		context.Capabilities[i] = maximumSID
	}
	b, err := EncodeSecurityContext(context)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSecurityContext(b); err != nil {
		t.Fatal(err)
	}
	context.Capabilities = append(context.Capabilities, maximumSID)
	if _, err := EncodeSecurityContext(context); err == nil {
		t.Fatal("accepted 129 capabilities")
	}
	context.Capabilities = nil
	b, err = EncodeSecurityContext(context)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSecurityContext(b)
	if err != nil || len(parsed.Capabilities) != 0 {
		t.Fatalf("empty capability list: %v", err)
	}
	context.PackageSID = append(maximumSID, 0)
	if _, err := EncodeSecurityContext(context); err == nil {
		t.Fatal("accepted trailing package SID byte")
	}
	context.PackageSID = maximumSID
	context.Capabilities = [][]byte{{1}}
	if _, err := EncodeSecurityContext(context); err == nil {
		t.Fatal("accepted truncated capability")
	}
}

func FuzzSecurityContext(f *testing.F) {
	f.Add(securityFixture(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		context, err := ParseSecurityContext(data)
		if err != nil {
			return
		}
		encoded, err := EncodeSecurityContext(context)
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
