package pri

import (
	"encoding/hex"
	"testing"
)

// One table entry and a forty-byte opaque section. Payload semantics are not
// asserted by this envelope fixture.
func containerFixture(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(
		"6d726d5f70726932000001007800000020000000400000000100ffff00000000" +
			"5b6d726d5f6465636e5f696e666f5d0000000000000000000000000028000000" +
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000" +
			"defaffde780000006d726d5f70726932")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContainer(t *testing.T) {
	b := containerFixture(t)
	c, err := ParseContainer(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Sections) != 1 || len(c.Sections[0].Data) != 40 || c.Header26 != 65535 {
		t.Fatalf("unexpected container: %+v", c)
	}
	if cap(c.Sections[0].Data) != 40 {
		t.Fatal("uncapped section")
	}
	b[64] = 42
	if c.Sections[0].Data[0] != 42 {
		t.Fatal("payload copied")
	}
	// Absent table entries are permitted by the native envelope validator.
	le.PutUint32(b[60:], 0)
	c, err = ParseContainer(b)
	if err != nil || c.Sections[0].Data != nil {
		t.Fatalf("absent entry: %v", err)
	}
}

func TestContainerMalformed(t *testing.T) {
	b := containerFixture(t)
	for n := range b {
		if _, err := ParseContainer(b[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	for _, tc := range []struct {
		offset int
		value  uint32
	}{
		{0, 0}, {12, 47}, {12, 0xffffffff}, {16, 24}, {16, 33}, {16, 0xfffffff8},
		{20, 56}, {20, 65}, {20, 104}, {24, 0x8000},
		{56, 1}, {56, 0xffffffff}, {60, 39}, {60, 0xffffffff},
		{104, 0}, {108, 0}, {112, 0},
	} {
		bad := containerFixture(t)
		le.PutUint32(bad[tc.offset:], tc.value)
		if _, err := ParseContainer(bad); err == nil {
			t.Fatalf("accepted mutation %d/%x", tc.offset, tc.value)
		}
	}
}

func FuzzContainer(f *testing.F) {
	f.Add(containerFixture(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseContainer(data)
		if err != nil {
			return
		}
		for _, s := range c.Sections {
			if len(s.Data) != cap(s.Data) {
				t.Fatal("uncapped section")
			}
		}
	})
}
