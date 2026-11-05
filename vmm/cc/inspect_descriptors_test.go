package cc

import "testing"

func TestLegacyDescriptor(t *testing.T) {
	d, err := legacyDescriptor([]byte{0xff, 0xff, 0x78, 0x56, 0x34, 0xfa, 0xcf, 0x12}, 0x2c)
	if err != nil || d["base"] != int64(0x12345678) || d["limit"] != int64(0xffffffff) || d["dpl"] != 3 || d["type"] != 10 || d["present"] != true || d["default32"] != true || d["system"] != false {
		t.Fatalf("32-bit page-granular descriptor: %v, %v", d, err)
	}
	d, err = legacyDescriptor([]byte{0x34, 0x12, 0x11, 0x22, 0x33, 0x92, 0, 0x44}, 0x18)
	if err != nil || d["base"] != int64(0x44332211) || d["limit"] != int64(0x1234) || d["default32"] != false {
		t.Fatalf("16-bit byte-granular descriptor: %v, %v", d, err)
	}
	if _, err := legacyDescriptor(make([]byte, 7), 0); err == nil {
		t.Fatal("short descriptor accepted")
	}
	if _, err := legacyDescriptor(make([]byte, 8), 65536); err == nil {
		t.Fatal("overflowing selector accepted")
	}
}

func TestDescriptorRange(t *testing.T) {
	for _, tc := range []struct {
		limit              uint32
		start, count, want int
	}{{65535, 8191, 64, 1}, {65535, 8192, 1, 0}, {23, 1, 64, 2}, {6, 0, 1, 0}} {
		n, err := descriptorRange(tc.limit, tc.start, tc.count)
		if err != nil || n != tc.want {
			t.Fatalf("%+v: %d, %v", tc, n, err)
		}
	}
	for _, tc := range []struct {
		limit        uint32
		start, count int
	}{{23, 4, 1}, {65535, -1, 1}, {65535, 0, 0}, {65535, 0, 257}, {65543, 0, 1}, {0xffffffff, 0, 1}} {
		if _, err := descriptorRange(tc.limit, tc.start, tc.count); err == nil {
			t.Fatalf("invalid range accepted: %+v", tc)
		}
	}
}
