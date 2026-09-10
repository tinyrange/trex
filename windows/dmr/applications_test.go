package dmr

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// Independent layout vector: one 46-byte application plus two padding bytes.
// Scalar values exercise wire preservation, not valid registration policy.
const applicationsGolden = "41505053400000000000000001000000" +
	"2e0000000000010204000300000000000000000001000000443322110000010006000000" +
	"410000002b00780000000000"

func applicationFixture(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(applicationsGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestApplicationsGolden(t *testing.T) {
	apps := []Application{{Value6: 1, Value7: 2, Value10: 3, ForegroundText: 1, Value24: 0x11223344,
		Strings: [6]string{"A"}, ContentURIRules: []ContentURIRule{{Include: true, URI: "x"}}}}
	want := applicationFixture(t)
	got, err := EncodeApplications(apps)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoded %x, want %x: %v", got, want, err)
	}
	parsed, err := ParseApplications(want)
	if err != nil || !reflect.DeepEqual(parsed, apps) {
		t.Fatalf("parsed %#v: %v", parsed, err)
	}
	apps = append(apps, Application{Strings: [6]string{"A", "B", "C", "D", "E", "名前😀"}, ContentURIRules: []ContentURIRule{}})
	got, err = EncodeApplications(apps)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseApplications(got)
	if err != nil || !reflect.DeepEqual(parsed, apps) {
		t.Fatalf("multiple applications: %v", err)
	}
}

func TestApplicationsMalformed(t *testing.T) {
	for _, tc := range []struct {
		offset int
		value  uint32
	}{
		{0, 0}, {4, 60}, {8, 1}, {12, 0}, {12, 2}, {12, 101},
		{16, 0xffffffff}, {16, 44}, {20, 1}, {24, 0x00030008},
		{44, 0x00020000}, {48, 0xffffffff}, {52, 0xd800},
		{60, 0x00010000},
	} {
		b := applicationFixture(t)
		le.PutUint32(b[tc.offset:], tc.value)
		if _, err := ParseApplications(b); err == nil {
			t.Fatalf("accepted mutation %d/%x", tc.offset, tc.value)
		}
	}
	b := applicationFixture(t)
	for i := range b {
		if _, err := ParseApplications(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}

func TestApplicationsLimits(t *testing.T) {
	apps := make([]Application, maxApplications)
	for i := range apps {
		apps[i].Strings[0] = "A"
	}
	b, err := EncodeApplications(apps)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseApplications(b)
	if err != nil || len(parsed) != maxApplications {
		t.Fatalf("maximum count: %v", err)
	}
	for _, invalid := range [][]Application{nil, append(apps, apps[0]), {{Strings: [6]string{"a\x00b"}}}, {{ContentURIRules: []ContentURIRule{{RuntimeAccess: 3}}}}} {
		if _, err := EncodeApplications(invalid); err == nil {
			t.Fatal("accepted invalid applications")
		}
	}
}

func FuzzApplications(f *testing.F) {
	f.Add(applicationFixture(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		apps, err := ParseApplications(data)
		if err != nil {
			return
		}
		b, err := EncodeApplications(apps)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
