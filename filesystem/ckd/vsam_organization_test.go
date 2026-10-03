package ckd

import "testing"

func TestVVRRecordOrganizationDoesNotGuess(t *testing.T) {
	for _, tc := range []struct {
		flags byte
		key   uint16
		want  VSAMOrganization
	}{
		{0x80, 24, VSAMKSDS}, {0x81, 45, VSAMKSDS},
		{2, 0, VSAMRRDS}, {3, 0, VSAMRRDS}, {1, 0, VSAMESDS},
		{0, 0, ""}, {0x82, 8, ""}, {0x80, 0, ""}, {2, 8, ""}, {1, 8, ""},
	} {
		v := &VVR{DataFlags: tc.flags, KeyLength: tc.key}
		got, err := v.recordOrganization()
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Fatalf("%#x/%d: %q %v", tc.flags, tc.key, got, err)
		}
		v.Index = true
		if _, err := v.recordOrganization(); err == nil {
			t.Fatal("index dispatched as data")
		}
	}
}

func TestVVRNonspannedESDSVersusLinear(t *testing.T) {
	v := &VVR{DataFlags: 0, CIBytes: 1024, MaximumRecordLength: 1017}
	if org, err := v.recordOrganization(); err != nil || org != VSAMESDS {
		t.Fatal(org, err)
	}
	v.MaximumRecordLength = 0
	if _, err := v.recordOrganization(); err == nil {
		t.Fatal("linear component accepted as ESDS")
	}
}
