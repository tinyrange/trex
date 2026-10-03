package ckd

import (
	"bytes"
	"io"
	"testing"
)

func extendedRecord(fill byte) []byte {
	b := append(bytes.Repeat([]byte{fill}, 512), make([]byte, 32)...)
	b[512] = 0x20
	b[522] = 0x10
	copy(b[541:], []byte{0x5a, 0x5a, 0xa5})
	return b
}
func TestExtendedPagesExcludeSuffixAcrossTracks(t *testing.T) {
	ds := &Dataset{SMSFlags: 0x84, Disk: openTest(t, image([][]Record{{r(1, nil, extendedRecord(1))}, {r(1, nil, extendedRecord(2))}})), Extents: []Extent{{First: 0, Last: 1}}}
	if _, err := ds.OpenPages(512); err == nil {
		t.Fatal("ordinary page reader accepted suffix")
	}
	p, err := ds.OpenVSAMPages(512)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 40)
	n, err := p.ReadAt(b, 500)
	want := append(bytes.Repeat([]byte{1}, 12), bytes.Repeat([]byte{2}, 28)...)
	if err != nil || n != 40 || !bytes.Equal(b, want) || p.Size() != 1024 {
		t.Fatal(n, err, b, p.Size())
	}
	n, err = p.ReadAt(b, 1010)
	if n != 14 || err != io.EOF {
		t.Fatal(n, err)
	}
}
func TestExtendedPagesRejectUnsupportedSuffixOnAnyTrack(t *testing.T) {
	for _, at := range []int{512, 513, 522, 541, 543} {
		bad := extendedRecord(2)
		bad[at] ^= 0x01
		ds := &Dataset{SMSFlags: 0x84, Disk: openTest(t, image([][]Record{{r(1, nil, extendedRecord(1))}, {r(1, nil, bad)}})), Extents: []Extent{{First: 0, Last: 1}}}
		p, err := ds.OpenVSAMPages(512)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Page(1); err == nil {
			t.Fatalf("accepted suffix mutation %d", at)
		}
	}
}
func TestVVRWideCIAddressedGeometry(t *testing.T) {
	b := vvrFixture()
	start := int(be.Uint16(b[2:])) + 2
	// A later common-cell generation extends the tail, not its leading fields.
	b = append(append(append([]byte(nil), b[:start+85]...), make([]byte, 68)...), b[start+85:]...)
	be.PutUint16(b, uint16(len(b)))
	be.PutUint16(b[start:], 153)
	component := start + 153
	volume := component + 98
	b[component+3] = 2
	be.PutUint16(b[component+8:], 0)
	be.PutUint16(b[component+10:], 0)
	b[volume+3] = 0x84
	be.PutUint32(b[volume+9:], 0x200000)
	be.PutUint32(b[volume+13:], 0x200001)
	v, err := ParseVVR(b)
	if err != nil || !v.CIAddressed || v.UsedBytes != uint64(0x200000)*4096 || v.AllocatedBytes != uint64(0x200001)*4096 {
		t.Fatal(v, err)
	}
	be.PutUint32(b[volume+9:], 0x200002)
	if _, err := ParseVVR(b); err == nil {
		t.Fatal("high-used exceeds high-allocated")
	}
}

func TestSMSManagedDoesNotMeanExtendedFormat(t *testing.T) {
	ds := &Dataset{SMSFlags: 0x80, Disk: openTest(t, image([][]Record{{r(1, nil, bytes.Repeat([]byte{7}, 512))}})), Extents: []Extent{{First: 0, Last: 0}}}
	p, err := ds.OpenVSAMPages(512)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Page(0)
	if err != nil || len(b) != 512 || b[0] != 7 {
		t.Fatal(b, err)
	}
	ds.SMSFlags = 0x84
	ds.Flags = 0x80
	if _, err := ds.OpenVSAMPages(512); err == nil {
		t.Fatal("accepted compressed profile")
	}
}
