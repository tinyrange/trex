package stuffit

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func installerRecords() []byte {
	b := make([]byte, 22)
	copy(b, "ST46")
	copy(b[10:], "rLau")
	b[14] = 2
	binary.BigEndian.PutUint16(b[4:], 1)
	for i := 0; i < 2; i++ {
		h := make([]byte, 112)
		h[2], h[3] = 1, 'F'
		payload := []byte{byte('A' + i)}
		if i == 0 {
			copy(h[66:], "TEXTTEST")
			binary.BigEndian.PutUint32(h[88:], 1)
		} else {
			copy(h[66:], "STcpSTin")
		}
		binary.BigEndian.PutUint32(h[96:], 1)
		binary.BigEndian.PutUint16(h[102:], crc16(payload))
		binary.BigEndian.PutUint16(h[110:], crc16(h[:110]))
		b = append(b, h...)
		b = append(b, payload...)
	}
	binary.BigEndian.PutUint32(b[6:], uint32(len(b)))
	return b
}
func TestInstallerMetadataPreserved(t *testing.T) {
	b := installerRecords()
	a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || a.RootCountVerified || a.TopLevelCount != 2 || a.DeclaredCount != 1 {
		t.Fatal("lost records/counts")
	}
	e := a.Entries[1]
	got, err := starfile.ReadAll(e.Data)
	if err != nil || string(got) != "B" || !e.InstallerRecord || e.Occurrence != 2 || e.Path != a.Entries[0].Path || e.DeclaredSizes[1] != 0 {
		t.Fatalf("lost metadata bytes or identity: %q %v", got, err)
	}
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 1); err == nil {
		t.Fatal("metadata escaped decoded byte limit")
	}
	b[len(b)-1] ^= 1
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil || !strings.Contains(err.Error(), "CRC mismatch") {
		t.Fatal("metadata CRC not checked", err)
	}
}
func TestOrdinaryDuplicatesStillRejected(t *testing.T) {
	b := installerRecords()
	h := b[135:247]
	copy(h[66:], "TEXTTEST")
	binary.BigEndian.PutUint32(h[88:], 1)
	binary.BigEndian.PutUint16(h[110:], crc16(h[:110]))
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatal("accepted ordinary duplicate", err)
	}
}

func TestOtherInstallerRecords(t *testing.T) {
	for _, kind := range []string{"STde", "STal", "DIFF"} {
		b := installerRecords()
		h := b[135:247]
		copy(h[66:], kind)
		if kind == "DIFF" {
			binary.BigEndian.PutUint32(h[88:], 1)
		}
		binary.BigEndian.PutUint16(h[110:], crc16(h[:110]))
		a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
		if err != nil {
			t.Fatal(kind, err)
		}
		got, err := starfile.ReadAll(a.Entries[1].Data)
		if err != nil || string(got) != "B" || a.Entries[1].Occurrence != 2 {
			t.Fatal("lost installer record", kind)
		}
	}
}

func TestST60InstallerRecords(t *testing.T) {
	for _, kind := range []string{"STde", "STda", "STmv"} {
		t.Run(kind, func(t *testing.T) {
			b := installerRecords()
			copy(b, "ST60")
			h := b[135:247]
			copy(h[66:], kind)
			binary.BigEndian.PutUint16(h[110:], crc16(h[:110]))
			a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
			if err != nil {
				t.Fatal(err)
			}
			e := a.Entries[1]
			got, err := starfile.ReadAll(e.Data)
			if err != nil || string(got) != "B" || !e.InstallerRecord || e.DeclaredSizes[1] != 0 || e.Occurrence != 2 || a.RootCountVerified {
				t.Fatalf("lost ST60 record: %+v %q %v", e, got, err)
			}
			if _, err := Open(&starfile.Bytes{Data: b}, 10, 1); err == nil {
				t.Fatal("metadata escaped decoded byte limit")
			}
			b[len(b)-1] ^= 1
			if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil || !strings.Contains(err.Error(), "CRC mismatch") {
				t.Fatal("metadata CRC not checked", err)
			}
		})
	}
}

func TestST60MetadataCanNameDirectory(t *testing.T) {
	testMetadataCanNameDirectory(t, "ST60")
}

func TestST65MetadataCanNameDirectory(t *testing.T) {
	testMetadataCanNameDirectory(t, "ST65")
}

func testMetadataCanNameDirectory(t *testing.T, signature string) {
	t.Helper()
	b := installerRecords()
	copy(b, signature)
	start := make([]byte, 112)
	start[0], start[1], start[2], start[3] = 32, 32, 1, 'F'
	binary.BigEndian.PutUint16(start[110:], crc16(start[:110]))
	end := append([]byte(nil), start...)
	end[0], end[1] = 33, 33
	binary.BigEndian.PutUint16(end[110:], crc16(end[:110]))
	metadata := append([]byte(nil), b[135:]...)
	copy(metadata[66:], "STde")
	binary.BigEndian.PutUint16(metadata[110:], crc16(metadata[:110]))
	b = append(b[:22], start...)
	b = append(b, end...)
	b = append(b, metadata...)
	binary.BigEndian.PutUint32(b[6:], uint32(len(b)))
	a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || !a.Entries[0].Directory || !a.Entries[1].InstallerRecord || a.Entries[1].Occurrence != 2 || a.Entries[0].Path != a.Entries[1].Path {
		t.Fatal("lost directory or metadata")
	}
	// A subsequent ordinary file must still collide with the original directory.
	ordinary := append([]byte(nil), metadata...)
	copy(ordinary[66:], "TEXTTEST")
	binary.BigEndian.PutUint32(ordinary[88:], 1)
	binary.BigEndian.PutUint16(ordinary[110:], crc16(ordinary[:110]))
	b = append(b, ordinary...)
	binary.BigEndian.PutUint32(b[6:], uint32(len(b)))
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatal("metadata hid the directory collision", err)
	}
}

func TestST60AlternativeFilesPreserved(t *testing.T) {
	b := installerRecords()
	copy(b, "ST60")
	h := b[135:247]
	copy(h[66:], "TEXTTEST")
	binary.BigEndian.PutUint32(h[88:], 1)
	binary.BigEndian.PutUint16(h[110:], crc16(h[:110]))
	a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range a.Entries {
		got, err := starfile.ReadAll(e.Data)
		if err != nil || len(got) != 1 || got[0] != byte('A'+i) || e.Occurrence != i+1 || e.InstallerRecord || e.Path != "/F" {
			t.Fatalf("lost alternative %d: %+v %q %v", i, e, got, err)
		}
	}
}

func TestST65Metadata(t *testing.T) {
	for _, kind := range []string{"STde", "STda", "STmv", "STal"} {
		b := installerRecords()
		copy(b, "ST65")
		h := b[135:247]
		copy(h[66:], kind)
		binary.BigEndian.PutUint16(h[110:], crc16(h[:110]))
		a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
		if err != nil {
			t.Fatal(kind, err)
		}
		e := a.Entries[1]
		got, err := starfile.ReadAll(e.Data)
		if err != nil || string(got) != "B" || !e.InstallerRecord || e.DeclaredSizes[1] != 0 || e.Occurrence != 2 || a.RootCountVerified {
			t.Fatal("lost ST65 metadata", kind, err)
		}
		if _, err := Open(&starfile.Bytes{Data: b}, 10, 1); err == nil {
			t.Fatal("metadata escaped byte limit")
		}
		b[len(b)-1] ^= 1
		if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil || !strings.Contains(err.Error(), "CRC mismatch") {
			t.Fatal("metadata CRC not checked", err)
		}
	}
}

func TestST65MetadataBeforeFile(t *testing.T) {
	b := installerRecords()
	copy(b, "ST65")
	first := append([]byte(nil), b[22:135]...)
	second := append([]byte(nil), b[135:]...)
	copy(second[66:], "STde")
	binary.BigEndian.PutUint16(second[110:], crc16(second[:110]))
	b = append(b[:22], second...)
	b = append(b, first...)
	a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || !a.Entries[0].InstallerRecord || a.Entries[1].InstallerRecord || a.Entries[1].Occurrence != 2 {
		t.Fatal("metadata obscured following file")
	}
	// A second ordinary file is still a collision, unlike ST60 alternatives.
	b = append(b, first...)
	binary.BigEndian.PutUint32(b[6:], uint32(len(b)))
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatal("accepted ordinary ST65 duplicate", err)
	}
}
