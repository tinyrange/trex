package windows

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestADReplicationMetadataWindows2000(t *testing.T) {
	// First two metadata entries on DNT 4 in Windows 2000 SP1's bootstrap
	// NTDS.DIT, retaining the header for a two-entry vector.
	want, _ := hex.DecodeString("01000000000000000200000000000000" +
		"00000000010000006e3d0f38000000000000000000000000000000000000000001000000000000000100000000000000" +
		"0a000000010000006e3d0f38000000000000000000000000000000000000000001000000000000000100000000000000")
	got, err := ADReplicationMetadata([]uint32{10, 0}, make([]byte, 16), 940522862, 1)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("metadata = %x, %v; want %x", got, err, want)
	}
	if _, err := ADReplicationMetadata([]uint32{1, 1}, make([]byte, 16), 0, 1); err == nil {
		t.Fatal("duplicate metadata accepted")
	}
}

func TestADLegacySecurityRecords(t *testing.T) {
	boot := bytes.Repeat([]byte{0x31}, 16)
	key := bytes.Repeat([]byte{0x42}, 16)
	salt := bytes.Repeat([]byte{0x53}, 16)
	pek, err := ADLegacyPEKList(boot, key, salt, 12345678)
	if err != nil {
		t.Fatal(err)
	}
	if len(pek) != 76 || binary.LittleEndian.Uint32(pek) != 2 || binary.LittleEndian.Uint32(pek[4:]) != 1 || !bytes.Equal(pek[8:24], salt) {
		t.Fatalf("PEK header: %x", pek)
	}
	plain := adRC4(pek[24:], boot, salt, 1000)
	signature, _ := hex.DecodeString("56d98148ec91d111905a00c04fc2d4cf")
	if !bytes.Equal(plain[:16], signature) || binary.LittleEndian.Uint64(plain[16:]) != 12345678 || binary.LittleEndian.Uint32(plain[28:]) != 1 || !bytes.Equal(plain[36:], key) {
		t.Fatalf("PEK content: %x", plain)
	}
	secret, err := ADLegacySecret([]byte("RID-protected NT hash"), key, salt)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(secret) != 0x11 || binary.LittleEndian.Uint32(secret[4:]) != 0 || !bytes.Equal(adRC4(secret[24:], key, salt, 1), []byte("RID-protected NT hash")) {
		t.Fatalf("secret record: %x", secret)
	}
	if _, err := ADLegacyPEKList(nil, key, salt, 0); err == nil {
		t.Fatal("short boot key accepted")
	}
	if _, err := ADLegacySecret(nil, key, salt); err == nil {
		t.Fatal("empty secret accepted")
	}
}

func TestADLegacyDNBinaryAndSchedule(t *testing.T) {
	guid, _ := hex.DecodeString("a9d1ca15768811d1aded00c04fd8d5cd")
	got, err := ADLegacyDNBinary(1200, guid)
	want, _ := hex.DecodeString("b004000014000000a9d1ca15768811d1aded00c04fd8d5cd")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("DN-Binary %x, %v", got, err)
	}
	if _, err := ADLegacyDNBinary(0, guid); err == nil {
		t.Fatal("zero DNT accepted")
	}
	schedule, err := ADReplicationSchedule(bytes.Repeat([]byte{15}, 168))
	if err != nil || len(schedule) != 188 || binary.LittleEndian.Uint32(schedule) != 188 || binary.LittleEndian.Uint32(schedule[8:]) != 1 || binary.LittleEndian.Uint32(schedule[12:]) != 0 || binary.LittleEndian.Uint32(schedule[16:]) != 20 || !bytes.Equal(schedule[20:], bytes.Repeat([]byte{15}, 168)) {
		t.Fatalf("schedule %x, %v", schedule, err)
	}
	if _, err := ADReplicationSchedule(bytes.Repeat([]byte{16}, 168)); err == nil {
		t.Fatal("reserved schedule bits accepted")
	}
	sid, _ := hex.DecodeString("01020000000000052000000020020000")
	stored, err := ADStoredSID(sid)
	want, _ = hex.DecodeString("01020000000000052000000000000220")
	if err != nil || !bytes.Equal(stored, want) {
		t.Fatalf("stored SID %x, %v", stored, err)
	}
}
