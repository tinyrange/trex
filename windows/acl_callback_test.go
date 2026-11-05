package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseACLCallbackPrincipal(t *testing.T) {
	ace := []byte{9, 3, 24, 0, 0, 0, 0, 0x10, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0x61, 0x72, 0x74, 0x78}
	acl := explicitTestACL(ace)
	_, entries, err := ParseACL(acl)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Mask != 0x10000000 || !bytes.Equal(entries[0].SID, ace[8:20]) || !bytes.Equal(entries[0].Data[20:], ace[20:]) {
		t.Fatalf("callback parts: %+v", entries)
	}
	for _, count := range []byte{3, 255} {
		bad := bytes.Clone(acl)
		bad[17] = count
		if _, _, err := ParseACL(bad); err == nil {
			t.Fatal("accepted truncated callback SID")
		}
	}
	bad := bytes.Clone(acl)
	binary.LittleEndian.PutUint16(bad[10:], 12)
	if _, _, err := ParseACL(bad); err == nil {
		t.Fatal("accepted short callback")
	}
}
