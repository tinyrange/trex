package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSAMAliasMembers(t *testing.T) {
	record := make([]byte, samAliasHeaderSize+12)
	binary.LittleEndian.PutUint32(record, 545)
	binary.LittleEndian.PutUint32(record[8:], 4)
	binary.LittleEndian.PutUint32(record[0x10:], 4)
	binary.LittleEndian.PutUint32(record[0x14:], 4)
	binary.LittleEndian.PutUint32(record[0x1c:], 8)
	binary.LittleEndian.PutUint32(record[0x20:], 4)
	binary.LittleEndian.PutUint32(record[0x28:], 12)
	copy(record[samAliasHeaderSize:], []byte("preserve me!"))
	authenticated := []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
	interactive := []byte{1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0}
	updated, err := SAMAliasWithMembers(record, [][]byte{authenticated, interactive})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record[samAliasHeaderSize:], updated[samAliasHeaderSize:len(record)]) {
		t.Fatal("unrelated alias payload changed")
	}
	members, err := SAMAliasMembers(updated)
	if err != nil || len(members) != 2 || !bytes.Equal(members[0], authenticated) || !bytes.Equal(members[1], interactive) {
		t.Fatalf("members = %x, error = %v", members, err)
	}
	again, err := SAMAliasWithMembers(updated, members)
	if err != nil || !bytes.Equal(again, updated) {
		t.Fatal("replacement is not idempotent", err)
	}
	empty, err := SAMAliasWithMembers(updated, nil)
	if err != nil || !bytes.Equal(empty, record) {
		t.Fatal("removing members did not preserve original record", err)
	}
	if _, err := SAMAliasWithMembers(record, [][]byte{authenticated, authenticated}); err == nil {
		t.Fatal("accepted duplicate membership")
	}
	for _, mutation := range []func([]byte){
		func(v []byte) { binary.LittleEndian.PutUint32(v[0x28:], 0xffffffff) },
		func(v []byte) { binary.LittleEndian.PutUint32(v[0x30:], 3) },
		func(v []byte) { v[len(record)] = 2 },
		func(v []byte) { v[len(record)+1] = 15 },
	} {
		bad := append([]byte(nil), updated...)
		mutation(bad)
		if _, err := SAMAliasMembers(bad); err == nil {
			t.Fatal("accepted malformed member vector")
		}
	}
}
