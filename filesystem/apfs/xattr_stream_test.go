package apfs

import (
	"bytes"
	"testing"
)

func TestXattrStreamIdentity(t *testing.T) {
	b := fixture()
	key := le.AppendUint16(fsKey(10, 4), 5)
	key = append(key, []byte("attr\x00")...)
	value := make([]byte, 52)
	le.PutUint16(value, 1) // nonresident attribute
	le.PutUint16(value[2:], 48)
	le.PutUint64(value[4:], 11)
	le.PutUint64(value[12:], 4)
	node := tree([]pair{inodePair(2, 2, 0, 0x41ed), inodePair(10, 10, 0, 0x81a4), drec("hello", 10), {key, value}, extentPair(0, 4, 12)}, false)
	copy(b[9*4096:], node)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := c.Volumes[0].Entries(false)
	if err != nil {
		t.Fatal(err)
	}
	if got := entries[1].XattrStreams["attr"]; got != 11 {
		t.Fatalf("stream ID %d", got)
	}
	var data [4]byte
	if _, err := entries[1].Xattrs["attr"].ReadAt(data[:], 0); err != nil || string(data[:]) != "data" {
		t.Fatalf("attribute %q %v", data, err)
	}
}
