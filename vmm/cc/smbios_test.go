package cc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSMBIOSGuestIdentityAndMemory(t *testing.T) {
	for _, memory := range []uint64{8 << 30, 16 << 30, 64 << 30} {
		uuid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		table := smbiosTable(memory, 4, uuid)
		records := map[byte][]byte{}
		handles := map[uint16]bool{}
		for at := 0; at < len(table); {
			if len(table)-at < 4 {
				t.Fatal("truncated header")
			}
			n := int(table[at+1])
			if n < 4 || n > len(table)-at {
				t.Fatal("formatted length")
			}
			end := bytes.Index(table[at+n:], []byte{0, 0})
			if end < 0 {
				t.Fatal("missing string terminator")
			}
			handle := binary.LittleEndian.Uint16(table[at+2:])
			if handles[handle] {
				t.Fatal("duplicate handle")
			}
			handles[handle] = true
			records[table[at]] = table[at : at+n]
			at += n + end + 2
		}
		for _, typ := range []byte{0, 1, 2, 3, 4, 16, 17, 32, 127} {
			if records[typ] == nil {
				t.Fatalf("missing type %d", typ)
			}
		}
		if !bytes.Equal(records[1][8:24], uuid[:]) {
			t.Fatal("UUID byte order")
		}
		if records[4][35] != 4 || records[4][37] != 4 {
			t.Fatal("CPU topology")
		}
		if records[0][19]&8 == 0 {
			t.Fatal("UEFI characteristic")
		}
		if got := binary.LittleEndian.Uint64(records[16][15:]); got != memory {
			t.Fatal("array capacity", got)
		}
		size := uint64(binary.LittleEndian.Uint16(records[17][12:]))
		if size == 0x7fff {
			size = uint64(binary.LittleEndian.Uint32(records[17][28:]))
		}
		if size<<20 != memory {
			t.Fatal("memory device size", size)
		}
		for _, tc := range []struct {
			typ    byte
			offset int
			target uint16
		}{{2, 11, 3}, {17, 4, 16}} {
			if got := binary.LittleEndian.Uint16(records[tc.typ][tc.offset:]); got != tc.target || !handles[got] {
				t.Fatal("dangling handle", tc)
			}
		}
		ep := smbios3Entry(0x1234567890, uint32(len(table)))
		var sum byte
		for _, v := range ep {
			sum += v
		}
		if sum != 0 || string(ep[:5]) != "_SM3_" || int(ep[6]) != len(ep) {
			t.Fatal("entry checksum/header")
		}
		if binary.LittleEndian.Uint64(ep[16:]) != 0x1234567890 || binary.LittleEndian.Uint32(ep[12:]) != uint32(len(table)) {
			t.Fatal("entry address/length")
		}
	}
}
