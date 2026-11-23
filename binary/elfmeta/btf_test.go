package elfmeta

import (
	"encoding/binary"
	"maps"
	"testing"
)

func TestBTFStructWithAnonymousUnion(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		const headerSize = 24
		blob := make([]byte, headerSize)
		order.PutUint16(blob, 0xeb9f)
		blob[2] = 1
		order.PutUint32(blob[4:], headerSize)
		appendWords := func(values ...uint32) {
			var raw [4]byte
			for _, value := range values {
				order.PutUint32(raw[:], value)
				blob = append(blob, raw[:]...)
			}
		}
		// struct task contains a direct member, a forward reference to an
		// anonymous union, and a bitfield. The union members share storage.
		appendWords(1, 1<<31|4<<24|3, 24, 6, 3, 0, 0, 2, 16*8, 19, 3, 1<<24|64)
		appendWords(0, 5<<24|2, 8, 10, 3, 0, 24, 3, 0)
		appendWords(0, 1<<24, 4, 32)
		typeSize := len(blob) - headerSize
		strings := "\x00task\x00pid\x00stackptr\x00flag\x00alt\x00"
		blob = append(blob, strings...)
		order.PutUint32(blob[12:], uint32(typeSize))
		order.PutUint32(blob[16:], uint32(typeSize))
		order.PutUint32(blob[20:], uint32(len(strings)))
		got, err := readBTFLayouts(blob, []string{"task"})
		if err != nil || got["task"].Size != 24 || !maps.Equal(got["task"].Fields, map[string]uint64{"pid": 0, "stackptr": 16, "alt": 16}) {
			t.Fatalf("%T: layouts %+v, %v", order, got, err)
		}
		if _, err := readBTFLayouts(blob[:len(blob)-1], []string{"task"}); err == nil {
			t.Fatal("accepted a truncated string section")
		}
		order.PutUint32(blob[headerSize+28:], 1) // Cycle through the anonymous member.
		order.PutUint32(blob[headerSize+32:], 0)
		if _, err := readBTFLayouts(blob, []string{"task"}); err == nil {
			t.Fatal("accepted a cyclic anonymous aggregate")
		}
	}
}
