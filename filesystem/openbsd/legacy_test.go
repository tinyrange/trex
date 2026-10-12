package openbsd

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestLegacyBSDLabel(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := fixture(order, 512, 512)
		h := b[512:]
		order.PutUint16(h[114:], 0)
		order.PutUint32(h[148+8:], 2048)
		h[148+13] = 8
		checksum(h, order)
		label, err := Open(&starfile.Bytes{Data: b}, 512)
		if err != nil {
			t.Fatal(err)
		}
		p := label.Partitions[0]
		if p.Start != 8 || p.Sectors != 16 || p.FragmentSize != 2048 || p.BlockSize != 16384 || label.BoundEnd != 128 {
			t.Fatalf("label: %+v %+v", label, p)
		}
	}
}
