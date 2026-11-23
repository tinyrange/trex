package r3000

import (
	"bytes"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestMOPV3LoadAndRetransmit(t *testing.T) {
	m := testMachine(t, 0)
	le := binary.LittleEndian
	image := make([]byte, 120)
	le.PutUint16(image, 0x162)
	le.PutUint16(image[2:], 1)
	le.PutUint16(image[16:], 56)
	le.PutUint16(image[20:], 0x107)
	le.PutUint32(image[36:], 0x80030000)
	copy(image[76:], ".text")
	le.PutUint32(image[88:], 0x80030000)
	le.PutUint32(image[92:], 4)
	le.PutUint32(image[96:], 116)
	le.PutUint32(image[112:], 0x20)
	copy(image[116:], []byte{1, 2, 3, 4})
	if err := m.ServeMOP("nt.exe", &starfile.Bytes{Data: image}); err != nil {
		t.Fatal(err)
	}
	client := [6]byte{2, 0, 0, 0, 0, 3}
	request := func(mac [6]byte, payload []byte) []byte {
		frame := mopFrame(mac, payload)
		copy(frame[6:12], client[:])
		reply, err := m.mop.receive(frame, m.epoch)
		if err != nil {
			t.Fatal(err)
		}
		if len(reply) == 0 {
			return nil
		}
		return reply[16 : 16+le.Uint16(reply[14:])]
	}
	program := []byte{8, 0, 1, 2, 6, 'n', 't', '.', 'e', 'x', 'e', 0}
	if got := request(mopMulticast, program); !bytes.Equal(got, []byte{3}) {
		t.Fatalf("volunteer %x", got)
	}
	block := request(mopMAC, program)
	if !bytes.Equal(block, []byte{2, 0, 0, 0, 3, 0x80, 1, 2, 3, 4}) {
		t.Fatalf("memory load %x", block)
	}
	if repeated := request(mopMAC, []byte{10, 0}); !bytes.Equal(repeated, block) || m.mop.acknowledged != 0 {
		t.Fatalf("retransmission %x, acked %d", repeated, m.mop.acknowledged)
	}
	done := request(mopMAC, []byte{10, 1})
	if len(done) != 19 || done[0] != 20 || done[1] != 1 || le.Uint32(done[15:]) != 0x80030000 || m.mop.acknowledged != 4 {
		t.Fatalf("transfer %x, acked %d", done, m.mop.acknowledged)
	}
	if last := request(mopMAC, []byte{10, 2}); last != nil || !m.mop.complete {
		t.Fatalf("final ack %x, complete %v", last, m.mop.complete)
	}
}
