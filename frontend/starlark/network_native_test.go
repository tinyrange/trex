package starlarkfrontend

import (
	"bytes"
	"testing"
)

// The bridge answers ARP for any address with the guest's MAC: everything
// beyond the stack is reached over the point-to-point CTC link.
func TestCTCBridgeARPReply(t *testing.T) {
	req := make([]byte, 42)
	copy(req[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(req[6:12], ctcHostMAC[:])
	req[12], req[13] = 0x08, 0x06
	copy(req[14:20], []byte{0, 1, 8, 0, 6, 4})
	req[20], req[21] = 0, 1
	copy(req[22:28], ctcHostMAC[:])
	copy(req[28:32], []byte{10, 42, 0, 1})
	copy(req[38:42], []byte{9, 19, 40, 167})
	r := arpReply(req)
	if r == nil || r[21] != 2 || !bytes.Equal(r[0:6], ctcHostMAC[:]) || !bytes.Equal(r[22:28], ctcGuestMAC[:]) ||
		!bytes.Equal(r[28:32], []byte{9, 19, 40, 167}) || !bytes.Equal(r[38:42], []byte{10, 42, 0, 1}) {
		t.Fatalf("ARP reply %X", r)
	}
	req[21] = 2
	if arpReply(req) != nil {
		t.Fatal("answered an ARP reply")
	}
}
