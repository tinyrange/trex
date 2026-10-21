package smb

import (
	"testing"
	"time"
)

func TestClientSigningRequiredWithoutEnabledBit(t *testing.T) {
	s, _ := newSession("User", "Domain", "Password", [16]byte{}, time.Now())
	req := negotiateRequest(0x210)
	le.PutUint16(req[68:], 2)
	out, e := s.process(req)
	if e != nil {
		t.Fatal(e)
	}
	assertStatus(t, out, 0)
}
