package smb

import (
	"testing"
	"time"
)

func TestReconnectRequiresFreshAuthentication(t *testing.T) {
	s, err := newSession("User", "Domain", "Password", [16]byte{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.process(negotiateRequest(0x210)); err != nil {
		t.Fatal(err)
	}
	nego := make([]byte, 40)
	copy(nego, ntlmMagic)
	le.PutUint32(nego[8:], 1)
	le.PutUint32(nego[12:], 0xe2088215)
	req := setupRequest(1, 0, nego)
	le.PutUint64(req[80:], 0x12345678) // PreviousSessionId from a lost connection.
	reply, err := s.process(req)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, reply, statusMoreProcessing)
	if len(s.key) != 0 {
		t.Fatal("previous session ID bypassed authentication")
	}
	challenge, err := ntlmMessage(reply[72:])
	if err != nil {
		t.Fatal(err)
	}
	auth, key := clientAuthenticate(t, nego, challenge)
	req = setupRequest(2, s.id, auth)
	le.PutUint64(req[80:], 0x12345678)
	reply, err = s.process(req)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, reply, 0)
	clientVerify(t, key, reply)
}
