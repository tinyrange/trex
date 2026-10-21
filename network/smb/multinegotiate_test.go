package smb

import (
	"testing"
	"time"
)

func TestMultiprotocolDoesNotEnableSMB1(t *testing.T) {
	s, _ := newSession("User", "Domain", "Password", [16]byte{}, time.Now())
	b := make([]byte, 35)
	copy(b, []byte{255, 'S', 'M', 'B'})
	b[4] = 0x72
	dialects := []byte("\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00")
	le.PutUint16(b[33:], uint16(len(dialects)))
	b = append(b, dialects...)
	out, e := s.process(b)
	if e != nil {
		t.Fatal(e)
	}
	if le.Uint16(out[68:]) != 0x2ff || s.negotiated {
		t.Fatal("discovery established a session")
	}
	req := negotiateRequest(0x210)
	le.PutUint64(req[24:], 1)
	out, e = s.process(req)
	if e != nil {
		t.Fatal(e)
	}
	assertStatus(t, out, 0)
	if !s.negotiated {
		t.Fatal("SMB2 followup rejected")
	}
	if _, e = s.process(b); e == nil {
		t.Fatal("SMB1 accepted after SMB2")
	}
}
