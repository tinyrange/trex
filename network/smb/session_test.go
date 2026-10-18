package smb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func clientRequest(command uint16, id, session uint64, body []byte) []byte {
	b := make([]byte, 64)
	copy(b, "\xfeSMB")
	binary.LittleEndian.PutUint16(b[4:], 64)
	binary.LittleEndian.PutUint16(b[12:], command)
	binary.LittleEndian.PutUint16(b[14:], 32)
	binary.LittleEndian.PutUint64(b[24:], id)
	binary.LittleEndian.PutUint64(b[40:], session)
	return append(b, body...)
}
func clientSign(key, b []byte) {
	binary.LittleEndian.PutUint32(b[16:], binary.LittleEndian.Uint32(b[16:])|8)
	clear(b[48:64])
	h := hmac.New(sha256.New, key)
	h.Write(b)
	copy(b[48:64], h.Sum(nil)[:16])
}
func clientVerify(t *testing.T, key, b []byte) {
	t.Helper()
	if binary.LittleEndian.Uint32(b[16:])&8 == 0 {
		t.Fatal("unsigned server response")
	}
	received := append([]byte(nil), b[48:64]...)
	clone := append([]byte(nil), b...)
	clientSign(key, clone)
	if !hmac.Equal(received, clone[48:64]) {
		t.Fatal("bad server signature")
	}
}
func negotiateRequest(dialects ...uint16) []byte {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b, 36)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(b[4:], 1)
	for _, dialect := range dialects {
		b = binary.LittleEndian.AppendUint16(b, dialect)
	}
	return clientRequest(0, 0, 0, b)
}
func setupRequest(id, session uint64, token []byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, 25)
	b[3] = 1
	binary.LittleEndian.PutUint16(b[12:], 88)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(token)))
	return clientRequest(1, id, session, append(b, token...))
}
func assertStatus(t *testing.T, b []byte, status uint32) {
	t.Helper()
	if len(b) < 64 || binary.LittleEndian.Uint32(b[8:]) != status {
		t.Fatalf("want status %08x: %x", status, b)
	}
}

func TestSessionSignedTransport(t *testing.T) {
	// net.Pipe provides no TCP socket. Exchange serialized packets through the
	// actual stream loop, including a deliberately fragmented first frame.
	s, err := newSession("User", "Domain", "Password", [16]byte{1, 2, 3}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { done <- s.serve(server) }()
	exchange := func(request []byte, fragment bool) []byte {
		t.Helper()
		var frame bytes.Buffer
		if err := writeFrame(&frame, request); err != nil {
			t.Fatal(err)
		}
		if fragment {
			for _, b := range frame.Bytes() {
				if _, err := client.Write([]byte{b}); err != nil {
					t.Fatal(err)
				}
			}
		} else if _, err := client.Write(frame.Bytes()); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	reply := exchange(negotiateRequest(0x202, 0x210, 0x311), true)
	assertStatus(t, reply, 0)
	if binary.LittleEndian.Uint16(reply[66:]) != 3 || binary.LittleEndian.Uint16(reply[68:]) != 0x210 {
		t.Fatal("dialect or mandatory signing")
	}
	if binary.LittleEndian.Uint32(reply[88:]) != 0 {
		t.Fatal("unsupported capabilities advertised")
	}
	nego := make([]byte, 40)
	copy(nego, ntlmMagic)
	binary.LittleEndian.PutUint32(nego[8:], 1)
	binary.LittleEndian.PutUint32(nego[12:], 0xe2088215)
	reply = exchange(setupRequest(1, 0, nego), false)
	assertStatus(t, reply, statusMoreProcessing)
	sid := binary.LittleEndian.Uint64(reply[40:])
	challenge, err := ntlmMessage(reply[72:])
	if err != nil {
		t.Fatal(err)
	}
	auth, key := clientAuthenticate(t, nego, challenge)
	reply = exchange(setupRequest(2, sid, auth), false)
	assertStatus(t, reply, 0)
	clientVerify(t, key, reply)
	if binary.LittleEndian.Uint16(reply[66:]) != 0 {
		t.Fatal("guest/null session")
	}
	echo := clientRequest(13, 3, sid, []byte{4, 0, 0, 0})
	clientSign(key, echo)
	reply = exchange(echo, false)
	assertStatus(t, reply, 0)
	clientVerify(t, key, reply)
	logoff := clientRequest(2, 4, sid, []byte{4, 0, 0, 0})
	clientSign(key, logoff)
	reply = exchange(logoff, false)
	assertStatus(t, reply, 0)
	clientVerify(t, key, reply)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.key, make([]byte, 16)) {
		t.Fatal("session key retained after stream closed")
	}
}
func establishedSession(t *testing.T) *session {
	t.Helper()
	s, err := newSession("User", "Domain", "Password", [16]byte{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s.negotiated = true
	s.key = bytes.Repeat([]byte{0x55}, 16)
	return s
}
func TestSessionTamperReplayAndCompoundAtomicValidation(t *testing.T) {
	for _, mode := range []string{"unsigned", "tampered", "replay", "wrong-session", "compound-tamper", "compound-valid"} {
		t.Run(mode, func(t *testing.T) {
			s := establishedSession(t)
			a := clientRequest(13, 0, s.id, []byte{4, 0, 0, 0})
			clientSign(s.key, a)
			switch mode {
			case "unsigned":
				binary.LittleEndian.PutUint32(a[16:], 0)
			case "tampered":
				a[66] ^= 1
			case "wrong-session":
				binary.LittleEndian.PutUint64(a[40:], s.id+1)
				clientSign(s.key, a)
			case "replay":
				if _, err := s.process(a); err != nil {
					t.Fatal(err)
				}
			case "compound-tamper", "compound-valid":
				s.credits[1] = true
				s.nextCredit = 2
				a = append(a, 0, 0, 0, 0)
				binary.LittleEndian.PutUint32(a[20:], 72)
				clientSign(s.key, a)
				b := clientRequest(13, 1, ^uint64(0), []byte{4, 0, 0, 0})
				binary.LittleEndian.PutUint32(b[16:], 4)
				clientSign(s.key, b)
				if mode == "compound-tamper" {
					b[67] ^= 1
				}
				a = append(a, b...)
			}
			out, err := s.process(a)
			if mode == "wrong-session" {
				if err != nil {
					t.Fatal(err)
				}
				assertStatus(t, out, statusUserSessionDeleted)
				clientVerify(t, s.key, out)
			} else if mode == "compound-valid" {
				if err != nil {
					t.Fatal(err)
				}
				n := int(binary.LittleEndian.Uint32(out[20:]))
				if n != 72 {
					t.Fatal("bad compound padding", n)
				}
				assertStatus(t, out[:n], 0)
				assertStatus(t, out[n:], 0)
				clientVerify(t, s.key, out[:n])
				clientVerify(t, s.key, out[n:])
			} else {
				if err == nil {
					t.Fatal("invalid request accepted")
				}
				if mode == "compound-tamper" && (!s.credits[0] || !s.credits[1]) {
					t.Fatal("partial effects before validation")
				}
			}
		})
	}
}
func TestNegotiationDoesNotDowngrade(t *testing.T) {
	s, _ := newSession("User", "Domain", "Password", [16]byte{}, time.Now())
	out, err := s.process(negotiateRequest(0x202))
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, out, statusNotSupported)
	if s.negotiated || !s.closing {
		t.Fatal("unsupported dialect accepted")
	}
}
func TestFramingBounds(t *testing.T) {
	for _, b := range [][]byte{{0, 0, 0, 63}, {0, 0x20, 0, 1}, {0x81, 0, 0, 64}, {0, 0, 0, 64, 1, 2}} {
		if _, err := readFrame(bytes.NewReader(b)); err == nil {
			t.Fatal("bad frame accepted")
		}
	}
	if _, err := readFrame(bytes.NewReader(nil)); err != io.EOF {
		t.Fatal(err)
	}
}
func FuzzSMBCompound(f *testing.F) {
	f.Add(negotiateRequest(0x210))
	f.Add(clientRequest(13, 0, 1, []byte{4, 0, 0, 0}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxFrame {
			return
		}
		reqs, err := parseRequests(b)
		if err != nil {
			return
		}
		for _, req := range reqs {
			if len(req.raw) < 64 {
				t.Fatal("short parsed message")
			}
			validSignature(make([]byte, 16), req.raw)
		}
		s, _ := newSession("User", "Domain", "Password", [16]byte{}, time.Now())
		s.process(b)
	})
}
