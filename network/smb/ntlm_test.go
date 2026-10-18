package smb

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestNTLMv2PublishedVector(t *testing.T) {
	// MS-NLMP 4.2.4.1.1, NTOWFv2("Password", "User", "Domain").
	// Microsoft Open Specifications test vector, not an implementation oracle.
	if got := hex.EncodeToString(ntlmV2Hash("User", "Domain", "Password")); got != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatal(got)
	}
}
func authenticationFixture(t *testing.T) (*ntlmServer, []byte, []byte) {
	t.Helper()
	s := &ntlmServer{user: "User", domain: "Domain", password: "Password"}
	negotiate := make([]byte, 40)
	copy(negotiate, ntlmMagic)
	binary.LittleEndian.PutUint32(negotiate[8:], 1)
	binary.LittleEndian.PutUint32(negotiate[12:], 0xe2088215)
	if _, err := s.start(negotiate); err != nil {
		t.Fatal(err)
	}
	auth, key := clientAuthenticate(t, s.negotiate, s.challenge)
	return s, auth, key
}

func clientAuthenticate(t *testing.T, negotiate, challenge []byte) ([]byte, []byte) {
	t.Helper()
	info, err := securityBuffer(challenge, 40)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 28)
	blob[0], blob[1] = 1, 1
	for at := 0; at+4 <= len(info); {
		id, n := binary.LittleEndian.Uint16(info[at:]), int(binary.LittleEndian.Uint16(info[at+2:]))
		at += 4
		if n > len(info)-at {
			t.Fatal("bad challenge AV length")
		}
		if id == 7 && n == 8 {
			copy(blob[8:16], info[at:at+n])
		}
		at += n
	}
	copy(blob[16:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	blob = append(blob, info...)
	blob = append(blob, 0, 0, 0, 0)
	hash := ntlmV2Hash("User", "Domain", "Password")
	proof := hmacMD5(hash, challenge[24:32], blob)
	base := hmacMD5(hash, proof)
	key := bytes.Repeat([]byte{0x55}, 16)
	encrypted := make([]byte, 16)
	cipher, _ := rc4.NewCipher(base)
	cipher.XORKeyStream(encrypted, key)
	auth := make([]byte, 88)
	copy(auth, ntlmMagic)
	binary.LittleEndian.PutUint32(auth[8:], 3)
	binary.LittleEndian.PutUint32(auth[60:], binary.LittleEndian.Uint32(challenge[20:]))
	auth = putSecurityBuffer(auth, 12, make([]byte, 24))
	auth = putSecurityBuffer(auth, 20, append(proof, blob...))
	auth = putSecurityBuffer(auth, 28, utf16Bytes("Domain"))
	auth = putSecurityBuffer(auth, 36, utf16Bytes("User"))
	auth = putSecurityBuffer(auth, 44, utf16Bytes("CLIENT"))
	auth = putSecurityBuffer(auth, 52, encrypted)
	copy(auth[72:88], hmacMD5(key, negotiate, challenge, auth))
	return auth, key
}
func TestNTLMAuthenticationIntegrityAndReplay(t *testing.T) {
	for _, name := range []string{"valid", "proof", "mic", "flags", "password", "offset", "nonce", "timestamp"} {
		t.Run(name, func(t *testing.T) {
			s, a, want := authenticationFixture(t)
			switch name {
			case "proof":
				i := binary.LittleEndian.Uint32(a[24:])
				a[i] ^= 1
			case "mic":
				a[72] ^= 1
			case "flags":
				a[60] &= ^byte(ntlmSign)
			case "password":
				s.password = "wrong"
			case "offset":
				binary.LittleEndian.PutUint32(a[24:], 0xffffffff)
			case "nonce":
				s.nonce[0] ^= 1
			case "timestamp":
				s.timestamp++
			}
			got, err := s.finish(a)
			if name == "valid" {
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("valid exchange", err)
				}
			} else if err == nil {
				t.Fatal("tampered authentication accepted")
			}
			if _, err := s.finish(a); err == nil {
				t.Fatal("authentication replay accepted")
			}
		})
	}
}
func TestSPNEGOBoundsAndTokenRoundTrip(t *testing.T) {
	token := append(append([]byte(nil), ntlmMagic...), 1, 0, 0, 0)
	wrapped := spnegoReply(token, false)
	got, err := ntlmMessage(wrapped)
	if err != nil || !bytes.Equal(got, token) {
		t.Fatal(err)
	}
	// Reject malformed lengths and multiple candidate security tokens.
	for _, bad := range [][]byte{{0xa1, 0x84, 255, 255, 255, 255}, der(0x30, append(der(4, token), der(4, token)...)), bytes.Repeat([]byte{1}, 65537)} {
		if _, err := ntlmMessage(bad); err == nil {
			t.Fatal("invalid SPNEGO accepted")
		}
	}
}
func FuzzNTLMParsing(f *testing.F) {
	f.Add([]byte("NTLMSSP"))
	f.Add(spnegoOffer())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		ntlmMessage(b)
		for _, off := range []int{12, 20, 28, 36, 44, 52} {
			securityBuffer(b, off)
		}
		s := &ntlmServer{user: "User", domain: "Domain", password: "Password"}
		s.start(b)
	})
}
