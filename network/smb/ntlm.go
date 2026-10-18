// Package smb implements a bounded SMB server for private virtual networks.
package smb

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

var errAuthentication = errors.New("SMB authentication failed")
var ntlmMagic = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

const ntlmUnicode uint32 = 1
const ntlmSign uint32 = 0x10
const ntlmNTLM uint32 = 0x200
const ntlmExtended uint32 = 0x80000
const ntlmTargetInfo uint32 = 0x800000
const ntlmVersion uint32 = 0x2000000
const ntlmKeyExchange uint32 = 0x40000000

func utf16Bytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, v := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}
func utf16String(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errAuthentication
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units)), nil
}
func hmacMD5(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func ntlmV2Hash(user, domain, password string) []byte {
	h := md4.New()
	h.Write(utf16Bytes(password))
	return hmacMD5(h.Sum(nil), utf16Bytes(strings.ToUpper(user)+domain))
}
func securityBuffer(msg []byte, offset int) ([]byte, error) {
	if offset < 0 || offset > len(msg)-8 {
		return nil, errAuthentication
	}
	n := uint64(binary.LittleEndian.Uint16(msg[offset:]))
	max := binary.LittleEndian.Uint16(msg[offset+2:])
	start := uint64(binary.LittleEndian.Uint32(msg[offset+4:]))
	if n > uint64(max) || start > uint64(len(msg)) || n > uint64(len(msg))-start {
		return nil, errAuthentication
	}
	return msg[start : start+n], nil
}
func putSecurityBuffer(msg []byte, at int, payload []byte) []byte {
	binary.LittleEndian.PutUint16(msg[at:], uint16(len(payload)))
	binary.LittleEndian.PutUint16(msg[at+2:], uint16(len(payload)))
	binary.LittleEndian.PutUint32(msg[at+4:], uint32(len(msg)))
	return append(msg, payload...)
}
func ntlmMessage(blob []byte) ([]byte, error) {
	if len(blob) > 65536 {
		return nil, errAuthentication
	}
	if bytes.HasPrefix(blob, ntlmMagic) {
		return append([]byte(nil), blob...), nil
	}
	var found []byte
	var walk func([]byte, int) error
	walk = func(data []byte, depth int) error {
		if depth > 8 {
			return errAuthentication
		}
		for len(data) > 0 {
			var v asn1.RawValue
			rest, err := asn1.Unmarshal(data, &v)
			if err != nil {
				return errAuthentication
			}
			data = rest
			if v.Class == 0 && v.Tag == 4 && bytes.HasPrefix(v.Bytes, ntlmMagic) {
				if found != nil {
					return errAuthentication
				}
				found = append([]byte(nil), v.Bytes...)
			} else if v.IsCompound {
				if err := walk(v.Bytes, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(blob, 0); err != nil || found == nil {
		return nil, errAuthentication
	}
	return found, nil
}
func der(tag byte, b []byte) []byte {
	out := []byte{tag}
	if len(b) < 128 {
		out = append(out, byte(len(b)))
	} else if len(b) < 256 {
		out = append(out, 0x81, byte(len(b)))
	} else {
		out = append(out, 0x82, byte(len(b)>>8), byte(len(b)))
	}
	return append(out, b...)
}

var ntlmOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

func spnegoReply(token []byte, complete bool) []byte {
	state := byte(1)
	if complete {
		state = 0
	}
	b := der(0xa0, []byte{0x0a, 1, state})
	if !complete {
		b = append(b, der(0xa1, ntlmOID)...)
	}
	if token != nil {
		b = append(b, der(0xa2, der(4, token))...)
	}
	return der(0xa1, der(0x30, b))
}
func spnegoOffer() []byte {
	mech := der(0xa0, der(0x30, ntlmOID))
	oid := []byte{6, 6, 0x2b, 6, 1, 5, 5, 2}
	return der(0x60, append(oid, der(0xa0, der(0x30, mech))...))
}
func windowsTime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10000000 + uint64(t.Nanosecond()/100)
}

type ntlmServer struct {
	user, domain, password string
	negotiate, challenge   []byte
	nonce                  [8]byte
	timestamp              uint64
	used                   bool
}

func (n *ntlmServer) start(blob []byte) ([]byte, error) {
	if n.negotiate != nil {
		return nil, errAuthentication
	}
	m, err := ntlmMessage(blob)
	if err != nil || len(m) < 32 || binary.LittleEndian.Uint32(m[8:]) != 1 {
		return nil, errAuthentication
	}
	flags := binary.LittleEndian.Uint32(m[12:])
	if flags&(ntlmUnicode|ntlmSign|ntlmNTLM|ntlmExtended) != (ntlmUnicode | ntlmSign | ntlmNTLM | ntlmExtended) {
		return nil, errAuthentication
	}
	if _, err := rand.Read(n.nonce[:]); err != nil {
		return nil, err
	}
	n.negotiate = m
	n.timestamp = windowsTime(time.Now())
	info := []byte{}
	av := func(id uint16, b []byte) {
		info = binary.LittleEndian.AppendUint16(info, id)
		info = binary.LittleEndian.AppendUint16(info, uint16(len(b)))
		info = append(info, b...)
	}
	av(1, utf16Bytes("TREX"))
	av(2, utf16Bytes(n.domain))
	av(7, binary.LittleEndian.AppendUint64(nil, n.timestamp))
	av(6, []byte{2, 0, 0, 0})
	av(0, nil)
	c := make([]byte, 56)
	copy(c, ntlmMagic)
	binary.LittleEndian.PutUint32(c[8:], 2)
	flags = flags&(ntlmKeyExchange|0xa0000000) | ntlmUnicode | ntlmSign | ntlmNTLM | ntlmExtended | ntlmTargetInfo | ntlmVersion | 4 | 0x8000
	binary.LittleEndian.PutUint32(c[20:], flags)
	copy(c[24:], n.nonce[:])
	copy(c[48:], []byte{10, 0, 0, 0, 0, 0, 0, 15})
	c = putSecurityBuffer(c, 12, utf16Bytes(n.domain))
	c = putSecurityBuffer(c, 40, info)
	n.challenge = c
	return spnegoReply(c, false), nil
}
func (n *ntlmServer) finish(blob []byte) ([]byte, error) {
	if n.challenge == nil || n.used {
		return nil, errAuthentication
	}
	n.used = true
	now := windowsTime(time.Now())
	if now < n.timestamp || now-n.timestamp > 5*60*10000000 {
		return nil, errAuthentication
	}
	m, err := ntlmMessage(blob)
	if err != nil || len(m) < 88 || binary.LittleEndian.Uint32(m[8:]) != 3 {
		return nil, errAuthentication
	}
	// Authenticate payloads may not alias the fixed header, version, or MIC.
	for _, off := range []int{12, 20, 28, 36, 44, 52} {
		if binary.LittleEndian.Uint16(m[off:]) != 0 && binary.LittleEndian.Uint32(m[off+4:]) < 88 {
			return nil, errAuthentication
		}
	}
	flags := binary.LittleEndian.Uint32(m[60:])
	required := ntlmUnicode | ntlmSign | ntlmNTLM | ntlmExtended | ntlmVersion
	if flags&required != required {
		return nil, errAuthentication
	}
	response, err := securityBuffer(m, 20)
	if err != nil || len(response) < 48 {
		return nil, errAuthentication
	}
	domainRaw, err := securityBuffer(m, 28)
	if err != nil {
		return nil, err
	}
	userRaw, err := securityBuffer(m, 36)
	if err != nil {
		return nil, err
	}
	domain, err := utf16String(domainRaw)
	if err != nil {
		return nil, err
	}
	user, err := utf16String(userRaw)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(user, n.user) || !strings.EqualFold(domain, n.domain) {
		return nil, errAuthentication
	}
	b := response[16:]
	if b[0] != 1 || b[1] != 1 || binary.LittleEndian.Uint64(b[8:]) != n.timestamp {
		return nil, errAuthentication
	}
	// Require the timestamp and MIC flag from the challenge target information.
	foundTime, foundMIC, terminated := false, false, false
	for at := 28; at+4 <= len(b); {
		id, size := binary.LittleEndian.Uint16(b[at:]), int(binary.LittleEndian.Uint16(b[at+2:]))
		at += 4
		if size > len(b)-at {
			return nil, errAuthentication
		}
		value := b[at : at+size]
		at += size
		if id == 0 {
			if size != 0 {
				return nil, errAuthentication
			}
			terminated = true
			break
		}
		if id == 7 {
			if size != 8 || binary.LittleEndian.Uint64(value) != n.timestamp || foundTime {
				return nil, errAuthentication
			}
			foundTime = true
		}
		if id == 6 {
			if size != 4 || binary.LittleEndian.Uint32(value)&2 == 0 || foundMIC {
				return nil, errAuthentication
			}
			foundMIC = true
		}
	}
	if !terminated || !foundTime || !foundMIC {
		return nil, errAuthentication
	}
	hash := ntlmV2Hash(user, domain, n.password)
	proof := hmacMD5(hash, n.nonce[:], b)
	if !hmac.Equal(proof, response[:16]) {
		return nil, errAuthentication
	}
	key := hmacMD5(hash, proof)
	encrypted, err := securityBuffer(m, 52)
	if err != nil {
		return nil, err
	}
	if flags&ntlmKeyExchange != 0 {
		if binary.LittleEndian.Uint32(n.challenge[20:])&ntlmKeyExchange == 0 || len(encrypted) != 16 {
			return nil, errAuthentication
		}
		cipher, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		key = make([]byte, 16)
		cipher.XORKeyStream(key, encrypted)
	} else if len(encrypted) != 0 {
		return nil, errAuthentication
	}
	mic := append([]byte(nil), m[72:88]...)
	clear(m[72:88])
	if !hmac.Equal(mic, hmacMD5(key, n.negotiate, n.challenge, m)) {
		return nil, errAuthentication
	}
	return key, nil
}
