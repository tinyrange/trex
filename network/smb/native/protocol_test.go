package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"github.com/tinyrange/trex/network/smb"
	"golang.org/x/crypto/md4"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

var wire = binary.LittleEndian

func u16(s string) []byte {
	var out []byte
	for _, c := range utf16.Encode([]rune(s)) {
		out = wire.AppendUint16(out, c)
	}
	return out
}
func md(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func sec(b []byte, at int, data []byte) []byte {
	wire.PutUint16(b[at:], uint16(len(data)))
	wire.PutUint16(b[at+2:], uint16(len(data)))
	wire.PutUint32(b[at+4:], uint32(len(b)))
	return append(b, data...)
}

type testClient struct {
	server  *smb.Server
	t       *testing.T
	c       net.Conn
	id, sid uint64
	key     []byte
	tree    uint32
}

func (c *testClient) call(cmd uint16, body []byte, status uint32) []byte {
	c.t.Helper()
	msg := make([]byte, 64)
	copy(msg, []byte{254, 'S', 'M', 'B'})
	wire.PutUint16(msg[4:], 64)
	wire.PutUint16(msg[12:], cmd)
	wire.PutUint16(msg[14:], 32)
	wire.PutUint64(msg[24:], c.id)
	c.id++
	wire.PutUint32(msg[36:], c.tree)
	wire.PutUint64(msg[40:], c.sid)
	msg = append(msg, body...)
	if c.key != nil {
		wire.PutUint32(msg[16:], 8)
		h := hmac.New(sha256.New, c.key)
		h.Write(msg)
		copy(msg[48:], h.Sum(nil)[:16])
	}
	prefix := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	if _, e := c.c.Write(append(prefix, msg...)); e != nil {
		c.t.Fatal(e)
	}
	if _, e := io.ReadFull(c.c, prefix); e != nil {
		c.t.Fatal(e)
	}
	n := int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3])
	if n < 64 || n > 2<<20 {
		c.t.Fatal("bad frame", n)
	}
	reply := make([]byte, n)
	if _, e := io.ReadFull(c.c, reply); e != nil {
		c.t.Fatal(e)
	}
	if got := wire.Uint32(reply[8:]); got != status {
		c.t.Fatalf("command %d status %08x want %08x", cmd, got, status)
	}
	if wire.Uint32(reply[16:])&8 != 0 {
		sig := append([]byte(nil), reply[48:64]...)
		clear(reply[48:64])
		h := hmac.New(sha256.New, c.key)
		h.Write(reply)
		if !hmac.Equal(sig, h.Sum(nil)[:16]) {
			c.t.Fatal("bad reply signature")
		}
	} else if c.key != nil {
		c.t.Fatal("unsigned reply")
	}
	if cmd == 1 {
		c.sid = wire.Uint64(reply[40:])
	}
	if cmd == 3 {
		c.tree = wire.Uint32(reply[36:])
	}
	return reply[64:]
}
func protocolClient(t *testing.T, r *Root) *testClient {
	t.Helper()
	server, e := smb.NewServer(smb.Config{User: "User", Domain: "Domain", Password: "Password", Share: "cwd", Files: r})
	if e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(10 * time.Second))
	done := make(chan error, 1)
	go func() { done <- server.Serve(b) }()
	t.Cleanup(func() { a.Close(); server.Close(); <-done })
	c := &testClient{t: t, c: a, server: server}
	neg := make([]byte, 38)
	wire.PutUint16(neg, 36)
	wire.PutUint16(neg[2:], 1)
	wire.PutUint16(neg[4:], 1)
	wire.PutUint16(neg[36:], 0x210)
	c.call(0, neg, 0)
	ntlm := make([]byte, 40)
	copy(ntlm, "NTLMSSP\x00")
	wire.PutUint32(ntlm[8:], 1)
	wire.PutUint32(ntlm[12:], 0xa2088215) // no key exchange
	setup := func(token []byte) []byte {
		b := make([]byte, 24)
		wire.PutUint16(b, 25)
		b[3] = 1
		wire.PutUint16(b[12:], 88)
		wire.PutUint16(b[14:], uint16(len(token)))
		return append(b, token...)
	}
	reply := c.call(1, setup(ntlm), 0xc0000016)
	at := bytes.Index(reply, []byte("NTLMSSP\x00"))
	if at < 0 {
		t.Fatal("missing challenge")
	}
	challenge := reply[at:]
	off, n := int(wire.Uint32(challenge[44:])), int(wire.Uint16(challenge[40:]))
	challenge = challenge[:off+n]
	info := challenge[off:]
	blob := make([]byte, 28)
	blob[0], blob[1] = 1, 1
	copy(blob[16:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	for at := 0; at+4 <= len(info); {
		id, n := wire.Uint16(info[at:]), int(wire.Uint16(info[at+2:]))
		at += 4
		if id == 7 {
			copy(blob[8:16], info[at:at+n])
		}
		at += n
	}
	blob = append(blob, info...)
	blob = append(blob, 0, 0, 0, 0)
	hash := md4.New()
	hash.Write(u16("Password"))
	v2 := md(hash.Sum(nil), u16("USERDomain"))
	proof := md(v2, challenge[24:32], blob)
	c.key = md(v2, proof)
	auth := make([]byte, 88)
	copy(auth, "NTLMSSP\x00")
	wire.PutUint32(auth[8:], 3)
	wire.PutUint32(auth[60:], wire.Uint32(challenge[20:]))
	auth = sec(auth, 12, make([]byte, 24))
	auth = sec(auth, 20, append(proof, blob...))
	auth = sec(auth, 28, u16("Domain"))
	auth = sec(auth, 36, u16("User"))
	auth = sec(auth, 44, u16("CLIENT"))
	auth = sec(auth, 52, nil)
	copy(auth[72:88], md(c.key, ntlm, challenge, auth))
	// The final auth request is unsigned; only its response uses the new key.
	c.authCall(setup(auth))
	tree := make([]byte, 8)
	wire.PutUint16(tree, 9)
	wire.PutUint16(tree[4:], 72)
	name := u16(`\\10.42.0.1\cwd`)
	wire.PutUint16(tree[6:], uint16(len(name)))
	c.call(3, append(tree, name...), 0)
	return c
}
func (c *testClient) authCall(body []byte) {
	// Construct final SESSION_SETUP without SMB signing, then verify its reply.
	msg := make([]byte, 64)
	copy(msg, []byte{254, 'S', 'M', 'B'})
	wire.PutUint16(msg[4:], 64)
	wire.PutUint16(msg[12:], 1)
	wire.PutUint16(msg[14:], 32)
	wire.PutUint64(msg[24:], c.id)
	c.id++
	wire.PutUint64(msg[40:], c.sid)
	msg = append(msg, body...)
	prefix := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	if _, err := c.c.Write(append(prefix, msg...)); err != nil {
		c.t.Fatal(err)
	}
	if _, e := io.ReadFull(c.c, prefix); e != nil {
		c.t.Fatal(e)
	}
	n := int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3])
	if n < 64 || n > 65536 {
		c.t.Fatal(n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c.c, b); err != nil {
		c.t.Fatal(err)
	}
	if wire.Uint32(b[8:]) != 0 {
		c.t.Fatalf("auth %x", b[8:12])
	}
	sig := append([]byte(nil), b[48:64]...)
	clear(b[48:64])
	h := hmac.New(sha256.New, c.key)
	h.Write(b)
	if !hmac.Equal(sig, h.Sum(nil)[:16]) {
		c.t.Fatal("auth signature")
	}
}
func (c *testClient) open(name string, disposition, options uint32, status uint32) []byte {
	return c.openAccess(name, disposition, options, 0x0013019f, status)
}
func (c *testClient) openAccess(name string, disposition, options, access, status uint32) []byte {
	return c.openMode(name, disposition, options, access, 7, status)
}
func (c *testClient) openMode(name string, disposition, options, access, share, status uint32) []byte {
	b := make([]byte, 56)
	wire.PutUint16(b, 57)
	wire.PutUint32(b[4:], 2)
	wire.PutUint32(b[24:], access)
	wire.PutUint32(b[32:], share)
	wire.PutUint32(b[36:], disposition)
	wire.PutUint32(b[40:], options)
	raw := u16(name)
	wire.PutUint16(b[44:], 120)
	wire.PutUint16(b[46:], uint16(len(raw)))
	r := c.call(5, append(b, raw...), status)
	if status != 0 {
		return nil
	}
	return append([]byte(nil), r[64:80]...)
}
func (c *testClient) close(id []byte) {
	b := make([]byte, 24)
	wire.PutUint16(b, 24)
	copy(b[8:], id)
	c.call(6, b, 0)
}
func (c *testClient) set(id []byte, class byte, data []byte, status uint32) {
	b := make([]byte, 32)
	wire.PutUint16(b, 33)
	b[2], b[3] = 1, class
	wire.PutUint32(b[4:], uint32(len(data)))
	wire.PutUint16(b[8:], 96)
	copy(b[16:], id)
	c.call(17, append(b, data...), status)
}
func TestSignedFileOperations(t *testing.T) {
	r, dir := rootFixture(t, false)
	c := protocolClient(t, r)
	id := c.open("transfer.bin", 2, 0x200040, 0)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	for i := 0; i < 3; i++ {
		b := make([]byte, 48)
		wire.PutUint16(b, 49)
		wire.PutUint16(b[2:], 112)
		wire.PutUint32(b[4:], uint32(len(payload)))
		wire.PutUint64(b[8:], uint64(i*len(payload)))
		copy(b[16:], id)
		c.call(9, append(b, payload...), 0)
	}
	b := make([]byte, 48)
	wire.PutUint16(b, 49)
	wire.PutUint32(b[4:], uint32(len(payload)))
	wire.PutUint64(b[8:], uint64(len(payload)))
	copy(b[16:], id)
	reply := c.call(8, b, 0)
	if !bytes.Equal(reply[16:], payload) {
		t.Fatal("read mismatch")
	}
	rename := make([]byte, 20)
	name := u16("renamed.bin")
	wire.PutUint32(rename[16:], uint32(len(name)))
	c.set(id, 10, append(rename, name...), 0)
	c.set(id, 20, wire.AppendUint64(nil, 100000), 0)
	c.close(id)
	got, e := os.ReadFile(filepath.Join(dir, "renamed.bin"))
	if e != nil || len(got) != 100000 || !bytes.Equal(got, bytes.Repeat([]byte("0123456789abcdef"), 6250)) {
		t.Fatal("host persistence", len(got), e)
	}
	d := c.open("", 1, 1, 0)
	q := make([]byte, 32)
	wire.PutUint16(q, 33)
	q[2], q[3] = 37, 1
	copy(q[8:], d)
	wire.PutUint16(q[24:], 96)
	wire.PutUint16(q[26:], 2)
	wire.PutUint32(q[28:], 65536)
	listing := c.call(14, append(q, '*', 0), 0)
	if !bytes.Contains(listing, u16("renamed.bin")) {
		t.Fatal("missing listing")
	}
	c.close(d)
	id = c.open("renamed.bin", 1, 0x40, 0)
	c.set(id, 13, []byte{1}, 0)
	c.close(id)
	if _, e := os.Stat(filepath.Join(dir, "renamed.bin")); !os.IsNotExist(e) {
		t.Fatal("delete", e)
	}
	c.open(`..\escape`, 2, 0x40, 0xc0000033)
}

func TestSignedReadOnlyShare(t *testing.T) {
	r, dir := rootFixture(t, true)
	original := []byte("host data")
	if err := os.WriteFile(filepath.Join(dir, "existing.txt"), original, 0600); err != nil {
		t.Fatal(err)
	}
	c := protocolClient(t, r)
	id := c.openAccess("existing.txt", 1, 0x40, 0x120089, 0)
	b := make([]byte, 48)
	wire.PutUint16(b, 49)
	wire.PutUint32(b[4:], 4096)
	copy(b[16:], id)
	reply := c.call(8, b, 0)
	if !bytes.Equal(reply[16:], original) {
		t.Fatal("read-only read mismatch")
	}
	wire.PutUint16(b[2:], 112)
	wire.PutUint32(b[4:], 1)
	c.call(9, append(b, 'x'), 0xc0000022)
	c.set(id, 20, wire.AppendUint64(nil, 0), 0xc0000022)
	c.set(id, 13, []byte{1}, 0xc0000022)
	c.close(id)
	c.open("existing.txt", 5, 0x40, 0xc0000022)
	c.open("created.txt", 2, 0x40, 0xc0000022)
	got, err := os.ReadFile(filepath.Join(dir, "existing.txt"))
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("read-only host mutation", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "created.txt")); !os.IsNotExist(err) {
		t.Fatal("created on read-only share", err)
	}
}

func TestServerCloseReleasesIdleHandles(t *testing.T) {
	r, dir := rootFixture(t, false)
	c := protocolClient(t, r)
	id := c.open("pending.txt", 2, 0x40, 0)
	c.set(id, 13, []byte{1}, 0)
	done := make(chan error, 1)
	go func() { done <- c.server.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server shutdown blocked on idle connection")
	}
	if _, err := os.Stat(filepath.Join(dir, "pending.txt")); !os.IsNotExist(err) {
		t.Fatal("open delete-pending handle leaked", err)
	}
	a, b := net.Pipe()
	defer a.Close()
	if err := c.server.Serve(b); err == nil {
		t.Fatal("closed server accepted connection")
	}
}
