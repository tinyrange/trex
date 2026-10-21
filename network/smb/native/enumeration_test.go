package native

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

func queryDir(c *testClient, id []byte, flags byte, pattern string, limit, status uint32) []byte {
	q := make([]byte, 32)
	wire.PutUint16(q, 33)
	q[2], q[3] = 37, flags // FILE_ID_BOTH_DIR_INFORMATION
	copy(q[8:], id)
	p := u16(pattern)
	wire.PutUint16(q[24:], 96)
	wire.PutUint16(q[26:], uint16(len(p)))
	wire.PutUint32(q[28:], limit)
	return c.call(14, append(q, p...), status)
}

func listingNames(t *testing.T, b []byte) []string {
	t.Helper()
	if len(b) < 8 || wire.Uint16(b[2:]) != 72 || int(wire.Uint32(b[4:])) != len(b)-8 {
		t.Fatal("invalid directory response")
	}
	b = b[8:]
	var names []string
	for len(b) > 0 {
		if len(b) < 104 {
			t.Fatal("short directory record")
		}
		n := int(wire.Uint32(b[60:]))
		if n%2 != 0 || n > len(b)-104 {
			t.Fatal("invalid name extent")
		}
		chars := make([]uint16, n/2)
		for i := range chars {
			chars[i] = wire.Uint16(b[104+i*2:])
		}
		names = append(names, string(utf16.Decode(chars)))
		next := int(wire.Uint32(b))
		if next == 0 {
			break
		}
		if next%8 != 0 || next < 104+n || next > len(b)-104 {
			t.Fatal("invalid next record")
		}
		b = b[next:]
	}
	return names
}

func TestExplorerDirectoryEnumeration(t *testing.T) {
	for _, child := range []bool{false, true} {
		for _, metadataFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("child=%t/metadataFirst=%t", child, metadataFirst), func(t *testing.T) {
				r, dir := rootFixture(t, false)
				name := ""
				if child {
					name = "child"
					dir = filepath.Join(dir, name)
					if e := os.Mkdir(dir, 0700); e != nil {
						t.Fatal(e)
					}
				}
				want := map[string]bool{}
				for i := 0; i < 137; i++ {
					n := fmt.Sprintf("entry-%03d-日.txt", i)
					if e := os.WriteFile(filepath.Join(dir, n), []byte("data"), 0600); e != nil {
						t.Fatal(e)
					}
					want[n] = true
				}
				c := protocolClient(t, r)
				var probe, enumerator []byte
				openProbe := func() {
					// Exact This PC root probe observed on Windows 11: attributes +
					// synchronize, no data access, no sharing, directory/backup intent.
					probe = c.openMode(name, 1, 0x800021, 0x100080, 0, 0)
				}
				openEnumerator := func() { enumerator = c.openAccess(name, 1, 0x20, 0x100081, 0) }
				if metadataFirst {
					openProbe()
					openEnumerator()
				} else {
					openEnumerator()
					openProbe()
				}
				// A second handle must have an independent enumeration cursor.
				other := c.openAccess(name, 1, 1, 0x100081, 0)
				first := listingNames(t, queryDir(c, other, 3, "entry-*", 512, 0))
				if len(first) != 1 || !want[first[0]] {
					t.Fatal("single entry", first)
				}
				c.close(other)
				for pass := 0; pass < 2; pass++ {
					seen := map[string]bool{}
					// Too-small buffers must preserve the pending entry for the next call.
					queryDir(c, enumerator, 1, "entry-*", 16, 0xc0000023)
					pages := 0
					for len(seen) < len(want) {
						pages++
						if pages > len(want) {
							t.Fatal("enumeration made no progress")
						}
						for _, n := range listingNames(t, queryDir(c, enumerator, 0, "", 512, 0)) {
							if !want[n] || seen[n] {
								t.Fatal("unexpected or duplicate entry", n)
							}
							seen[n] = true
						}
					}
					if pages < 2 {
						t.Fatal("pagination not exercised")
					}
					queryDir(c, enumerator, 0, "", 512, 0x80000006)
				}
				c.close(probe)
				c.close(enumerator)
			})
		}
	}
}

func TestMetadataProbeDoesNotDisableDataSharing(t *testing.T) {
	r, _ := rootFixture(t, false)
	c := protocolClient(t, r)
	data := c.openMode("Hello.txt", 1, 0x40, 0x120089, 0, 0)
	for _, access := range []uint32{0x100080, 0x100100} {
		probe := c.openMode("Hello.txt", 1, 0x40, access, 0, 0)
		c.close(probe)
	}
	for _, access := range []uint32{1, 2, 0x10000} {
		c.openMode("Hello.txt", 1, 0x40, access, 7, 0xc0000043)
	}
	c.close(data)
}
