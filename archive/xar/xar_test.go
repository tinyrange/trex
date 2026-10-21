package xar

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"io"
	"strings"
	"testing"
)

func fixture(t *testing.T, memberSize int, modify func(string) string) ([]byte, []byte) {
	t.Helper()
	plain := bytes.Repeat([]byte("member-data\n"), memberSize)
	var data bytes.Buffer
	z := zlib.NewWriter(&data)
	z.Write(plain)
	z.Close()
	stored := sha1.Sum(data.Bytes())
	expanded := sha1.Sum(plain)
	toc := fmt.Sprintf(`<xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum><file id="1"><name>dir</name><type>directory</type><mode>0755</mode><file id="2"><name>member</name><type>file</type><mode>0644</mode><uid>501</uid><gid>20</gid><data><offset>20</offset><length>%d</length><size>%d</size><encoding style="application/x-gzip"/><archived-checksum style="sha1">%s</archived-checksum><extracted-checksum style="sha1">%s</extracted-checksum></data></file><file id="3"><name>alias</name><type link="2">hardlink</type></file><file id="4"><name>link</name><type>symlink</type><link>member</link></file></file></toc></xar>`, data.Len(), len(plain), hex.EncodeToString(stored[:]), hex.EncodeToString(expanded[:]))
	if modify != nil {
		toc = modify(toc)
	}
	var packed bytes.Buffer
	z = zlib.NewWriter(&packed)
	z.Write([]byte(toc))
	z.Close()
	digest := sha1.Sum(packed.Bytes())
	h := make([]byte, 28)
	copy(h, "xar!")
	binary.BigEndian.PutUint16(h[4:], 28)
	binary.BigEndian.PutUint16(h[6:], 1)
	binary.BigEndian.PutUint64(h[8:], uint64(packed.Len()))
	binary.BigEndian.PutUint64(h[16:], uint64(len(toc)))
	binary.BigEndian.PutUint32(h[24:], 1)
	b := append(h, packed.Bytes()...)
	b = append(b, digest[:]...)
	b = append(b, data.Bytes()...)
	return b, plain
}
func TestMembersLinksAndChecksums(t *testing.T) {
	b, plain := fixture(t, 150000, nil)
	a, err := Open(bytes.NewReader(b), 100)
	if err != nil {
		t.Fatal(err)
	}
	e := a.Entries[1]
	if e.Path != "dir/member" || e.UID != 501 || e.Mode != 0644 {
		t.Fatalf("metadata %+v", e)
	}
	for _, off := range []int64{int64(len(plain) - 8), 100, 110, 0} {
		var p [8]byte
		if _, err := e.Data.ReadAt(p[:], off); err != nil || !bytes.Equal(p[:], plain[off:off+8]) {
			t.Fatalf("read %d %x %v", off, p, err)
		}
	}
	if a.Entries[2].Data != e.Data || a.Entries[2].Target != e.Path || a.Entries[3].Target != "member" {
		t.Fatal("link metadata")
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
	result, err := auto.Identify(bytes.NewReader(b), auto.Options{})
	if err != nil || result.Format != "xar" {
		t.Fatalf("auto %v %v", result, err)
	}
}
func TestRejectUnsafeMetadataAndLimits(t *testing.T) {
	for _, change := range []func(string) string{
		func(s string) string { return strings.Replace(s, "<name>member</name>", "<name>../escape</name>", 1) },
		func(s string) string {
			return strings.Replace(s, "<offset>20</offset>", "<offset>999999999999</offset>", 1)
		},
		func(s string) string { return strings.Replace(s, `id="3"`, `id="2"`, 1) },
		func(s string) string { return strings.Replace(s, `link="2"`, `link="3"`, 1) },
	} {
		b, _ := fixture(t, 10, change)
		if _, err := Open(bytes.NewReader(b), 100); err == nil {
			t.Fatal("accepted malformed TOC")
		}
	}
	b, _ := fixture(t, 10, nil)
	if _, err := Open(bytes.NewReader(b), 1); err == nil {
		t.Fatal("entry cap")
	}
	b[len(b)-1] ^= 1
	a, err := Open(bytes.NewReader(b), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Entries[1].Verify(); err == nil {
		t.Fatal("accepted corrupt member")
	}
}
func TestRejectTOCChecksum(t *testing.T) {
	b, _ := fixture(t, 1, nil)
	offset := 28 + int(binary.BigEndian.Uint64(b[8:]))
	b[offset] ^= 1
	if _, err := Open(bytes.NewReader(b), 100); err == nil {
		t.Fatal("accepted corrupt TOC checksum")
	}
}
func TestZlibSizeAndTrailingValidation(t *testing.T) {
	for _, kind := range []string{"short", "long", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			var b bytes.Buffer
			z := zlib.NewWriter(&b)
			z.Write([]byte("abcd"))
			z.Close()
			size := int64(4)
			if kind == "short" {
				size = 3
			}
			if kind == "long" {
				size = 5
			}
			if kind == "trailing" {
				b.WriteByte(7)
			}
			f := &zlibFile{source: bytes.NewReader(b.Bytes()), size: size}
			if _, err := io.ReadAll(io.NewSectionReader(f, 0, size)); err == nil {
				t.Fatal("accepted zlib size/trailing mismatch")
			}
		})
	}
}
