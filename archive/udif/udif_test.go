package udif

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"hash/crc32"
	"io"
	"strings"
	"testing"
)

func fixture(t *testing.T, mutate func([]byte), corrupt bool) []byte {
	t.Helper()
	plain := bytes.Repeat([]byte{0x57}, 512)
	var packed bytes.Buffer
	z := zlib.NewWriter(&packed)
	z.Write(plain)
	z.Close()
	data := append(bytes.Repeat([]byte{0x41}, 512), packed.Bytes()...)
	if corrupt {
		data[len(data)-1] ^= 1
	}
	be := binary.BigEndian
	raw := make([]byte, 204+4*40)
	copy(raw, "mish")
	be.PutUint32(raw[4:], 1)
	be.PutUint64(raw[16:], 3)
	be.PutUint32(raw[200:], 4)
	kinds := []uint32{1, 0x80000005, 2, 0xffffffff}
	for i, k := range kinds {
		p := raw[204+i*40:]
		be.PutUint32(p, k)
		be.PutUint64(p[8:], uint64(i))
		if i < 3 {
			be.PutUint64(p[16:], 1)
		}
	}
	be.PutUint64(raw[204+32:], 512)
	be.PutUint64(raw[244+24:], 512)
	be.PutUint64(raw[244+32:], uint64(packed.Len()))
	logical := append(bytes.Repeat([]byte{0x41}, 512), plain...)
	be.PutUint32(raw[64:], 2)
	be.PutUint32(raw[68:], 32)
	be.PutUint32(raw[72:], crc32.ChecksumIEEE(logical))
	if mutate != nil {
		mutate(raw)
	}
	metadata := []byte(fmt.Sprintf(`<plist><dict><key>resource-fork</key><dict><key>blkx</key><array><dict><key>Name</key><string>fixture</string><key>Data</key><data>%s</data></dict></array></dict></dict></plist>`, base64.StdEncoding.EncodeToString(raw)))
	h := make([]byte, 512)
	copy(h, "koly")
	be.PutUint32(h[4:], 4)
	be.PutUint32(h[8:], 512)
	be.PutUint32(h[56:], 1)
	be.PutUint32(h[60:], 1)
	be.PutUint64(h[32:], uint64(len(data)))
	be.PutUint64(h[216:], uint64(len(data)))
	be.PutUint64(h[224:], uint64(len(metadata)))
	be.PutUint64(h[492:], 3)
	be.PutUint32(h[80:], 2)
	be.PutUint32(h[84:], 32)
	be.PutUint32(h[88:], crc32.ChecksumIEEE(data))
	return append(append(data, metadata...), h...)
}
func TestDiskRangesAndChecksums(t *testing.T) {
	d, err := Open(bytes.NewReader(fixture(t, nil, false)))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 40)
	n, err := d.ReadAt(b, 500)
	if err != nil || n != 40 || !bytes.Equal(b[:12], bytes.Repeat([]byte{0x41}, 12)) || !bytes.Equal(b[12:], bytes.Repeat([]byte{0x57}, 28)) {
		t.Fatalf("cross-run read %x %d %v", b, n, err)
	}
	d.ReadAt(b, 1500)
	if !bytes.Equal(b[:36], make([]byte, 36)) {
		t.Fatal("zero-filled range")
	}
	if _, err = d.ReadAt(b, 1530); err != io.EOF {
		t.Fatal("EOF", err)
	}
	if _, err = d.ReadAt(b, -1); err == nil {
		t.Fatal("negative offset")
	}
	if err = d.Verify(); err != nil {
		t.Fatal(err)
	}
	if d.cache.Stats().Hits == 0 {
		t.Fatal("chunk not reused")
	}
}
func TestRejectMalformedMaps(t *testing.T) {
	for name, fn := range map[string]func([]byte){
		"overlap":       func(b []byte) { binary.BigEndian.PutUint64(b[244+8:], 0) },
		"stored-bounds": func(b []byte) { binary.BigEndian.PutUint64(b[204+24:], 1<<63) },
		"run-count":     func(b []byte) { binary.BigEndian.PutUint32(b[200:], 100) },
		"terminator":    func(b []byte) { binary.BigEndian.PutUint32(b[324:], 2) },
		"codec":         func(b []byte) { binary.BigEndian.PutUint32(b[244:], 0x80000007) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(bytes.NewReader(fixture(t, fn, false))); err == nil {
				t.Fatal("accepted malformed map")
			}
		})
	}
}
func TestCorruptCompressedChunk(t *testing.T) {
	d, err := Open(bytes.NewReader(fixture(t, nil, true)))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := d.ReadAt(b, 512); err == nil {
		t.Fatal("accepted corrupt zlib checksum")
	}
}
func TestXMLDepthBound(t *testing.T) {
	if _, err := parseXML([]byte(strings.Repeat("<a>", 100) + strings.Repeat("</a>", 100))); err == nil {
		t.Fatal("accepted excessive XML depth")
	}
}
func TestAutoDecodedDisk(t *testing.T) {
	b := fixture(t, nil, false)
	result, err := auto.Identify(bytes.NewReader(b), auto.Options{})
	if err != nil || result.Format != "udif" {
		t.Fatalf("identify: %v %v", result, err)
	}
	if result.View.(*auto.DecodedView).Reader.Size() != 1536 {
		t.Fatal("logical size")
	}
}

func TestExplicitZeroVersusIgnoreAndMasterChecksum(t *testing.T) {
	var tableCRC uint32
	b := fixture(t, func(raw []byte) {
		binary.BigEndian.PutUint32(raw[284:], 0) // Explicit zero-fill, not ignore.
		logical := append(bytes.Repeat([]byte{0x41}, 512), bytes.Repeat([]byte{0x57}, 512)...)
		logical = append(logical, make([]byte, 512)...)
		tableCRC = crc32.ChecksumIEEE(logical)
		binary.BigEndian.PutUint32(raw[72:], tableCRC)
	}, false)
	trailer := b[len(b)-512:]
	binary.BigEndian.PutUint32(trailer[352:], 2)
	binary.BigEndian.PutUint32(trailer[356:], 32)
	binary.BigEndian.PutUint32(trailer[360:], crc32.ChecksumIEEE(binary.BigEndian.AppendUint32(nil, tableCRC)))
	d, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(); err != nil {
		t.Fatal(err)
	}
	trailer[360] ^= 1
	d, err = Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(); err == nil {
		t.Fatal("corrupt master checksum accepted")
	}
}
