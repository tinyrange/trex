package nsis

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/filesystem/iso9660"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"hash/crc32"
	"os"
	"testing"
)

type uninstallerMedia struct {
	*os.File
	size int64
}

func (m uninstallerMedia) Size() int64 { return m.size }
func TestUninstallerMedia(t *testing.T) {
	path := os.Getenv("TREX_NSIS_TEST_ISO")
	if path == "" {
		t.Skip("explicit media required")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	image, err := iso9660.ISO9660Builtin(nil, nil, starlark.Tuple{adapter.File(uninstallerMedia{f, stat.Size()})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	source, ok, err := image.(starlark.Mapping).Get(starlark.String("/browsers/Netscape 8.0.2/nsb-install-8-0.exe"))
	if err != nil || !ok {
		t.Fatal("missing media")
	}
	a, err := Open(source.(storage.Reader), Options{}, 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	output, err := a.Uninstaller(1261)
	if err != nil {
		t.Fatal(err)
	}
	if output.Size() != 68000 {
		t.Fatalf("uninstaller size %d", output.Size())
	}
	listing, err := List(output, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if listing.HeaderOffset != 37888 || listing.HeaderSize != 8755 {
		t.Fatalf("uninstaller header %+v", listing)
	}
	data := output.(*starfile.Bytes).Data
	if binary.LittleEndian.Uint32(data[len(data)-4:]) != crc32.ChecksumIEEE(data[512:len(data)-4]) {
		t.Fatal("bad uninstall CRC")
	}
	original := make([]byte, a.source.Size())
	if err := readAt(a.source, original, 0); err != nil {
		t.Fatal(err)
	}
	end := a.Listing.HeaderOffset + a.Listing.ContainerSize
	if binary.LittleEndian.Uint32(original[end-4:]) != crc32.ChecksumIEEE(original[512:end-4]) {
		t.Fatal("source CRC convention differs")
	}
}

func TestUninstallerPatchBounds(t *testing.T) {
	stub := []byte("abcdefgh")
	patch := []byte{2, 0, 0, 0, 3, 0, 0, 0, 'X', 'Y', 0, 0, 0, 0}
	if err := applyStubPatch(stub, patch); err != nil || string(stub) != "abcXYfgh" {
		t.Fatalf("patch: %s %v", stub, err)
	}
	for _, bad := range [][]byte{patch[:9], patch[:13], append(bytes.Clone(patch), 0), {1, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0}} {
		if err := applyStubPatch(make([]byte, 8), bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}
