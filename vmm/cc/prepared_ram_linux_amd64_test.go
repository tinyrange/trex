//go:build linux && amd64

package cc

import (
	"testing"

	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"golang.org/x/sys/unix"
)

func TestPreparedRAMPrivateMappings(t *testing.T) {
	const page = 4096
	image := filesystem.NewGeneratedImage("test RAM", 3*page, []filesystem.ExtentSpec{
		{Start: page, Size: 1, File: &starfile.Bytes{Data: []byte{42}}},
	})
	template, err := prepareRAM(image, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = template.Close() })
	mapping := func() []byte {
		// The trailing page belongs to another accelerator memory region.
		mem, err := unix.Mmap(-1, 0, 4*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Munmap(mem) })
		mem[3*page] = 19
		if err := template.mapPrivate(mem[:3*page]); err != nil {
			t.Fatal(err)
		}
		return mem
	}
	left, right := mapping(), mapping()
	left[0], left[page], left[2*page] = 1, 2, 3
	if right[0] != 0 || right[page] != 42 || right[2*page] != 0 || left[3*page] != 19 {
		t.Fatal("private RAM writes escaped the mapping or changed its trailing region")
	}
	if err := template.Close(); err != nil {
		t.Fatal(err)
	}
	if right[page] != 42 || left[page] != 2 {
		t.Fatal("closing the template invalidated an existing mapping")
	}
}
