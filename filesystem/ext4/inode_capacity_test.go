package ext4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func readImageRegion(t *testing.T, image storage.Reader, offset int64, length int) []byte {
	t.Helper()
	data := make([]byte, length)
	if _, err := image.ReadAt(data, offset); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBuildReservedInodeBitmapsAndTables(t *testing.T) {
	input := []unixfs.Entry{
		{Path: "dir/file", Mode: unixfs.Regular | 0644, Data: bytes.NewReader([]byte("payload"))},
		{Path: "alias", Mode: unixfs.Regular | 0644, Target: "dir/file", Hardlink: true},
	}
	image, err := Build(input, BuildOptions{Size: 256 << 20, InodeCount: 4097})
	if err != nil {
		t.Fatal(err)
	}
	sb := readImageRegion(t, image, 1024, 1024)
	// Two groups, with 2080 inodes each after the requested minimum is rounded.
	// Reserved inodes 1..10 include the root; the directory and file use 11,12.
	if got := binary.LittleEndian.Uint32(sb); got != 4160 {
		t.Fatalf("inode capacity = %d, want 4160", got)
	}
	if got := binary.LittleEndian.Uint32(sb[16:]); got != 4148 {
		t.Fatalf("free inode count = %d, want 4148", got)
	}
	for group := 0; group < 2; group++ {
		desc := readImageRegion(t, image, 4096+int64(group)*32, 32)
		bitmapBlock := binary.LittleEndian.Uint32(desc[4:])
		bitmap := readImageRegion(t, image, int64(bitmapBlock)*4096, 4096)
		allocated := 0
		if group == 0 {
			allocated = 12
		}
		if got := binary.LittleEndian.Uint16(desc[14:]); int(got) != 2080-allocated {
			t.Fatalf("group %d free inode count = %d", group, got)
		}
		for index := 0; index < 32768; index++ {
			set := bitmap[index/8]&(1<<uint(index%8)) != 0
			if want := index < allocated || index >= 2080; set != want {
				t.Fatalf("group %d bitmap bit %d = %v, want %v", group, index, set, want)
			}
		}
		tableBlock := binary.LittleEndian.Uint32(desc[8:])
		unused := readImageRegion(t, image, int64(tableBlock)*4096+int64(allocated)*256, (2080-allocated)*256)
		if !bytes.Equal(unused, make([]byte, len(unused))) {
			t.Fatalf("group %d unused inode records are not zero", group)
		}
		if group == 1 {
			backup := readImageRegion(t, image, 128<<20, 1024)
			if binary.LittleEndian.Uint32(backup) != 4160 || binary.LittleEndian.Uint32(backup[16:]) != 4148 {
				t.Fatal("backup superblock lost inode capacity")
			}
		}
	}
}

func TestBuildInodeCapacityFloorPreservesDefault(t *testing.T) {
	var input []unixfs.Entry
	for index := 0; index < 200; index++ {
		input = append(input, unixfs.Entry{Path: fmt.Sprintf("file-%03d", index), Mode: unixfs.Regular | 0644})
	}
	var images [][]byte
	for _, minimum := range []int64{0, 1} {
		image, err := Build(input, BuildOptions{Size: 8 << 20, InodeCount: minimum})
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.NewSectionReader(image, 0, image.Size()))
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint32(data[1024:]); got != 224 {
			t.Fatalf("automatic inode capacity = %d, want 224", got)
		}
		images = append(images, data)
	}
	if !bytes.Equal(images[0], images[1]) {
		t.Fatal("minimum below input requirements changed the default image")
	}
}

func TestBuildInodeCapacityForWritableBuildRoot(t *testing.T) {
	image, err := Build(nil, BuildOptions{Size: 8 << 30, InodeCount: 400000})
	if err != nil {
		t.Fatal(err)
	}
	sb := readImageRegion(t, image, 1024, 1024)
	if binary.LittleEndian.Uint32(sb) != 401408 || binary.LittleEndian.Uint32(sb[16:]) != 401398 {
		t.Fatal("build root did not retain rounded capacity and free inodes")
	}
	if image.Size() != 8<<30 {
		t.Fatal("inode reservation changed disk capacity")
	}
}

func TestBuildInodeCapacityRejectsOverflowAndBounds(t *testing.T) {
	for _, test := range []struct {
		name, message string
		size, inodes  int64
	}{
		{"negative", "inode_count", 8 << 20, -1},
		{"uint32 overflow", "inode_count", 8 << 30, 1 << 32},
		{"int64 maximum", "inode_count", 8 << 30, math.MaxInt64},
		{"group bitmap", "metadata capacity", 128 << 20, 32769},
		{"metadata memory", "metadata capacity", 8 << 30, 2000000},
		{"rounded total overflow", "metadata capacity", int64(math.MaxUint32) * 4096, math.MaxUint32},
		{"inode tables exhaust disk", "no data space", 8 << 20, 32768},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Build(nil, BuildOptions{Size: test.size, InodeCount: test.inodes})
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Build: got %v, want %q", err, test.message)
			}
		})
	}
}

func TestBuildBuiltinInodeCapacity(t *testing.T) {
	args := starlark.Tuple{starlark.NewList(nil), starlark.MakeInt64(8 << 20)}
	kwargs := []starlark.Tuple{{starlark.String("inode_count"), starlark.MakeInt(511)}}
	value, err := BuildBuiltin(nil, nil, args, kwargs)
	if err != nil {
		t.Fatal(err)
	}
	image, ok := value.(storage.Reader)
	if !ok {
		t.Fatalf("builtin returned %T", value)
	}
	sb := readImageRegion(t, image, 1024, 1024)
	if binary.LittleEndian.Uint32(sb) != 512 || binary.LittleEndian.Uint32(sb[16:]) != 502 {
		t.Fatal("Starlark minimum did not reach the inode allocation")
	}
	for _, minimum := range []starlark.Value{starlark.MakeInt(-1), starlark.MakeInt64(1 << 32), starlark.String("512")} {
		kwargs[0][1] = minimum
		if _, err := BuildBuiltin(nil, nil, args, kwargs); err == nil {
			t.Fatalf("accepted invalid Starlark inode_count %s", minimum)
		}
	}
}
