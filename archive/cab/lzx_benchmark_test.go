package cab

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/tinyrange/trex/compression/lzx"
	"github.com/tinyrange/trex/filesystem/iso9660"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// BenchmarkLZXMedia measures only decoder throughput, including its allocations.
// ISO and CAB parsing and compressed-data reads happen outside the timer. No
// media bytes are extracted to the host. Opt in with CAB_LZX_ISO and a comma-
// separated CAB_LZX_MEMBERS list of paths inside that ISO.
func BenchmarkLZXMedia(b *testing.B) {
	name := os.Getenv("CAB_LZX_ISO")
	if name == "" {
		b.Skip("set CAB_LZX_ISO and CAB_LZX_MEMBERS")
	}
	f, err := os.Open(name)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		b.Fatal(err)
	}
	image, err := iso9660.ISO9660Builtin(nil, nil, starlark.Tuple{&lzxBenchmarkFile{File: f, size: info.Size()}}, nil)
	if err != nil {
		b.Fatal(err)
	}
	members := os.Getenv("CAB_LZX_MEMBERS")
	if members == "" {
		b.Fatal("set CAB_LZX_MEMBERS to CAB paths inside the ISO")
	}
	for _, member := range strings.Split(members, ",") {
		value, found, err := image.(starlark.Mapping).Get(starlark.String(member))
		if err != nil || !found {
			b.Fatalf("member %s: found=%v err=%v", member, found, err)
		}
		archive, err := Open(value.(starfile.File), false)
		if err != nil {
			b.Fatal(err)
		}
		lzxFolders := 0
		for index, folder := range archive.folders {
			if folder.compression&15 != 3 {
				continue
			}
			lzxFolders++
			blocks, err := archive.readFolderDataBlocks(folder)
			if err != nil {
				b.Fatal(err)
			}
			input, size := cabinetBlocksPayload(blocks)
			bits := int(folder.compression >> 8)
			b.Run(fmt.Sprintf("%s/folder%d", member, index), func(b *testing.B) {
				want, err := lzx.Decompress(input, bits, size)
				if err != nil {
					b.Fatal(err)
				}
				hash := sha256.Sum256(want)
				b.Logf("compressed=%d output=%d window=%d sha256=%x", len(input), size, bits, hash)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				var out []byte
				for i := 0; i < b.N; i++ {
					out, err = lzx.Decompress(input, bits, size)
					if err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				if sha256.Sum256(out) != hash {
					b.Fatal("unstable decoded output")
				}
			})
		}
		if lzxFolders == 0 {
			b.Fatalf("%s has no LZX folders", member)
		}
	}
}

type lzxBenchmarkFile struct {
	*os.File
	size int64
}

func (f *lzxBenchmarkFile) Size() int64         { return f.size }
func (*lzxBenchmarkFile) String() string        { return "<benchmark ISO>" }
func (*lzxBenchmarkFile) Type() string          { return "file" }
func (*lzxBenchmarkFile) Freeze()               {}
func (*lzxBenchmarkFile) Truth() starlark.Bool  { return starlark.True }
func (*lzxBenchmarkFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable file") }
