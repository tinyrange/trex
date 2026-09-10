package wim

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/tinyrange/trex/compression/lzx"
	"github.com/tinyrange/trex/filesystem/iso9660"
	"github.com/tinyrange/trex/filesystem/udf"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// BenchmarkLZXMedia decodes a deterministic sample of up to 256 compressed
// chunks from an LZX WIM. ISO/WIM reads and output hashing are outside timing.
// Set WIM_LZX_ISO to local media; WIM_LZX_MEMBER defaults to /sources/install.wim.
func BenchmarkLZXMedia(b *testing.B) {
	name := os.Getenv("WIM_LZX_ISO")
	if name == "" {
		b.Skip("set WIM_LZX_ISO")
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
	iso, err := iso9660.ISO9660Builtin(nil, nil, starlark.Tuple{&lzxBenchmarkFile{File: f, size: info.Size()}}, nil)
	if err != nil {
		b.Fatal(err)
	}
	member := os.Getenv("WIM_LZX_MEMBER")
	if member == "" {
		member = "/sources/install.wim"
	}
	value, found, err := iso.(starlark.Mapping).Get(starlark.String(member))
	if err != nil || !found {
		image, udfErr := udf.UDFBuiltin(nil, nil, starlark.Tuple{&lzxBenchmarkFile{File: f, size: info.Size()}}, nil)
		if udfErr != nil {
			b.Fatal(udfErr)
		}
		value, found, err = image.(starlark.Mapping).Get(starlark.String(member))
	}
	if err != nil || !found {
		b.Fatalf("member %s: found=%v err=%v", member, found, err)
	}
	archive, err := Open(value.(starfile.File))
	if err != nil {
		b.Fatal(err)
	}
	if archive.flags&0x40000 == 0 {
		b.Fatal("media is not LZX-compressed")
	}
	type sample struct {
		input []byte
		size  int
		hash  [32]byte
	}
	var samples []sample
	total := 0
	for _, entry := range archive.lookup {
		if entry.resource.flags&wimResourceCompressed == 0 {
			continue
		}
		chunks, err := archive.resourceChunks(entry.resource)
		if err != nil {
			b.Fatal(err)
		}
		for _, chunk := range chunks {
			if chunk.inSize == int64(chunk.outputSize) {
				continue
			}
			input := make([]byte, chunk.inSize)
			if _, err := archive.file.ReadAt(input, entry.resource.offset+chunk.inOffset); err != nil {
				b.Fatal(err)
			}
			out, err := lzx.DecompressWIMChunk(input, 15, chunk.outputSize)
			if err != nil {
				b.Fatal(err)
			}
			samples = append(samples, sample{input, chunk.outputSize, sha256.Sum256(out)})
			total += chunk.outputSize
			break // sample many resources, rather than one large file
		}
		if len(samples) == 256 {
			break
		}
	}
	if len(samples) == 0 {
		b.Fatal("no compressed LZX chunks")
	}
	aggregate := sha256.New()
	compressed := 0
	for _, s := range samples {
		aggregate.Write(s.hash[:])
		compressed += len(s.input)
	}
	b.Logf("chunks=%d compressed=%d output=%d hash-of-output-hashes=%x", len(samples), compressed, total, aggregate.Sum(nil))
	b.SetBytes(int64(total))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range samples {
			if _, err := lzx.DecompressWIMChunk(s.input, 15, s.size); err != nil {
				b.Fatal(err)
			}
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
