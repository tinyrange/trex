package wim

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
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
		plain []byte
	}
	var samples []sample
	total := 0
	// The parse-only lookup table is released after opening. Select unique
	// resources from the retained content index in deterministic disk order.
	resources := make([]wimResource, 0, len(archive.byHash))
	seen := make(map[wimResource]bool)
	for _, indexed := range archive.byHash {
		location := archive.expandIndexed(indexed)
		if !seen[location.resource] {
			resources = append(resources, location.resource)
			seen[location.resource] = true
		}
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].offset < resources[j].offset })
	for _, resource := range resources {
		if resource.flags&wimResourceCompressed == 0 {
			continue
		}
		chunks, err := archive.resourceChunks(resource)
		if err != nil {
			b.Fatal(err)
		}
		for _, chunk := range chunks {
			if chunk.inSize == int64(chunk.outputSize) {
				continue
			}
			input := make([]byte, chunk.inSize)
			if _, err := archive.file.ReadAt(input, resource.offset+chunk.inOffset); err != nil {
				b.Fatal(err)
			}
			out, err := lzx.DecompressWIMChunk(input, 15, chunk.outputSize)
			if err != nil {
				b.Fatal(err)
			}
			samples = append(samples, sample{input, chunk.outputSize, out})
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
		checksum := sha256.Sum256(s.plain)
		aggregate.Write(checksum[:])
		compressed += len(s.input)
	}
	b.Logf("chunks=%d compressed=%d output=%d hash-of-output-hashes=%x", len(samples), compressed, total, aggregate.Sum(nil))
	b.Run("LZX/decode", func(b *testing.B) {
		b.SetBytes(int64(total))
		b.ReportAllocs()
		for b.Loop() {
			for _, s := range samples {
				if _, err := lzx.DecompressWIMChunk(s.input, 15, s.size); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(64<<10))
	if err != nil {
		b.Fatal(err)
	}
	defer encoder.Close()
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	if err != nil {
		b.Fatal(err)
	}
	defer decoder.Close()
	var lz4Encoder lz4.Compressor
	codecs := []struct {
		name   string
		encode func([]byte, []byte) []byte
		decode func([]byte, []byte) ([]byte, error)
	}{
		{"raw", nil, nil},
		{"zstd", func(dst, src []byte) []byte { return encoder.EncodeAll(src, dst[:0]) },
			func(dst, src []byte) ([]byte, error) { return decoder.DecodeAll(src, dst[:0]) }},
		{"lz4", func(dst, src []byte) []byte {
			count, err := lz4Encoder.CompressBlock(src, dst)
			if err != nil {
				b.Fatal(err)
			}
			return dst[:count]
		}, func(dst, src []byte) ([]byte, error) {
			count, err := lz4.UncompressBlock(src, dst)
			return dst[:count], err
		}},
		{"s2", s2.Encode, s2.Decode},
	}
	for _, codec := range codecs {
		encoded := make([][]byte, len(samples))
		bytesStored := 0
		encodeBuffer := make([]byte, lz4.CompressBlockBound(64<<10))
		decodeBuffer := make([]byte, 64<<10)
		for i, sample := range samples {
			record := sample.plain
			if codec.encode != nil {
				if compressed := codec.encode(encodeBuffer, sample.plain); len(compressed) != 0 && len(compressed) < len(record) {
					data, err := codec.decode(decodeBuffer, compressed)
					if err != nil || !bytes.Equal(data, sample.plain) {
						b.Fatalf("%s did not round trip a media chunk: %v", codec.name, err)
					}
					record = bytes.Clone(compressed)
				}
			}
			encoded[i] = record
			bytesStored += len(record)
		}
		b.Run(codec.name+"/random-read", func(b *testing.B) {
			window := make([]byte, 4096)
			b.SetBytes(int64(len(window)))
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				index := (i * 73) % len(samples)
				record := encoded[index]
				if len(record) < samples[index].size {
					var err error
					record, err = codec.decode(decodeBuffer, record)
					if err != nil {
						b.Fatal(err)
					}
				}
				length := min(len(record), len(window))
				offset := (i * 307) % (len(record) - length + 1)
				copy(window, record[offset:offset+length])
				if window[0] != samples[index].plain[offset] {
					b.Fatal("incorrect random read")
				}
			}
			b.ReportMetric(float64(bytesStored)/float64(total), "stored/raw")
		})
		if codec.encode != nil {
			b.Run(codec.name+"/encode", func(b *testing.B) {
				b.SetBytes(int64(total))
				b.ReportAllocs()
				for b.Loop() {
					for _, sample := range samples {
						codec.encode(encodeBuffer, sample.plain)
					}
				}
			})
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
