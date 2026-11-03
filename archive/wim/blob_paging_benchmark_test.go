package wim

import (
	"crypto/sha1"
	"fmt"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

// Isolate the private solid-blob cache from LZMS throughput: reader already
// exposes expanded source bytes. Half-random/half-zero pages exercise encoded
// retention without turning every input into either all-zero or raw fallback.
func pagingBenchmarkFile(size int) (*File, []byte) {
	data := make([]byte, size)
	state := uint64(0x951d)
	for i := range data {
		if i%65536 < 32768 {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			data[i] = byte(state)
		}
	}
	source := &countingWIMFile{data: data}
	a := &Archive{blobCache: bytecache.New(64 << 20), blobHotCache: bytecache.New(0)}
	return &File{archive: a, entry: entry{path: "paging-benchmark", hash: sha1.Sum(data), size: int64(size)},
		reader: source, location: &wimResourceLocation{resource: wimResource{flags: wimResourceSolid, compression: 3}}}, data
}

func BenchmarkSolidBlobPaging(b *testing.B) {
	for _, size := range []int{64 << 10, 1 << 20, 32 << 20} {
		for _, mode := range []string{"cold-fill", "compressed-hit", "decoded-hit", "parallel-compressed-hit"} {
			b.Run(fmt.Sprintf("%dKiB/%s", size>>10, mode), func(b *testing.B) {
				f, plain := pagingBenchmarkFile(size)
				if mode == "decoded-hit" {
					f.archive.blobHotCache = bytecache.New(64 << 20)
				}
				got := make([]byte, 4096)
				if mode != "cold-fill" {
					if _, err := f.ReadAt(got, 0); err != nil {
						b.Fatal(err)
					}
					f.reader = &countingWIMFile{} // A cache hit must not consult source.
				}
				b.SetBytes(int64(len(got)))
				b.ReportAllocs()
				b.ResetTimer()
				if mode == "parallel-compressed-hit" {
					b.RunParallel(func(pb *testing.PB) {
						buf := make([]byte, 4096)
						i := 0
						for pb.Next() {
							off := (i * 4096) % (size - len(buf) + 1)
							if n, err := f.ReadAt(buf, int64(off)); n != len(buf) || err != nil || buf[0] != plain[off] || buf[len(buf)-1] != plain[off+len(buf)-1] {
								b.Errorf("cached parallel range %d: %d %v", off, n, err)
							}
							i++
						}
					})
					return
				}
				for i := 0; i < b.N; i++ {
					if mode == "cold-fill" {
						f.archive.blobCache = bytecache.New(0)
						f.archive.blobHotCache = bytecache.New(0)
					}
					off := (i * 4096) % (size - len(got) + 1)
					if n, err := f.ReadAt(got, int64(off)); n != len(got) || err != nil || got[0] != plain[off] || got[len(got)-1] != plain[off+len(got)-1] {
						b.Fatalf("cached range %d: %d %v", off, n, err)
					}
				}
			})
		}
	}
}
