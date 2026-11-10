package catalog

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func BenchmarkCatalogEntries(b *testing.B) {
	for _, version := range []int{2, 3} {
		b.Run(fmt.Sprintf("v%d", version-1), func(b *testing.B) {
			digests := make([][]byte, 4096)
			for i := range digests {
				digests[i] = make([]byte, 32)
				binary.LittleEndian.PutUint32(digests[i], uint32(i))
			}
			data := catalogTestFile(b, version, true, digests...)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				v, entries, err := ParseEntries(data)
				if err != nil || v != version-1 || len(entries) != len(digests) {
					b.Fatalf("version=%d count=%d err=%v", v, len(entries), err)
				}
			}
		})
	}
}
