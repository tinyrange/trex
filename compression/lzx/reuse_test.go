package lzx

import (
	"bytes"
	"sync"
	"testing"
)

// Independent chunks must not inherit code-length deltas or match history,
// including when the preceding decode failed partway through its tables.
func TestWIMIndependentDecoderState(t *testing.T) {
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for cycle := 0; cycle < 25; cycle++ {
				for _, kind := range []string{"literals", "matches", "uncompressed"} {
					input, want := lzxBenchmarkStream(kind, true)
					for _, bad := range [][]byte{nil, input[:len(input)/2], {0xff, 0xff}} {
						_, _ = DecompressWIMChunk(bad, 15, len(want))
					}
					got, err := DecompressWIMChunk(input, 15, len(want))
					if err != nil || !bytes.Equal(got, want) {
						t.Errorf("%s: independent chunk corrupted: %v", kind, err)
						return
					}
				}
			}
		}()
	}
	group.Wait()
}
