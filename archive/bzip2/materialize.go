package bzip2

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/tinyrange/trex/storage"
)

// Materialize validates all concatenated streams and returns an immutable
// bounded RAM snapshot. Integrity failures never return a partial snapshot.
func Materialize(source storage.Reader, maximum int64) (storage.Reader, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("bzip2: materialize requires positive maximum_bytes")
	}
	decoded := NewReader(source, maximum)
	if err := decoded.scan(); err != nil {
		return nil, err
	}
	store := storage.NewMemoryStore(maximum)
	defer store.Close()

	// Decode independent blocks concurrently without using the random-access
	// reader's eviction window. Only this bounded batch can hold expanded
	// bytes in addition to the snapshot, and the stream CRC stays in order.
	type result struct {
		data []byte
		crc  uint32
		err  error
	}
	workers := min(runtime.GOMAXPROCS(0), 4)
	results := make([]result, workers)
	var off int64
	var streamCRC uint32
	for first := 0; first < len(decoded.blocks); first += workers {
		batch := results[:min(workers, len(decoded.blocks)-first)]
		var pending sync.WaitGroup
		for i := range batch {
			pending.Go(func() {
				data, crc, _, err := decoded.decode(first+i, true)
				batch[i] = result{data: data, crc: crc, err: err}
			})
		}
		pending.Wait()
		for i, block := range batch {
			if block.err != nil {
				return nil, block.err
			}
			if int64(len(block.data)) > maximum-off {
				return nil, decoded.limitError()
			}
			streamCRC = (streamCRC<<1 | streamCRC>>31) ^ block.crc
			index := decoded.blocks[first+i]
			if index.streamEnd {
				if streamCRC != index.expectedCRC {
					return nil, fmt.Errorf("bzip2: stream checksum mismatch")
				}
				streamCRC = 0
			}
			if _, err := store.WriteAt(block.data, off); err != nil {
				return nil, err
			}
			off += int64(len(block.data))
		}
		clear(batch)
	}
	return store.Snapshot()
}
