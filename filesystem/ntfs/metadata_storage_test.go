package ntfs

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestPackedMFTIsIndependentByteExactSnapshot(t *testing.T) {
	b := &ntfsBuild{size: 64 << 20, mftRecords: 128, versionMajor: 3}
	b.nodes = []*ntfsNode{{id: 0, linkCount: 1}, {id: 63, linkCount: 2}, {id: 64, linkCount: 1}, {id: 127, linkCount: 1}}
	// The former contiguous representation, including unused record slots.
	want := make([]byte, b.mftRecords*ntfsRecordSize)
	for _, node := range b.nodes {
		record, err := b.mftRecord(node)
		if err != nil {
			t.Fatal(err)
		}
		copy(want[int64(node.id)*ntfsRecordSize:], record)
	}
	store, err := starfile.NewPackedFileStore(64<<10, false)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := b.packedMFT(store)
	if err != nil {
		t.Fatal(err)
	}
	// A final image must not consult mutable builder/source state after handoff.
	for _, node := range b.nodes {
		node.linkCount = 99
	}
	b.nodes = nil
	b.mftRecords = 0
	for _, span := range [][2]int64{{0, int64(len(want))}, {0, 4096}, {65530, 30}, {1020, 1040}, {int64(len(want)) - 7, 20}} {
		span := span
		t.Run(fmt.Sprintf("offset%d-length%d", span[0], span[1]), func(t *testing.T) {
			t.Parallel()
			got := make([]byte, span[1])
			n, err := packed.ReadAt(got, span[0])
			end := min(span[0]+span[1], int64(len(want)))
			if !bytes.Equal(got[:n], want[span[0]:end]) {
				t.Fatal("snapshot bytes changed")
			}
			if (end < span[0]+span[1] && err != io.EOF) || (end == span[0]+span[1] && err != nil) {
				t.Fatalf("n=%d err=%v", n, err)
			}
		})
	}
	if _, err := packed.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative read accepted")
	}
}

func TestInitialLogReaderBoundaries(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		const size = 16384
		var prefix []byte
		if legacy {
			prefix = ntfsInitialLogPages(size)
		}
		reader := &ntfsInitialLogReader{size: size, prefix: prefix}
		want := bytes.Repeat([]byte{0xff}, size)
		copy(want, prefix)
		for _, span := range [][2]int64{{0, size}, {8190, 10}, {size - 3, 10}, {size, 1}, {size + 10, 1}} {
			got := make([]byte, span[1])
			n, err := reader.ReadAt(got, span[0])
			start, end := min(span[0], size), min(span[0]+span[1], size)
			if !bytes.Equal(got[:n], want[start:end]) {
				t.Fatalf("legacy=%v span=%v", legacy, span)
			}
			if n < len(got) && err != io.EOF {
				t.Fatalf("short read: %v", err)
			}
		}
		if _, err := reader.ReadAt(make([]byte, 1), -1); err == nil {
			t.Fatal("negative read accepted")
		}
	}
}
