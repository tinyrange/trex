package wim

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type metadataReader struct {
	data      []byte
	tableSize int64
	entered   chan struct{}
	release   chan struct{}
	fail      bool
}

func (r *metadataReader) Size() int64 { return int64(len(r.data)) }
func (r *metadataReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.tableSize && r.entered != nil {
		r.entered <- struct{}{}
		if r.fail && off == r.tableSize {
			return 0, io.ErrClosedPipe
		}
		<-r.release
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}
func metadataFixture() (*metadataReader, wimResource, []byte) {
	const chunkSize = 32768
	plain := make([]byte, (1<<20)+123)
	for i := range plain {
		plain[i] = byte((i/chunkSize)*17 + i%251)
	}
	chunks := (len(plain) + chunkSize - 1) / chunkSize
	table := make([]byte, (chunks-1)*4)
	for i := 0; i < chunks-1; i++ {
		binary.LittleEndian.PutUint32(table[i*4:], uint32((i+1)*chunkSize))
	}
	r := &metadataReader{data: append(table, plain...), tableSize: int64(len(table))}
	return r, wimResource{flags: wimResourceCompressed, size: int64(len(r.data)), originalSize: int64(len(plain))}, plain
}
func TestParallelMetadataPreservesChunkOrderAndTail(t *testing.T) {
	r, resource, want := metadataFixture()
	// WIM permits stored chunks inside a compressed resource; the partial tail
	// and distinct chunk contents catch offset, ordering and overlap mistakes.
	archive := &Archive{file: r, chunkSize: 32768}
	got, err := archive.readResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("metadata chunks reordered, overlapped, or tail lost")
	}
}
func TestParallelMetadataJoinsWorkersOnReadError(t *testing.T) {
	r, resource, _ := metadataFixture()
	r.entered = make(chan struct{}, 64)
	r.release = make(chan struct{})
	r.fail = true
	var once sync.Once
	release := func() { once.Do(func() { close(r.release) }) }
	defer release()
	archive := &Archive{file: r, chunkSize: 32768}
	done := make(chan error, 1)
	go func() {
		data, err := archive.readResource(resource)
		if data != nil {
			err = errors.New("partial metadata published")
		}
		done <- err
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-r.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("metadata workers did not start")
		}
	}
	select {
	case <-done:
		t.Fatal("returned while backing reads were still active")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("lost storage error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("metadata workers not joined")
	}
}
