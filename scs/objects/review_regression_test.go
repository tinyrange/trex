package objects_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/tinyrange/trex/scs/objects"
	"github.com/tinyrange/trex/storage"
)

type reviewReader struct {
	size int64
	read func([]byte, int64) (int, error)
}

func (r reviewReader) Size() int64                             { return r.size }
func (r reviewReader) ReadAt(p []byte, off int64) (int, error) { return r.read(p, off) }
func TestObjectVerificationRejectsNonprogressAndShortReaders(t *testing.T) {
	for _, tc := range []struct {
		name     string
		read     func([]byte, int64) (int, error)
		expected error
	}{
		{"zero", func([]byte, int64) (int, error) { return 0, nil }, io.ErrNoProgress},
		{"short-nil", func(p []byte, _ int64) (int, error) { p[0] = 'x'; return 1, nil }, io.ErrUnexpectedEOF},
		{"short-eof", func(p []byte, _ int64) (int, error) { p[0] = 'x'; return 1, io.EOF }, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cache(t, sourceFunc(func(context.Context, objects.ID) (objects.Object, error) {
				return objects.Object{Kind: 1, Data: reviewReader{size: 4, read: tc.read}}, nil
			}), 32, 4)
			id := objects.Identity(1, []byte("xxxx"))
			if _, e := c.Fetch(context.Background(), id); !errors.Is(e, tc.expected) {
				t.Fatal(e)
			}
			if c.Stats().Entries != 0 {
				t.Fatal("invalid object cached")
			}
			// Repeating must return promptly rather than finding a stuck flight.
			if _, e := c.Fetch(context.Background(), id); !errors.Is(e, tc.expected) {
				t.Fatal(e)
			}
		})
	}
}
func TestObjectVerificationAllowsFullReadWithEOF(t *testing.T) {
	data := []byte("full")
	id := objects.Identity(1, data)
	c := cache(t, sourceFunc(func(context.Context, objects.ID) (objects.Object, error) {
		return objects.Object{Kind: 1, Data: reviewReader{size: 4, read: func(p []byte, _ int64) (int, error) { return copy(p, data), io.EOF }}}, nil
	}), 32, 4)
	object, e := c.Fetch(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4)
	_, e = object.Data.ReadAt(b, 0)
	if e != nil || !bytes.Equal(b, data) {
		t.Fatal(b, e)
	}
}
func TestEmptyReaderManifestIsVerifiedWithoutFetching(t *testing.T) {
	c := cache(t, sourceFunc(func(context.Context, objects.ID) (objects.Object, error) {
		t.Fatal("empty read fetched source")
		return objects.Object{}, nil
	}), 32, 4)
	if _, e := c.Reader(context.Background(), objects.Identity(1, []byte("other")), 1, 0); e == nil {
		t.Fatal("invalid empty manifest accepted")
	}
	reader, e := c.Reader(context.Background(), objects.Identity(1, nil), 1, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reader.ReadAt(make([]byte, 1), 0); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.ChunkedReader(ctx, []objects.Chunk{{ID: objects.Identity(1, []byte("x")), Kind: 1, Size: 1}}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

var _ storage.Reader = reviewReader{}
