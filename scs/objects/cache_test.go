package objects_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/tinyrange/trex/scs/objects"
	"github.com/tinyrange/trex/scs/repo"
	"github.com/tinyrange/trex/storage"
)

type sourceFunc func(context.Context, objects.ID) (objects.Object, error)

func (f sourceFunc) Fetch(ctx context.Context, id objects.ID) (objects.Object, error) {
	return f(ctx, id)
}
func cache(t *testing.T, source objects.Source, bytes int64, entries int) *objects.Cache {
	t.Helper()
	c, e := objects.NewCache(source, objects.Limits{CacheBytes: bytes, ObjectBytes: 1024, Entries: entries})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestLazyChunkedRetrievalAndCacheTiers(t *testing.T) {
	data := map[objects.ID][]byte{}
	chunks := []objects.Chunk{}
	for _, s := range []string{"abcd", "efgh", "ijkl"} {
		b := []byte(s)
		id := objects.Identity(1, b)
		data[id] = b
		chunks = append(chunks, objects.Chunk{ID: id, Kind: 1, Size: 4})
	}
	source := sourceFunc(func(ctx context.Context, id objects.ID) (objects.Object, error) {
		b, ok := data[id]
		if !ok {
			return objects.Object{}, errors.New("missing")
		}
		return objects.Object{Kind: 1, Data: bytes.NewReader(b)}, nil
	})
	upstream := cache(t, source, 64, 16)
	local := cache(t, upstream, 8, 2)
	reader, e := local.ChunkedReader(context.Background(), chunks)
	if e != nil {
		t.Fatal(e)
	}
	if local.Stats().Fetches != 0 || upstream.Stats().Fetches != 0 {
		t.Fatal("eager fetch")
	}
	b := make([]byte, 1)
	_, e = reader.ReadAt(b, 5)
	if e != nil || string(b) != "f" {
		t.Fatal(string(b), e)
	}
	if local.Stats().FetchedBytes != 4 {
		t.Fatal("small read fetched unrelated chunks", local.Stats())
	}
	b = make([]byte, 5)
	_, e = reader.ReadAt(b, 2)
	if e != nil || string(b) != "cdefg" {
		t.Fatal(string(b), e)
	}
	b = make([]byte, 12)
	_, e = reader.ReadAt(b, 0)
	if e != nil || string(b) != "abcdefghijkl" {
		t.Fatal(string(b), e)
	}
	if local.Stats().CachedBytes > 8 || local.Stats().Entries > 2 || upstream.Stats().Fetches != 3 {
		t.Fatal(local.Stats(), upstream.Stats())
	}
	b = make([]byte, 4)
	_, e = reader.ReadAt(b, 10)
	if !errors.Is(e, io.EOF) || string(b[:2]) != "kl" {
		t.Fatal(b, e)
	}
	// Portable consumers ingest directly, without a checkout or host file.
	r, e := repo.CreateOptimized(storage.NewMemoryStore(4 << 20))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	w := r.Empty()
	if e = w.WriteReader("remote", reader); e != nil {
		t.Fatal(e)
	}
	got, e := w.ReadFile("remote")
	if e != nil || string(got) != "abcdefghijkl" {
		t.Fatal(string(got), e)
	}
}
func TestObjectVerificationOwnershipAndEviction(t *testing.T) {
	data := []byte("original")
	id := objects.Identity(2, data)
	c := cache(t, sourceFunc(func(context.Context, objects.ID) (objects.Object, error) {
		return objects.Object{Kind: 2, Data: bytes.NewReader(data)}, nil
	}), 8, 1)
	object, e := c.Fetch(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	data[0] = 'X'
	b := make([]byte, 8)
	_, e = object.Data.ReadAt(b, 0)
	if e != nil || string(b) != "original" {
		t.Fatal("source alias escaped", string(b), e)
	}
	again, e := c.Fetch(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	_, e = again.Data.ReadAt(b, 0)
	if e != nil || string(b) != "original" {
		t.Fatal(string(b), e)
	}
	bad := cache(t, sourceFunc(func(context.Context, objects.ID) (objects.Object, error) {
		return objects.Object{Kind: 2, Data: bytes.NewReader([]byte("wrong"))}, nil
	}), 16, 2)
	if _, e = bad.Fetch(context.Background(), id); e == nil {
		t.Fatal("unverified bytes exposed")
	}
	if bad.Stats().Entries != 0 {
		t.Fatal("failure cached")
	}
	mismatch, e := c.Reader(context.Background(), id, 1, 8)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = mismatch.ReadAt(b, 0); e == nil {
		t.Fatal("wrong manifest kind accepted")
	}
	if _, e = c.Reader(context.Background(), id, 2, 2048); !errors.Is(e, objects.ErrLimit) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Fetch(ctx, id); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestConcurrentObjectRequestsAndWaiterCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	id := objects.Identity(1, []byte("value"))
	var once sync.Once
	c := cache(t, sourceFunc(func(ctx context.Context, _ objects.ID) (objects.Object, error) {
		once.Do(func() { close(started) })
		select {
		case <-ctx.Done():
			return objects.Object{}, ctx.Err()
		case <-release:
		}
		return objects.Object{Kind: 1, Data: bytes.NewReader([]byte("value"))}, nil
	}), 64, 4)
	done := make(chan error, 1)
	go func() { _, e := c.Fetch(context.Background(), id); done <- e }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.Fetch(ctx, id); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	var group sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() { defer group.Done(); _, e := c.Fetch(context.Background(), id); errs <- e }()
	}
	close(release)
	group.Wait()
	close(errs)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if c.Stats().Fetches != 1 {
		t.Fatal(c.Stats())
	}
}
