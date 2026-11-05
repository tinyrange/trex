package bytecache

import (
	"errors"
	"testing"
)

func TestLoadTimingExcludesHitsAndIncludesFailures(t *testing.T) {
	c := New(8)
	key := Key{Index: 1}
	if _, err := c.Get(key, func() ([]byte, error) { return []byte("payload"), nil }); err != nil {
		t.Fatal(err)
	}
	first := c.Stats()
	if first.LoadNanoseconds == 0 {
		t.Fatal("successful loader was not timed")
	}
	if _, err := c.Get(key, func() ([]byte, error) { t.Fatal("hit called loader"); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if c.Stats().LoadNanoseconds != first.LoadNanoseconds {
		t.Fatal("hit changed loader time")
	}
	failure := errors.New("source failed")
	if _, err := c.Get(Key{Index: 2}, func() ([]byte, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	last := c.Stats()
	if last.LoadNanoseconds <= first.LoadNanoseconds || last.Loads != 1 || last.Misses != 2 {
		t.Fatalf("failed load timing/counts: %+v", last)
	}
}
