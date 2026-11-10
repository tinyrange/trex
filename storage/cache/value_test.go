package bytecache

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestValuesShareByteBudgetAndSingleFlight(t *testing.T) {
	c := New(12)
	var loads atomic.Int32
	value := &struct{ text string }{"immutable"}
	load := func() (any, int64, error) { loads.Add(1); return value, 8, nil }
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.GetValue(Key{Kind: 4}, load)
			if err != nil || got != value {
				t.Errorf("value=%v err=%v", got, err)
			}
		}()
	}
	wg.Wait()
	if loads.Load() != 1 {
		t.Fatalf("loads=%d", loads.Load())
	}
	_, _ = c.Get(Key{Kind: 1}, func() ([]byte, error) { return []byte("12345678"), nil })
	if stats := c.Stats(); stats.Bytes != 8 || stats.Evictions != 1 {
		t.Fatal(stats)
	}
	if _, err := c.GetValue(Key{Kind: 4}, load); err != nil {
		t.Fatal(err)
	}
	if loads.Load() != 2 {
		t.Fatal("weighted object did not reload after byte eviction")
	}
	c.Clear()
	if stats := c.Stats(); stats.Bytes != 0 || stats.Entries != 0 {
		t.Fatal(stats)
	}
	if value.text != "immutable" {
		t.Fatal("eviction invalidated a returned value")
	}
	if _, err := c.GetValue(Key{Kind: 9}, func() (any, int64, error) { return value, -1, nil }); err == nil {
		t.Fatal("negative weight accepted")
	}
	if c.Stats().Entries != 0 {
		t.Fatal("failed load retained")
	}
}
