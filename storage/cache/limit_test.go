package bytecache

import "testing"

func TestSetLimitEvictsLRUWithoutInvalidatingReaders(t *testing.T) {
	c := New(12)
	read := func(i int) []byte {
		t.Helper()
		v, err := c.Get(Key{Index: i}, func() ([]byte, error) { return []byte{byte(i), 0, 0, 0}, nil })
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	first := read(1)
	read(2)
	read(3)
	read(1)
	c.SetLimit(8)
	if s := c.Stats(); s.Bytes != 8 || s.Evictions != 1 {
		t.Fatalf("shrink: %+v", s)
	}
	before := c.Stats().Loads
	read(1)
	read(3)
	if c.Stats().Loads != before {
		t.Fatal("most recent values evicted")
	}
	read(2)
	if c.Stats().Loads != before+1 {
		t.Fatal("oldest survived")
	}
	c.SetLimit(-1)
	if s := c.Stats(); s.Bytes != 0 || s.Entries != 0 {
		t.Fatalf("disable: %+v", s)
	}
	if first[0] != 1 {
		t.Fatal("caller value invalidated")
	}
	c.SetLimit(16)
	read(1)
	before = c.Stats().Loads
	read(1)
	if c.Stats().Loads != before {
		t.Fatal("grown cache did not retain value")
	}
}

func TestSetLimitDuringLoad(t *testing.T) {
	c := New(16)
	started, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		v, err := c.Get(Key{Index: 1}, func() ([]byte, error) { close(started); <-resume; return []byte("large"), nil })
		if err != nil || string(v) != "large" {
			t.Errorf("load: %q %v", v, err)
		}
	}()
	<-started
	c.SetLimit(2)
	if s := c.Stats(); s.Entries != 1 {
		t.Fatalf("pending identity removed: %+v", s)
	}
	close(resume)
	<-done
	if s := c.Stats(); s.Bytes != 0 || s.Entries != 0 {
		t.Fatalf("completion ignored new limit: %+v", s)
	}
}
