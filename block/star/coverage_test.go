package star

import (
	"math/rand"
	"sync"
	"testing"
)

func TestByteCoverageAgainstByteOracle(t *testing.T) {
	for seed := int64(0); seed < 20; seed++ {
		rng := rand.New(rand.NewSource(seed))
		c := byteCoverage{limit: 1024}
		oracle := make([]bool, 4096)
		for step := 0; step < 1000; step++ {
			start := rng.Intn(len(oracle))
			length := rng.Intn(min(80, len(oracle)-start) + 1)
			c.add(int64(start), int64(length))
			for i := start; i < start+length; i++ {
				oracle[i] = true
			}
			var count int64
			for _, set := range oracle {
				if set {
					count++
				}
			}
			if c.bytes != count || c.overflow {
				t.Fatalf("seed=%d step=%d got=%d want=%d", seed, step, c.bytes, count)
			}
		}
	}
}
func TestByteCoverageOverflowDoesNotPretendToBeExact(t *testing.T) {
	c := byteCoverage{limit: 2}
	c.add(0, 10)
	c.add(20, 10)
	c.add(5, 20)
	if c.bytes != 30 || len(c.ranges) != 1 {
		t.Fatalf("bridge failed: %+v", c)
	}
	c.add(40, 1)
	c.add(50, 1)
	if !c.overflow || c.bytes != 31 || len(c.ranges) != 2 {
		t.Fatalf("bound failed: %+v", c)
	}
	c.add(0, 100)
	if c.bytes != 31 || !c.overflow {
		t.Fatal("overflow must remain explicit and frozen")
	}
	invalid := byteCoverage{limit: 2}
	invalid.add(1<<63-2, 4)
	if !invalid.overflow || invalid.bytes != 0 {
		t.Fatal("integer overflow accepted")
	}
}
func TestOverlayUniqueTrafficIncludesRepeatsZeroAndConcurrentReads(t *testing.T) {
	d, err := newOverlayBlockDevice(testBlockDevice(t, 4096), 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	d.coverageLimit = 32
	d.readCoverage.limit = 32
	d.writeCoverage.limit = 32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.ReadAt(make([]byte, 100), 10); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err = d.WriteAt(make([]byte, 20), 40); err != nil {
		t.Fatal(err)
	}
	if err = d.ZeroAt(50, 20); err != nil {
		t.Fatal(err)
	}
	if _, err = d.WriteAt(make([]byte, 10), 4096); err == nil {
		t.Fatal("out-of-bounds write accepted")
	}
	s := d.Stats()
	if s["unique_read_bytes"].String() != "100" || s["read_bytes"].String() != "800" || s["unique_write_bytes"].String() != "30" || s["write_bytes"].String() != "40" || s["coverage_complete"].String() != "True" {
		t.Fatalf("traffic: %v", s)
	}
}
