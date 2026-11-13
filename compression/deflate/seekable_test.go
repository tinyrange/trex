package deflate

import (
	"bytes"
	"compress/flate"
	"io"
	"math/rand"
	"testing"
	"time"
)

func compress(t *testing.T, data []byte, level int) []byte {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, level)
	if err != nil {
		t.Fatal(err)
	}
	// Flush periodically so the stream has many blocks, including the empty
	// stored blocks sync flushes emit.
	for at := 0; at < len(data); at += 100000 {
		w.Write(data[at:min(at+100000, len(data))])
		w.Flush()
	}
	w.Close()
	return b.Bytes()
}

func TestSeekableRandomReads(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	data := make([]byte, 9<<20)
	for i := range data {
		if i%4096 < 3000 {
			data[i] = byte(i / 4096) // compressible runs
		} else {
			data[i] = byte(rng.Intn(256))
		}
	}
	for _, level := range []int{flate.NoCompression, flate.BestSpeed, flate.DefaultCompression, flate.HuffmanOnly} {
		c := compress(t, data, level)
		s := NewSeekable(bytes.NewReader(c), int64(len(c)), int64(len(data)), 1<<20)
		// Forward, backward and random reads across checkpoints.
		offs := []int64{0, 5 << 20, 1 << 20, int64(len(data)) - 10}
		for i := 0; i < 200; i++ {
			offs = append(offs, rng.Int63n(int64(len(data))))
		}
		for _, off := range offs {
			n := min(int64(rng.Intn(200000)+1), int64(len(data))-off)
			got := make([]byte, n)
			if m, err := s.ReadAt(got, off); (err != nil && err != io.EOF) || int64(m) != n {
				t.Fatalf("level %d off %d: %d %v", level, off, m, err)
			}
			if !bytes.Equal(got, data[off:off+n]) {
				t.Fatalf("level %d: mismatch at %d", level, off)
			}
		}
		if len(s.points) < 5 {
			t.Fatalf("level %d: only %d checkpoints", level, len(s.points))
		}
	}
}

// patterned mixes long zero runs (distance-1 matches), short-period repeats
// (overlapping matches), text-like data and incompressible bytes.
func patterned(size int) []byte {
	rng := rand.New(rand.NewSource(2))
	data := make([]byte, size)
	words := []string{"DATASET ", "SYS1.LINKLIB ", "IEFBR14 ", "//STEP1 EXEC PGM=", "ABCABCAB"}
	for i := 0; i < size; {
		switch rng.Intn(4) {
		case 0: // zeros
			i += rng.Intn(70000)
		case 1: // period 1-7 pattern
			p := rng.Intn(7) + 1
			n := rng.Intn(3000)
			for j := 0; j < n && i < size; j++ {
				data[i] = byte('A' + (j % p))
				i++
			}
		case 2:
			for j := rng.Intn(400); j > 0 && i < size; j-- {
				i += copy(data[i:], words[rng.Intn(len(words))])
			}
		default:
			for j := rng.Intn(5000); j > 0 && i < size; j-- {
				data[i] = byte(rng.Intn(256))
				i++
			}
		}
	}
	return data
}

func TestSeekableMatchesAndSmallReads(t *testing.T) {
	data := patterned(6 << 20)
	for _, level := range []int{flate.NoCompression, flate.BestSpeed, flate.BestCompression, flate.HuffmanOnly} {
		c := compress(t, data, level)
		s := NewSeekable(bytes.NewReader(c), int64(len(c)), int64(len(data)), 1<<20)
		// Sequential reads of awkward sizes exercise the slow path at
		// every read boundary.
		got := make([]byte, 0, len(data))
		buf := make([]byte, 7919)
		for off := int64(0); off < int64(len(data)); {
			n, err := s.ReadAt(buf[:1+int(off)%len(buf)], off)
			if err != nil && err != io.EOF {
				t.Fatalf("level %d at %d: %v", level, off, err)
			}
			got = append(got, buf[:n]...)
			off += int64(n)
		}
		if !bytes.Equal(got, data) {
			for i := range data {
				if got[i] != data[i] {
					t.Fatalf("level %d: first difference at %d", level, i)
				}
			}
		}
		// The end of the stream.
		tail := make([]byte, 100)
		if n, err := s.ReadAt(tail, int64(len(data))-50); n != 50 || err != io.EOF || !bytes.Equal(tail[:50], data[len(data)-50:]) {
			t.Fatalf("level %d tail: %d %v", level, n, err)
		}
	}
}

func BenchmarkSeekableDecode(b *testing.B) {
	data := patterned(32 << 20)
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(data)
	w.Close()
	c := buf.Bytes()
	out := make([]byte, 1<<20)
	b.SetBytes(int64(len(data)))
	b.Run("seekable", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		for i := 0; i < b.N; i++ {
			s := NewSeekable(bytes.NewReader(c), int64(len(c)), int64(len(data)), 1<<20)
			for off := int64(0); off < int64(len(data)); off += int64(len(out)) {
				s.ReadAt(out, off)
			}
		}
	})
	b.Run("stdlib", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		for i := 0; i < b.N; i++ {
			io.Copy(io.Discard, flate.NewReader(bytes.NewReader(c)))
		}
	})
}

// Background indexing runs alongside random reads; it records checkpoints
// across the stream (none with a window of zeros) and reads stay correct.
func TestSeekableBackgroundIndex(t *testing.T) {
	data := patterned(12 << 20)
	c := compress(t, data, flate.BestSpeed)
	s := NewSeekable(bytes.NewReader(c), int64(len(c)), int64(len(data)), 1<<20)
	s.IndexInBackground()
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 300; i++ {
		off := rng.Int63n(int64(len(data)))
		n := min(int64(rng.Intn(70000)+1), int64(len(data))-off)
		got := make([]byte, n)
		if m, err := s.ReadAt(got, off); (err != nil && err != io.EOF) || int64(m) != n || !bytes.Equal(got, data[off:off+n]) {
			t.Fatalf("read at %d: %d %v", off, m, err)
		}
	}
	for start := time.Now(); s.last().out < int64(len(data))-(2<<20); {
		if time.Since(start) > 20*time.Second {
			t.Fatalf("background index reached only %d", s.last().out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.pmu.Lock()
	defer s.pmu.Unlock()
	for i, p := range s.points {
		if i > 0 && p.out < s.points[i-1].out+s.interval {
			t.Fatalf("checkpoints %d and %d closer than the interval", s.points[i-1].out, p.out)
		}
		if p.window != nil && bytes.Count(p.window, []byte{0}) == len(p.window) {
			t.Fatalf("stored a zero window at %d", p.out)
		}
	}
}
