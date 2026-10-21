package gitstore

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	scsnative "github.com/tinyrange/trex/scs/native"
	"github.com/tinyrange/trex/scs/repo"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testPackEntry struct {
	base []byte
	body []byte
}

func blobHash(body []byte) []byte {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d%c", len(body), 0)
	h.Write(body)
	return h.Sum(nil)
}
func dependencyPack(t *testing.T, entries []testPackEntry) ([]byte, Download) {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(len(entries)))
	for _, e := range entries {
		kind := byte(3)
		if e.base != nil {
			kind = 7
		}
		n := len(e.body)
		header := kind<<4 | byte(n&15)
		n >>= 4
		if n != 0 {
			header |= 128
		}
		b.WriteByte(header)
		for n != 0 {
			v := byte(n & 127)
			n >>= 7
			if n != 0 {
				v |= 128
			}
			b.WriteByte(v)
		}
		b.Write(e.base)
		z := zlib.NewWriter(&b)
		if _, err := z.Write(e.body); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes(), Download{Objects: uint32(len(entries)), PackBytes: int64(b.Len()), PackHash: hex.EncodeToString(sum[:])}
}

// Reverse references force the scheduler to discover a long dependency chain;
// side branches test that releasing one child does not lose sibling work.
func TestParallelDependencyBranches(t *testing.T) {
	var entries []testPackEntry
	bodies := [][]byte{[]byte("000000")}
	for i := 1; i <= 60; i++ {
		b := []byte(fmt.Sprintf("%06d", i))
		entries = append(entries, testPackEntry{blobHash(bodies[len(bodies)-1]), append([]byte{6, 6, 6}, b...)})
		side := []byte(fmt.Sprintf("s%05d", i))
		entries = append(entries, testPackEntry{blobHash(b), append([]byte{6, 6, 6}, side...)})
		bodies = append(bodies, b)
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	entries = append(entries, testPackEntry{body: bodies[0]})
	pack, d := dependencyPack(t, entries)
	d.Refs = map[string]string{"refs/tags/tip": hex.EncodeToString(blobHash(bodies[len(bodies)-1]))}
	for _, parallel := range []bool{true, false} {
		t.Run(fmt.Sprint(parallel), func(t *testing.T) {
			r, err := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "deps.scs"))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var input io.ReadSeeker = bytes.NewReader(pack)
			if !parallel {
				input = struct{ io.ReadSeeker }{input}
			}
			if _, err := ImportPack(context.Background(), r, input, d, Options{}); err != nil {
				t.Fatal(err)
			}
			for _, body := range bodies {
				id, _ := repo.GitOIDFromBytes(blobHash(body))
				_, got, err := r.ReadGitObject(id)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatalf("body %s: %q %v", body, got, err)
				}
			}
			if err := r.Scrub(true); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestParallelDependencyFailuresDoNotPublish(t *testing.T) {
	base := []byte("abcdef")
	cases := map[string][]testPackEntry{
		"missing":         {{blobHash(base), []byte{6, 7, 1, 'X', 0x90, 6}}},
		"bad-copy":        {{blobHash(base), []byte{6, 7, 0x91, 6, 7}}, {body: base}},
		"wrong-base-size": {{blobHash(base), []byte{5, 1, 1, 'X'}}, {body: base}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			pack, d := dependencyPack(t, entries)
			r, err := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "failure.scs"))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := ImportPack(context.Background(), r, bytes.NewReader(pack), d, Options{}); err == nil {
				t.Fatal("accepted malformed dependency")
			}
			if _, err := r.GitCatalog("git"); err == nil {
				t.Fatal("published failed import")
			}
		})
	}
}

type cancellingPack struct {
	*bytes.Reader
	cancel context.CancelFunc
}

func (p cancellingPack) ReadAt(b []byte, off int64) (int, error) {
	p.cancel()
	return p.Reader.ReadAt(b, off)
}
func TestParallelWorkerCancellation(t *testing.T) {
	pack, d := dependencyPack(t, []testPackEntry{{body: []byte("a")}, {body: []byte("b")}})
	r, err := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "cancel.scs"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := ImportPack(ctx, r, cancellingPack{bytes.NewReader(pack), cancel}, d, Options{}); err == nil {
		t.Fatal("cancelled import succeeded")
	}
	if _, err := r.GitCatalog("git"); err == nil {
		t.Fatal("published cancelled import")
	}
}

// Sequential reads pause late in the scan until an object is accounted for.
// Independent worker ReadAt calls remain available. A two-pass importer cannot
// complete this fixture, so it checks actual overlap, not merely final counts.
type gatedScan struct {
	*bytes.Reader
	ctx      context.Context
	gate     <-chan struct{}
	rewinds  int
	cut      int64
	released bool
}

func (p *gatedScan) Seek(off int64, whence int) (int64, error) {
	if off == 0 && whence == io.SeekStart {
		p.rewinds++
	}
	return p.Reader.Seek(off, whence)
}
func (p *gatedScan) Read(b []byte) (int, error) {
	if p.rewinds >= 2 && !p.released {
		pos := p.Size() - int64(p.Len())
		if pos >= p.cut {
			select {
			case <-p.gate:
				p.released = true
			case <-p.ctx.Done():
				return 0, p.ctx.Err()
			}
		} else if int64(len(b)) > p.cut-pos {
			b = b[:p.cut-pos]
		}
	}
	return p.Reader.Read(b)
}

type importSignal struct {
	once sync.Once
	gate chan struct{}
}

func (s *importSignal) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte("native objects=")) {
		s.once.Do(func() { close(s.gate) })
	}
	return len(b), nil
}
func TestParallelScanOverlapsIngestion(t *testing.T) {
	var entries []testPackEntry
	for i := 0; i < 2200; i++ {
		entries = append(entries, testPackEntry{body: []byte(fmt.Sprintf("%06d", i))})
	}
	// A late REF dependency also exercises discovery after a base was committed.
	target := []byte("X000000")
	entries = append(entries, testPackEntry{blobHash(entries[0].body), []byte{6, 7, 1, 'X', 0x90, 6}})
	pack, d := dependencyPack(t, entries)
	d.Refs = map[string]string{"refs/tags/target": hex.EncodeToString(blobHash(target))}
	r, err := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "stream.scs"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	signal := &importSignal{gate: make(chan struct{})}
	input := &gatedScan{Reader: bytes.NewReader(pack), ctx: ctx, gate: signal.gate, cut: int64(len(pack) * 3 / 4)}
	if _, err := ImportPack(ctx, r, input, d, Options{Progress: signal}); err != nil {
		t.Fatal(err)
	}
	if !input.released {
		t.Fatal("scan did not pass ingestion gate")
	}
	id, _ := repo.GitOIDFromBytes(blobHash(target))
	_, got, err := r.ReadGitObject(id)
	if err != nil || !bytes.Equal(got, target) {
		t.Fatalf("late reference: %q %v", got, err)
	}
}
