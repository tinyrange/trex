package starlarkfrontend

import (
	"crypto/sha256"
	"errors"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type digestTestReader struct {
	started chan struct{}
	release <-chan struct{}
	active  *atomic.Int32
	peak    *atomic.Int32
	failure error
	size    int64
}

func (r *digestTestReader) Size() int64 { return r.size }
func (r *digestTestReader) ReadAt(p []byte, off int64) (int, error) {
	if r.failure != nil {
		return 0, r.failure
	}
	n := r.active.Add(1)
	defer r.active.Add(-1)
	for {
		old := r.peak.Load()
		if n <= old || r.peak.CompareAndSwap(old, n) {
			break
		}
	}
	r.started <- struct{}{}
	<-r.release
	return strings.NewReader("contents").ReadAt(p, off)
}

func TestDigestManyBoundedReadersAndOrdering(t *testing.T) {
	started := make(chan struct{}, 20)
	release := make(chan struct{})
	var active, peak atomic.Int32
	values := []starlark.Value{starlark.String("first"), starlark.Bytes("second")}
	for i := 0; i < 12; i++ {
		values = append(values, starfile.NewReader(fmt.Sprint(i), &digestTestReader{started: started, release: release, active: &active, peak: &peak, size: 8}))
	}
	done := make(chan error, 1)
	go func() {
		result, err := digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList(values)}, nil)
		if err == nil {
			for i := range values {
				value := starlark.String("contents")
				if i == 0 {
					value = "first"
				}
				if i == 1 {
					value = "second"
				}
				want, e := digestBuiltin(nil, nil, starlark.Tuple{value}, nil)
				if e != nil || result.(*starlark.List).Index(i) != want {
					err = fmt.Errorf("out of order digest %d", i)
					break
				}
			}
		}
		done <- err
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("workers did not overlap")
		}
	}
	if peak.Load() != 4 {
		close(release)
		t.Fatal("unbounded workers", peak.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if active.Load() != 0 || peak.Load() > 4 {
		t.Fatal("workers left running or exceeded bound")
	}
}

func TestDigestManyErrorsAndAlgorithms(t *testing.T) {
	for _, alg := range []string{"md5", "sha1", "SHA-256", "sha512"} {
		kwargs := []starlark.Tuple{{starlark.String("algorithm"), starlark.String(alg)}, {starlark.String("workers"), starlark.MakeInt(1)}}
		got, err := digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{starlark.Bytes("test")})}, kwargs)
		want, we := digestBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("test")}, kwargs[:1])
		if err != nil || we != nil || got.(*starlark.List).Index(0) != want {
			t.Fatal(alg, got, err, we)
		}
	}
	for _, worker := range []int{0, 9} {
		if _, err := digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList(nil)}, []starlark.Tuple{{starlark.String("workers"), starlark.MakeInt(worker)}}); err == nil {
			t.Fatal("invalid worker count")
		}
	}
	if got, err := digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList(nil)}, nil); err != nil || got.(*starlark.List).Len() != 0 {
		t.Fatal(got, err)
	}
	for _, failure := range []error{io.EOF, errors.New("integrity failure")} {
		file := starfile.NewReader("bad", &digestTestReader{failure: failure, size: 8})
		result, err := digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{starlark.String("good"), file})}, nil)
		if result != nil || !errors.Is(err, failure) {
			t.Fatal("lost read failure", result, err)
		}
	}
}

type verifiedDigestFixture struct {
	verified bool
	reads    int
}

func (r *verifiedDigestFixture) Size() int64 { return 8 }
func (r *verifiedDigestFixture) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return strings.NewReader("contents").ReadAt(p, off)
}
func (r *verifiedDigestFixture) VerifiedSHA256() ([32]byte, bool) {
	return sha256.Sum256([]byte("contents")), r.verified
}
func TestDigestReusesOnlyVerifiedImmutableSHA256(t *testing.T) {
	r := &verifiedDigestFixture{}
	file := starfile.NewReader("immutable", r)
	want, err := digestBuiltin(nil, nil, starlark.Tuple{file}, nil)
	if err != nil || r.reads == 0 {
		t.Fatal("unverified digest skipped bytes", err)
	}
	r.verified = true
	r.reads = 0
	got, err := digestBuiltin(nil, nil, starlark.Tuple{file}, nil)
	if err != nil || got != want || r.reads != 0 {
		t.Fatal("verified identity not reused", err)
	}
	got, err = digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{file, file})}, nil)
	if err != nil || r.reads != 0 || got.(*starlark.List).Index(1) != want {
		t.Fatal("batch identity not reused", err)
	}
	_, err = digestBuiltin(nil, nil, starlark.Tuple{file}, []starlark.Tuple{{starlark.String("algorithm"), starlark.String("sha1")}})
	if err != nil || r.reads == 0 {
		t.Fatal("SHA256 substituted for another algorithm", err)
	}
}
