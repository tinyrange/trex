package storage

import (
	"crypto/sha256"
	"io"
	"sync/atomic"
	"testing"
)

type profileVerifiedReader struct {
	verified atomic.Bool
	fail     atomic.Bool
}

func (*profileVerifiedReader) Size() int64 { return 2 }
func (r *profileVerifiedReader) ReadAt(p []byte, off int64) (int, error) {
	if r.fail.Load() {
		return 0, io.ErrUnexpectedEOF
	}
	if off != 0 {
		return 0, io.EOF
	}
	n := copy(p, []byte("ok"))
	r.verified.Store(true)
	return n, nil
}
func (r *profileVerifiedReader) VerifiedSHA256() ([32]byte, bool) {
	return sha256.Sum256([]byte("ok")), r.verified.Load()
}

func TestReadProfilerPreservesVerifiedIdentityWithoutReading(t *testing.T) {
	p, err := NewReadProfiler(&profileTestClock{}, 4, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	source := &profileVerifiedReader{}
	reader, _ := p.Wrap(source, "content")
	verified := reader.(VerifiedSHA256Reader)
	if _, ok := verified.VerifiedSHA256(); ok {
		t.Fatal("invented proof")
	}
	if p.Snapshot(0).Total.Calls != 0 {
		t.Fatal("identity query read source")
	}
	if _, err := reader.ReadAt(make([]byte, 2), 0); err != nil {
		t.Fatal(err)
	}
	if digest, ok := verified.VerifiedSHA256(); !ok || digest != sha256.Sum256([]byte("ok")) {
		t.Fatal("lost content identity")
	}
	if p.Snapshot(0).Total.Calls != 1 {
		t.Fatal("proof query reread source")
	}
	source.fail.Store(true)
	if _, err := reader.ReadAt(make([]byte, 2), 0); err != io.ErrUnexpectedEOF {
		t.Fatal("proof hid backing error", err)
	}
	ordinary, _ := p.Wrap(&profileTestReader{clock: &profileTestClock{}}, "ordinary")
	if _, ok := ordinary.(VerifiedSHA256Reader).VerifiedSHA256(); ok {
		t.Fatal("ordinary reader gained proof")
	}
}
