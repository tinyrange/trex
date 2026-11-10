package native

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	"github.com/tinyrange/trex/windows/msdelta"
)

func TestRecoveryReadersSeparateTimestampsAndRevalidateAfterEviction(t *testing.T) {
	source, target := []byte("installed"), []byte("basis")
	expected, err := msdelta.CreateReversePSFRecord(source, target, 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cache := bytecache.New(int64(len(expected)))
	calls := 0
	corrupt := false
	loader := func() ([]byte, error) {
		calls++
		data := append([]byte(nil), expected...)
		if corrupt {
			data[len(data)-1] ^= 1
		}
		return data, nil
	}
	a, err := newRecoveryReader(cache, bytecache.Key{Index: 7, Source: 0}, loader)
	if err != nil {
		t.Fatal(err)
	}
	if hash, verified := a.VerifiedSHA256(); !verified || hash != sha256.Sum256(expected) || calls != 1 {
		t.Fatal("initial generation did not establish immutable content identity")
	}
	b, err := newRecoveryReader(cache, bytecache.Key{Index: 7, Source: 1}, func() ([]byte, error) {
		return msdelta.CreateReversePSFRecord(source, target, 1, 1024)
	})
	if err != nil {
		t.Fatal(err)
	}
	bdata, err := io.ReadAll(io.NewSectionReader(b, 0, b.Size()))
	if err != nil || bytes.Equal(bdata, expected) {
		t.Fatal("timestamp cache collision", err)
	}
	adata, err := io.ReadAll(io.NewSectionReader(a, 0, a.Size()))
	if err != nil || !bytes.Equal(adata, expected) || calls != 2 {
		t.Fatal("regeneration failed", err, calls)
	}
	recovered, err := msdelta.ApplyPSFRecordBounded(source, adata, 1024)
	if err != nil || !bytes.Equal(recovered, target) {
		t.Fatal("regenerated content", err)
	}
	if _, err := b.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
	corrupt = true
	if _, err := a.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("accepted changed record after eviction")
	}
	if cache.Stats().Bytes > int64(len(expected)) {
		t.Fatal("unbounded retention")
	}
}

func TestRecoveryReaderPropagatesGenerationFailure(t *testing.T) {
	failure := errors.New("basis integrity failure")
	if _, err := newRecoveryReader(bytecache.New(1024), bytecache.Key{}, func() ([]byte, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatal("lost initial failure", err)
	}
	if _, err := newRecoveryReader(bytecache.New(1024), bytecache.Key{}, func() ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("accepted empty recovery")
	}
}
