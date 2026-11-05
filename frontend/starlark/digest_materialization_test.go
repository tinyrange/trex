package starlarkfrontend

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// This fixture models the portable verified-reader contract: a first read
// validates every byte, and only then may its immutable identity be returned.
type materializingDigestReader struct {
	data      []byte
	expected  [32]byte
	verified  bool
	publish   bool
	readBytes int
	size      int64
}

func (r *materializingDigestReader) Size() int64 { return r.size }
func (r *materializingDigestReader) ReadAt(p []byte, off int64) (int, error) {
	if r.publish {
		if sha256.Sum256(r.data) != r.expected {
			return 0, io.ErrUnexpectedEOF
		}
		r.verified = true
	}
	n, err := bytes.NewReader(r.data).ReadAt(p, off)
	r.readBytes += n
	return n, err
}
func (r *materializingDigestReader) VerifiedSHA256() ([32]byte, bool) { return r.expected, r.verified }

func TestDigestManyReusesIdentityOnlyAfterCompleteMaterialization(t *testing.T) {
	data := bytes.Repeat([]byte("full payload validation"), 10000)
	for _, publish := range []bool{false, true} {
		for _, algorithm := range []string{"sha256", "sha1"} {
			r := &materializingDigestReader{data: data, expected: sha256.Sum256(data), publish: publish, size: int64(len(data))}
			got, err := digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{starfile.NewReader("materializing", r)})}, []starlark.Tuple{{starlark.String("algorithm"), starlark.String(algorithm)}})
			want, we := digestBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, []starlark.Tuple{{starlark.String("algorithm"), starlark.String(algorithm)}})
			if err != nil || we != nil || got.(*starlark.List).Index(0) != want {
				t.Fatal(algorithm, publish, err, we)
			}
			expectedReads := len(data)
			if publish && algorithm == "sha256" {
				expectedReads = 32 << 10
			}
			if r.readBytes != expectedReads {
				t.Fatalf("read %d, expected %d (publish=%v %s)", r.readBytes, expectedReads, publish, algorithm)
			}
		}
	}
	for _, corrupt := range []bool{false, true} {
		r := &materializingDigestReader{data: data, expected: sha256.Sum256(data), publish: corrupt, size: int64(len(data)) + 1}
		if corrupt {
			r.expected[0] ^= 1
		}
		got, err := digestManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{starfile.NewReader("bad", r)})}, nil)
		if err == nil || got != nil {
			t.Fatal("accepted corrupt or truncated payload", got, err)
		}
	}
}
