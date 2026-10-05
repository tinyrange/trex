package repo

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"github.com/pjbgf/sha1cd"
)

// GitIngester owns one worker's compression state. It is not safe for concurrent
// use, but separate ingesters may write to the same repository concurrently.
// Call Close when the worker exits.
type GitIngester struct {
	r   *Repository
	enc *zstd.Encoder
}

func (r *Repository) NewGitIngester() (*GitIngester, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithWindowSize(1<<20))
	if err != nil {
		return nil, err
	}
	return &GitIngester{r, enc}, nil
}
func (w *GitIngester) Close() { w.enc.Close() }

// Ingest verifies and encodes outside the repository lock. Only immutable base
// lookup and the final append/index update hold the lock.
func (w *GitIngester) Ingest(ctx context.Context, kind byte, full []byte, base GitOID, extents []Extent, size uint64) (GitOID, []byte, error) {
	r := w.r
	if err := ctx.Err(); err != nil {
		return GitOID{}, nil, err
	}
	if !r.optimized || kind < GitCommit || kind > GitTag || size > maxBody {
		return GitOID{}, nil, errors.New("invalid optimized Git body")
	}
	var baseKey objectKey
	var baseDepth byte
	var b []byte
	r.mu.Lock()
	err := r.ready()
	if err == nil && base.Valid() {
		v, ok := r.lookupGit(base)
		if !ok || v.Kind != kind || v.Body == (objectKey{}) {
			err = errors.New("invalid Git base")
		} else {
			baseKey = v.Body
			baseLoc, _ := r.lookupObject(baseKey)
			baseDepth = baseLoc.depth
			b, err = r.getRaw(baseKey, bodyKind)
		}
	}
	r.mu.Unlock()
	if err != nil {
		return GitOID{}, nil, err
	}
	body := full
	if base.Valid() {
		body, err = ApplyExtents(b, extents, size)
	} else if uint64(len(body)) != size {
		err = errors.New("Git body size mismatch")
	}
	if err != nil {
		return GitOID{}, nil, err
	}
	h := sha1cd.New()
	fmt.Fprintf(h, "%s %d%c", GitTypeName(kind), len(body), 0)
	h.Write(body)
	oid, _ := GitOIDFromBytes(h.Sum(nil))
	id := digestKey(bodyKind, body)
	depth := byte(0)
	var ops []byte
	if base.Valid() && baseDepth < maxBodyDepth {
		ops = nativeOps(extents)
		if len(ops) < len(body) {
			depth = baseDepth + 1
		}
	}
	if depth == 0 {
		ops = nativeOps([]Extent{{Length: uint64(len(body)), Data: body}})
	}
	data := make([]byte, 42)
	data[0], data[1] = 2, depth
	binary.BigEndian.PutUint64(data[2:10], size)
	if depth != 0 {
		copy(data[10:42], baseKey[:])
	}
	data = append(data, kind, oid[32])
	data = append(data, oid[:oid[32]]...)
	data = w.enc.EncodeAll(ops, data)
	sum := sha256.Sum256(data)
	data = append(data, sum[:]...)
	if err := ctx.Err(); err != nil {
		return GitOID{}, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return GitOID{}, nil, err
	}
	if _, ok := r.lookupGit(oid); ok {
		return oid, body, nil
	}
	if _, ok := r.lookupObject(id); !ok {
		native := id.ID()
		if _, err := r.appendEncoded(bodyKind, native, data, len(body), depth); err != nil {
			return GitOID{}, nil, err
		}
		if err := r.registerBodyGit(native, data); err != nil {
			return GitOID{}, nil, err
		}
		if r.verifiedBodies == nil {
			r.verifiedBodies = map[objectKey][32]byte{}
		}
		r.verifiedBodies[id] = sum
		r.bodyCodec().remember(id, body)
	} else {
		// Identical native bytes can have more than one typed Git identity.
		descriptor := []byte{2, kind, oid[32]}
		descriptor = append(descriptor, oid[:oid[32]]...)
		descriptor = binary.BigEndian.AppendUint64(descriptor, size)
		descriptor = append(descriptor, id[:]...)
		native, err := r.append(gitObjectKind, descriptor)
		if err != nil {
			return GitOID{}, nil, err
		}
		if err := r.registerGit(native, descriptor, false); err != nil {
			return GitOID{}, nil, err
		}
	}
	return oid, body, nil
}
