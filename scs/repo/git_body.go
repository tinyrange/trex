package repo

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/pjbgf/sha1cd"
	"hash"
)

// IngestGitBody converts a full body or native base-relative extents into a
// verified Git object. The returned bytes are owned by the caller. No transport
// bytes, compression or Git delta instructions enter the native representation.
func (r *Repository) IngestGitBody(ctx context.Context, kind byte, full []byte, base GitOID, extents []Extent, size uint64) (GitOID, []byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, _, body, err := r.ingestBody(ctx, kind, full, base, extents, size, GitOID{})
	return id, body, err
}
func (r *Repository) ingestBody(ctx context.Context, kind byte, full []byte, base GitOID, extents []Extent, size uint64, expected GitOID) (GitOID, ID, []byte, error) {
	if err := ctx.Err(); err != nil {
		return GitOID{}, "", nil, err
	}
	if err := r.ready(); err != nil {
		return GitOID{}, "", nil, err
	}
	if !r.optimized || kind < GitCommit || kind > GitTag || size > maxBody {
		return GitOID{}, "", nil, errors.New("invalid optimized Git body")
	}
	body := full
	var nativeBase ID
	if base.Valid() {
		v, ok := r.lookupGit(base)
		if !ok || v.Kind != kind || v.Body == (objectKey{}) {
			return GitOID{}, "", nil, errors.New("invalid Git base")
		}
		nativeBase = v.Body.ID()
		b, err := r.getRaw(v.Body, bodyKind)
		if err != nil {
			return GitOID{}, "", nil, err
		}
		body, err = ApplyExtents(b, extents, size)
		if err != nil {
			return GitOID{}, "", nil, err
		}
	} else if uint64(len(body)) != size {
		return GitOID{}, "", nil, errors.New("Git body size mismatch")
	}
	var h hash.Hash = sha1cd.New()
	if expected[32] == 32 {
		h = sha256.New()
	}
	fmt.Fprintf(h, "%s %d%c", GitTypeName(kind), len(body), 0)
	h.Write(body)
	oid, _ := GitOIDFromBytes(h.Sum(nil))
	if expected.Valid() && oid != expected {
		return GitOID{}, "", nil, errors.New("Git object checksum mismatch")
	}
	if old, ok := r.lookupGit(oid); ok {
		return oid, old.ID.ID(), body, nil
	}
	native, err := r.putBodyIdentity(body, nativeBase, extents, oid, kind)
	if err != nil {
		return GitOID{}, "", nil, err
	}
	if v, ok := r.lookupGit(oid); ok {
		return oid, v.ID.ID(), body, nil
	}
	data := []byte{2, kind, oid[32]}
	data = append(data, oid[:oid[32]]...)
	data = binary.BigEndian.AppendUint64(data, uint64(len(body)))
	raw, _ := hex.DecodeString(string(native))
	data = append(data, raw...)
	id, err := r.append(gitObjectKind, data)
	if err == nil {
		err = r.registerGit(id, data, false)
	}
	return oid, id, body, err
}
