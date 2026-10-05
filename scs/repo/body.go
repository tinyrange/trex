package repo

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/klauspost/compress/zstd"
)

const maxBody = 1 << 30
const maxBodyDepth = 16
const bodyCacheLimit = 256 << 20

// Extent is either a slice of an immutable base or literal bytes. This native
// representation is independent of Git's delta instruction encoding.
type Extent struct {
	Offset, Length uint64
	Data           []byte
}
type cachedBody struct {
	id   objectKey
	data []byte
}
type bodyCodec struct {
	enc   *zstd.Encoder
	dec   *zstd.Decoder
	cache map[objectKey]*list.Element
	lru   *list.List
	bytes int
}

func (r *Repository) bodyCodec() *bodyCodec {
	if r.codec == nil {
		e, _ := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithWindowSize(1<<20))
		d, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxBody+1<<20))
		r.codec = &bodyCodec{enc: e, dec: d, cache: map[objectKey]*list.Element{}, lru: list.New()}
	}
	return r.codec
}
func (c *bodyCodec) close()                          { c.enc.Close(); c.dec.Close() }
func (c *bodyCodec) remember(id objectKey, b []byte) { c.rememberBody(id, b, true) }

// Decoder-owned bytes can be shared by immutable readers and the cache.
func (c *bodyCodec) rememberOwned(id objectKey, b []byte) { c.rememberBody(id, b, false) }
func (c *bodyCodec) rememberBody(id objectKey, b []byte, clone bool) {
	if len(b) > bodyCacheLimit/4 {
		return
	}
	if e := c.cache[id]; e != nil {
		c.lru.MoveToFront(e)
		return
	}
	for c.bytes+len(b) > bodyCacheLimit {
		e := c.lru.Back()
		v := e.Value.(cachedBody)
		delete(c.cache, v.id)
		c.bytes -= len(v.data)
		c.lru.Remove(e)
	}
	if clone {
		b = bytes.Clone(b)
	}
	c.cache[id] = c.lru.PushFront(cachedBody{id, b})
	c.bytes += len(b)
}

// body payload: version, depth, decoded length:u64, native base ID (zero for
// literals), zstd-compressed native extent instructions, physical SHA-256.
// Identity hashes the reconstructed bytes, never the compression or base choice.
func (r *Repository) inspectBody(data []byte, off int64) (location, error) {
	if len(data) < 74 || (data[0] != 1 && data[0] != 2) || data[1] > maxBodyDepth {
		return location{}, errors.New("invalid native body header")
	}
	sum := sha256.Sum256(data[:len(data)-32])
	if !bytes.Equal(sum[:], data[len(data)-32:]) {
		return location{}, errors.New("native body physical checksum mismatch")
	}
	if _, _, _, err := bodyIdentity(data); err != nil {
		return location{}, err
	}
	n := binary.BigEndian.Uint64(data[2:10])
	if n > maxBody {
		return location{}, errors.New("native body too large")
	}
	if data[1] != 0 {
		base := keyBytes(data[10:42])
		loc, ok := r.lookupObject(base)
		if !ok || loc.kind != bodyKind || loc.offset >= off || loc.depth+1 != data[1] {
			return location{}, errors.New("invalid native base reference")
		}
	} else if !bytes.Equal(data[10:42], make([]byte, 32)) {
		return location{}, errors.New("literal body has base")
	}
	return location{offset: off, size: int(n), kind: bodyKind, stored: len(data), depth: data[1]}, nil
}
func nativeOps(extents []Extent) []byte {
	var b []byte
	for _, e := range extents {
		if e.Length == 0 {
			continue
		}
		if e.Data != nil {
			b = binary.AppendUvarint(b, e.Length<<1)
			b = append(b, e.Data...)
		} else {
			b = binary.AppendUvarint(b, e.Length<<1|1)
			b = binary.AppendUvarint(b, e.Offset)
		}
	}
	return b
}

// ApplyExtents bounds-checks native copy/literal operations before reconstruction.
func ApplyExtents(base []byte, extents []Extent, size uint64) ([]byte, error) {
	if size > maxBody {
		return nil, errors.New("native body limit")
	}
	out := make([]byte, 0, int(size))
	for _, e := range extents {
		if e.Length > size-uint64(len(out)) {
			return nil, errors.New("extent output overflow")
		}
		if e.Data != nil {
			if uint64(len(e.Data)) != e.Length {
				return nil, errors.New("literal size mismatch")
			}
			out = append(out, e.Data...)
		} else {
			if e.Offset > uint64(len(base)) || e.Length > uint64(len(base))-e.Offset {
				return nil, errors.New("extent outside base")
			}
			out = append(out, base[e.Offset:e.Offset+e.Length]...)
		}
	}
	if uint64(len(out)) != size {
		return nil, errors.New("extent size mismatch")
	}
	return out, nil
}
func (r *Repository) putBody(body []byte, base ID, extents []Extent) (ID, error) {
	return r.putBodyIdentity(body, base, extents, GitOID{}, 0)
}
func (r *Repository) putBodyIdentity(body []byte, base ID, extents []Extent, oid GitOID, kind byte) (ID, error) {
	if len(body) > maxBody {
		return "", errors.New("native body limit")
	}
	id := digest(bodyKind, body)
	if _, ok := r.lookupObject(key(id)); ok {
		return id, nil
	}
	c := r.bodyCodec()
	depth := byte(0)
	ops := nativeOps([]Extent{{Length: uint64(len(body)), Data: body}})
	if base != "" {
		loc, ok := r.lookupObject(key(base))
		if !ok || loc.kind != bodyKind {
			return "", errors.New("native base not found")
		}
		if loc.depth < maxBodyDepth {
			candidate := nativeOps(extents)
			if len(candidate) < len(ops) {
				ops = candidate
				depth = loc.depth + 1
			}
		}
	}
	data := make([]byte, 42)
	data[0] = 1
	data[1] = depth
	binary.BigEndian.PutUint64(data[2:10], uint64(len(body)))
	if depth != 0 {
		raw, _ := hex.DecodeString(string(base))
		copy(data[10:], raw)
	}
	if oid.Valid() {
		data[0] = 2
		data = append(data, kind, oid[32])
		data = append(data, oid[:oid[32]]...)
	}
	data = c.enc.EncodeAll(ops, data)
	sum := sha256.Sum256(data)
	data = append(data, sum[:]...)
	_, err := r.appendEncoded(bodyKind, id, data, len(body), depth)
	if err == nil {
		if oid.Valid() {
			err = r.registerBodyGit(id, data)
		}
		if r.verifiedBodies == nil {
			r.verifiedBodies = map[objectKey][32]byte{}
		}
		r.verifiedBodies[key(id)] = sum
		c.remember(key(id), body)
	}
	return id, err
}

// readBody returns caller-owned mutable bytes, as required by ReadFile.
func (r *Repository) readBody(id objectKey, loc location) ([]byte, error) {
	data, err := r.readBodyShared(id, loc)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(data), nil
}

// readBodyShared returns immutable bytes under Repository.mu. Never expose a
// mutable alias through public APIs. Readers may retain these bytes after eviction.
func (r *Repository) readBodyShared(id objectKey, loc location) ([]byte, error) {
	c := r.bodyCodec()
	if e := c.cache[id]; e != nil {
		c.lru.MoveToFront(e)
		return e.Value.(cachedBody).data, nil
	}
	if err := r.flush(); err != nil {
		return nil, err
	}
	data := make([]byte, loc.stored)
	if _, err := r.f.ReadAt(data, loc.offset); err != nil {
		return nil, err
	}
	checked, err := r.inspectBody(data, loc.offset)
	if err != nil {
		return nil, err
	}
	if checked.size != loc.size || checked.depth != loc.depth {
		return nil, errors.New("native index mismatch")
	}
	_, _, opsStart, err := bodyIdentity(data)
	if err != nil {
		return nil, err
	}
	ops, err := c.dec.DecodeAll(data[opsStart:len(data)-32], nil)
	if err != nil {
		return nil, err
	}
	var base []byte
	if loc.depth != 0 {
		baseID := keyBytes(data[10:42])
		baseLoc, ok := r.lookupObject(baseID)
		if !ok || baseLoc.kind != bodyKind {
			return nil, errors.New("missing native base")
		}
		base, err = r.readBodyShared(baseID, baseLoc)
		if err != nil {
			return nil, err
		}
	}
	out := make([]byte, 0, loc.size)
	for len(ops) > 0 {
		v, n := binary.Uvarint(ops)
		if n <= 0 {
			return nil, errors.New("invalid native extent")
		}
		ops = ops[n:]
		length := v >> 1
		if length == 0 || length > uint64(loc.size-len(out)) {
			return nil, errors.New("invalid native extent length")
		}
		if v&1 == 0 {
			if length > uint64(len(ops)) {
				return nil, errors.New("truncated literal")
			}
			out = append(out, ops[:length]...)
			ops = ops[length:]
		} else {
			offset, n := binary.Uvarint(ops)
			if n <= 0 || offset > uint64(len(base)) || length > uint64(len(base))-offset {
				return nil, errors.New("invalid native copy")
			}
			ops = ops[n:]
			out = append(out, base[offset:offset+length]...)
		}
	}
	var encoded [32]byte
	copy(encoded[:], data[len(data)-32:])
	proof, verified := r.verifiedBodies[id]
	if len(out) != loc.size || ((!verified || proof != encoded) && digestKey(bodyKind, out) != id) {
		return nil, errors.New("native canonical checksum mismatch")
	}
	if r.verifiedBodies == nil {
		r.verifiedBodies = map[objectKey][32]byte{}
	}
	r.verifiedBodies[id] = encoded
	c.rememberOwned(id, out)
	return out, nil
}
func (r *Repository) Optimized() bool { return r.optimized }

func (r *Repository) borrowBody(id ID) ([]byte, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	if !validID(id) {
		return nil, errors.New("invalid body ID")
	}
	loc, ok := r.lookupObject(key(id))
	if !ok || loc.kind != bodyKind {
		return nil, errors.New("missing native body")
	}
	return r.readBodyShared(key(id), loc)
}
