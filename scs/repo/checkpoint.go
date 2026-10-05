package repo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const checkpointPage byte = 10
const checkpointEnd byte = 11
const checkpointFooterSize = headerSize + 24

type checkpointRoots struct {
	Refs map[string]ID
	Git  map[string]ID
}

// Checkpoint builds an in-file paged index once for optimized repositories.
// Subsequent durable writes maintain incremental index runs automatically; an
// already-indexed checkpoint only syncs pending changes. Data records remain
// immutable. Missing or torn tail locators fall back to a physical scan.
func (r *Repository) Checkpoint() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	if !r.optimized {
		return r.sync()
	}
	return r.buildFastIndex()
}
func (r *Repository) legacyCheckpoint() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	if !r.optimized {
		return r.sync()
	}
	if err := r.sync(); err != nil {
		return err
	}
	if err := r.discardCheckpoint(); err != nil {
		return err
	}
	start := r.end
	// Object and Git metadata are emitted together: no per-object reads on reopen.
	gitByID := make(map[objectKey]GitOID, len(r.gitObjects))
	for oid, v := range r.gitObjects {
		gitByID[v.ID] = oid
	}
	page := []byte{0}
	emit := func() error {
		compressed := r.bodyCodec().enc.EncodeAll(page, nil)
		if len(compressed) > maxRecord {
			return errors.New("checkpoint page too large")
		}
		_, err := r.appendCheckpointRecord(checkpointPage, compressed)
		page = []byte{0}
		return err
	}
	for id, loc := range r.objects {
		raw := id[:]
		page = append(page, raw...)
		page = binary.BigEndian.AppendUint64(page, uint64(loc.offset))
		page = binary.BigEndian.AppendUint32(page, uint32(loc.size))
		page = binary.BigEndian.AppendUint32(page, uint32(loc.stored))
		page = append(page, loc.kind, loc.depth)
		if loc.kind == gitObjectKind || loc.kind == bodyKind {
			oid, ok := gitByID[id]
			if !ok {
				if loc.kind == gitObjectKind {
					return errors.New("missing Git checkpoint metadata")
				}
				page = append(page, 0)
			} else {
				v := r.gitObjects[oid]
				page = append(page, 1)
				page = append(page, oid[:]...)
				page = append(page, v.Kind)
				if loc.kind == gitObjectKind {
					var raw [32]byte
					if v.Body != (objectKey{}) {
						b := v.Body[:]
						copy(raw[:], b)
					}
					page = append(page, raw[:]...)
					page = binary.BigEndian.AppendUint64(page, uint64(v.Size))
				}
			}
		}

		if len(page) > 1<<20 {
			if err := emit(); err != nil {
				return err
			}
		}
	}
	if len(page) > 1 {
		if err := emit(); err != nil {
			return err
		}
	}
	meta, err := json.Marshal(checkpointRoots{r.refs, r.gitCatalogs})
	if err != nil {
		return err
	}
	page = append([]byte{1}, meta...)
	if err = emit(); err != nil {
		return err
	}
	footer := binary.BigEndian.AppendUint64(nil, uint64(start))
	footer = binary.BigEndian.AppendUint64(footer, uint64(r.end))
	footer = binary.BigEndian.AppendUint64(footer, uint64(len(r.objects)))
	if _, err = r.appendCheckpointRecord(checkpointEnd, footer); err != nil {
		return err
	}
	r.checkpointStart = start
	return r.sync()
}
func (r *Repository) appendCheckpointRecord(kind byte, data []byte) (ID, error) {
	id := digest(kind, data)
	off := r.end
	var h [headerSize]byte
	h[0] = kind
	binary.BigEndian.PutUint64(h[1:9], uint64(len(data)))
	raw, _ := hex.DecodeString(string(id))
	copy(h[9:], raw)
	if err := writePart(r.writer, h[:]); err != nil {
		r.poisoned = err
		return "", err
	}
	if err := writePart(r.writer, data); err != nil {
		r.poisoned = err
		return "", err
	}
	r.end = off + headerSize + int64(len(data))
	return id, nil
}
func (r *Repository) loadCheckpoint(fileSize int64) (bool, error) {
	if !r.optimized || fileSize < int64(len(magic))+checkpointFooterSize {
		return false, nil
	}
	tail := make([]byte, checkpointFooterSize)
	if _, err := r.f.ReadAt(tail, fileSize-checkpointFooterSize); err != nil {
		return false, err
	}
	if tail[0] != checkpointEnd || binary.BigEndian.Uint64(tail[1:9]) != 24 {
		return false, nil
	}
	if digest(checkpointEnd, tail[headerSize:]) != ID(hex.EncodeToString(tail[9:41])) {
		return false, nil
	}
	data := tail[headerSize:]
	start := int64(binary.BigEndian.Uint64(data))
	end := int64(binary.BigEndian.Uint64(data[8:]))
	count := binary.BigEndian.Uint64(data[16:])
	if start < int64(len(magic)) || end != fileSize-checkpointFooterSize || start > end || count > uint64(start/headerSize) {
		return false, errors.New("invalid checkpoint bounds")
	}
	r.gitStats = GitStats{Types: map[string]GitTypeStats{}}
	r.gitObjects = map[GitOID]gitLocation{}
	roots := checkpointRoots{}
	sawRoots := false
	for off := start; off < end; {
		var h [headerSize]byte
		if _, err := r.f.ReadAt(h[:], off); err != nil {
			return false, err
		}
		n := binary.BigEndian.Uint64(h[1:9])
		if h[0] != checkpointPage || n > maxRecord || int64(n) > end-off-headerSize {
			return false, errors.New("invalid checkpoint page")
		}
		b := make([]byte, int(n))
		if _, err := r.f.ReadAt(b, off+headerSize); err != nil {
			return false, err
		}
		if digest(checkpointPage, b) != ID(hex.EncodeToString(h[9:])) {
			return false, errors.New("checkpoint checksum mismatch")
		}
		b, err := r.bodyCodec().dec.DecodeAll(b, nil)
		if err != nil {
			return false, err
		}
		if len(b) == 0 || len(b) > maxRecord {
			return false, errors.New("invalid checkpoint decoded size")
		}
		switch b[0] {
		case 1:
			if sawRoots {
				return false, errors.New("duplicate checkpoint roots")
			}
			if err := json.Unmarshal(b[1:], &roots); err != nil {
				return false, err
			}
			sawRoots = true
		case 0:
			b = b[1:]
			for len(b) > 0 {
				if len(b) < 50 {
					return false, io.ErrUnexpectedEOF
				}
				id := keyBytes(b[:32])
				loc := location{offset: int64(binary.BigEndian.Uint64(b[32:40])), size: int(binary.BigEndian.Uint32(b[40:44])), stored: int(binary.BigEndian.Uint32(b[44:48])), kind: b[48], depth: b[49]}
				b = b[50:]
				physical := loc.size
				if loc.kind == bodyKind {
					physical = loc.stored
				}
				if loc.offset < int64(len(magic))+headerSize || loc.offset > start || int64(physical) > start-loc.offset || loc.kind < blockKind || loc.kind > bodyKind || loc.kind == refsKind || loc.depth > maxBodyDepth {
					return false, errors.New("invalid checkpoint location")
				}
				if _, ok := r.objects[id]; ok {
					return false, errors.New("duplicate checkpoint ID")
				}
				r.objects[id] = loc
				if loc.kind == gitObjectKind || loc.kind == bodyKind {
					if len(b) < 1 {
						return false, io.ErrUnexpectedEOF
					}
					flag := b[0]
					b = b[1:]
					if flag > 1 || flag == 0 && loc.kind == gitObjectKind {
						return false, errors.New("invalid Git checkpoint flag")
					}
					if flag == 1 {
						if len(b) < 34 {
							return false, io.ErrUnexpectedEOF
						}
						var oid GitOID
						copy(oid[:], b[:33])
						v := gitLocation{ID: id, Body: id, Size: int64(loc.size), Kind: b[33]}
						b = b[34:]
						if loc.kind == gitObjectKind {
							if len(b) < 40 {
								return false, io.ErrUnexpectedEOF
							}
							v.Body = objectKey{}
							if !bytes.Equal(b[:32], make([]byte, 32)) {
								v.Body = keyBytes(b[:32])
							}
							v.Size = int64(binary.BigEndian.Uint64(b[32:40]))
							b = b[40:]
						}
						if !oid.Valid() || v.Size < 0 || v.Size > maxBody || v.Kind < GitCommit || v.Kind > GitTag {
							return false, errors.New("invalid checkpoint Git metadata")
						}
						if _, ok := r.gitObjects[oid]; ok {
							return false, errors.New("duplicate checkpoint Git ID")
						}
						if err := r.registerGitLocation(oid, v); err != nil {
							return false, err
						}
					}
				}

			}
		default:
			return false, errors.New("invalid checkpoint page type")
		}
		off += headerSize + int64(n)
	}
	if !sawRoots || roots.Refs == nil || uint64(len(r.objects)) != count {
		return false, errors.New("incomplete checkpoint")
	}
	r.refs = roots.Refs
	r.gitCatalogs = roots.Git
	for name, id := range r.refs {
		if !validName(name) || r.objects[key(id)].kind != snapshotKind {
			return false, errors.New("invalid checkpoint workspace")
		}
	}
	for _, v := range r.gitObjects {
		if v.Body != (objectKey{}) {
			loc, ok := r.objects[v.Body]
			if !ok || loc.kind != bodyKind || int64(loc.size) != v.Size || v.ID != v.Body && !r.earlierKey(v.Body, v.ID) {
				return false, errors.New("invalid checkpoint Git body")
			}
		}
	}
	for name, id := range r.gitCatalogs {
		var c GitCatalog
		if err := r.getJSON(id, gitCatalogKind, &c); err != nil {
			return false, err
		}
		if c.Name != name {
			return false, errors.New("checkpoint catalog name mismatch")
		}
		if err := r.validateGitCatalog(c); err != nil {
			return false, err
		}
	}
	r.checkpointStart = start
	return true, nil
}

// Scrub verifies every persisted record and native base linkage. canonical=true
// also reconstructs and hashes every native body, including unreachable bodies.
func (r *Repository) Scrub(canonical bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	if err := r.flush(); err != nil {
		return err
	}
	probe := &Repository{f: r.f, objects: map[objectKey]location{}, refs: map[string]ID{}, skipCheckpoint: true}
	if err := probe.scan(); err != nil {
		return err
	}
	if canonical {
		for id, loc := range probe.objects {
			if loc.kind == bodyKind {
				if _, err := probe.getRaw(id, bodyKind); err != nil {
					return fmt.Errorf("body %s: %w", id, err)
				}
			}
		}
	}
	if probe.codec != nil {
		probe.codec.close()
	}
	return nil
}
