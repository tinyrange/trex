// Package repo implements single-file, content-addressed workspace repositories.
// The experimental format is not yet a stable interchange format.
package repo

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"sync"
)

const BlockSize = 4096
const magic = "SCSREPO2"
const maxRecord = 64 << 20
const headerSize = 41 // kind, uint64 payload length, SHA-256(kind || payload)
const (
	blockKind      byte = 1
	fileKind       byte = 2
	treeKind       byte = 3
	snapshotKind   byte = 4
	refsKind       byte = 5
	indexKind      byte = 6
	gitObjectKind  byte = 7
	gitCatalogKind byte = 8
	bodyKind       byte = 9
)

type ID string

type location struct {
	offset int64
	size   int
	kind   byte
	stored int
	depth  byte
}
type catalog struct {
	Refs map[string]ID `json:"refs"`
}

// Repository owns an exclusively supplied storage backend for its lifetime. Methods are safe for
// concurrent use. Only Publish changes durable named workspace roots.
type Repository struct {
	fast            *fastState
	skipCheckpoint  bool
	checkpointStart int64
	optimized       bool
	writer          *bufio.Writer
	end             int64
	codec           *bodyCodec
	verifiedBodies  map[objectKey][32]byte
	mu              sync.Mutex
	f               repositoryFile
	objects         map[objectKey]location
	refs            map[string]ID
	poisoned        error
	gitObjects      map[GitOID]gitLocation
	gitCatalogs     map[string]ID
	gitStats        GitStats
}

func digest(kind byte, data []byte) ID {
	h := sha256.New()
	h.Write([]byte{kind})
	h.Write(data)
	return ID(hex.EncodeToString(h.Sum(nil)))
}
func validID(id ID) bool { b, e := hex.DecodeString(string(id)); return e == nil && len(b) == 32 }

// Create initializes an empty caller-owned store as SCSREPO2.
func Create(store storage.Store) (*Repository, error) { return create(store, false) }

// CreateOptimized initializes an empty store as paged/compressed SCSREPO3.
func CreateOptimized(store storage.Store) (*Repository, error) { return create(store, true) }
func create(store storage.Store, optimized bool) (*Repository, error) {
	if store == nil {
		return nil, errors.New("nil repository store")
	}
	f := &storeFile{Store: store}
	n, err := store.Length()
	if err == nil && n != 0 {
		err = errors.New("repository store is not empty")
	}
	if err != nil {
		store.Close()
		return nil, err
	}
	r := &Repository{f: f, objects: map[objectKey]location{}, refs: map[string]ID{}, optimized: optimized}
	m := magic
	if optimized {
		m = "SCSREPO3"
	}
	if err = writePart(f, []byte(m)); err == nil {
		err = f.Sync()
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	r.end = int64(len(m))
	if optimized {
		r.writer = bufio.NewWriterSize(f, 1<<20)
	}
	return r, nil
}

// Open lazily verifies records as accessed and repairs an incomplete tail.
// It takes exclusive ownership of store, including on failure.
func Open(store storage.Store) (*Repository, error) { return open(store, false) }

// OpenVerified ignores derived indexes and scans all physical records.
func OpenVerified(store storage.Store) (*Repository, error) { return open(store, true) }
func open(store storage.Store, verify bool) (*Repository, error) {
	if store == nil {
		return nil, errors.New("nil repository store")
	}
	f := &storeFile{Store: store}
	r := &Repository{f: f, objects: map[objectKey]location{}, refs: map[string]ID{}, skipCheckpoint: verify}
	if err := r.scan(); err != nil {
		r.closeFailedOpen()
		return nil, err
	}
	n, err := store.Length()
	if err != nil {
		r.closeFailedOpen()
		return nil, err
	}
	r.end = n
	if r.optimized {
		if _, err = f.Seek(r.end, io.SeekStart); err != nil {
			r.closeFailedOpen()
			return nil, err
		}
		r.writer = bufio.NewWriterSize(f, 1<<20)
	}
	return r, nil
}
func (r *Repository) scan() error {
	st, err := r.f.Stat()
	if err != nil {
		return err
	}
	m := make([]byte, len(magic))
	if _, err = r.f.ReadAt(m, 0); err != nil {
		return errors.New("invalid repository header")
	}
	if string(m) == "SCSREPO1" {
		return errors.New("unsupported repository format SCSREPO1; this build uses SCSREPO2: keep the old file and use a v1 build to recover native edits, or re-import Git into a new file")
	}
	r.optimized = string(m) == "SCSREPO3"
	if string(m) != magic && !r.optimized {
		return errors.New("invalid repository header")
	}
	r.end = st.Size()
	if !r.skipCheckpoint {
		if loaded, _, err := r.loadFastIndex(st.Size()); loaded || err != nil {
			return err
		}
		if loaded, err := r.loadCheckpoint(st.Size()); loaded || err != nil {
			return err
		}
	}
	off := int64(len(magic))
	for off < st.Size() {
		if st.Size()-off < headerSize {
			return r.trim(off)
		}
		var h [headerSize]byte
		if _, err := r.f.ReadAt(h[:], off); err != nil {
			return err
		}
		n := binary.BigEndian.Uint64(h[1:9])
		if h[0] < blockKind || h[0] > fastEndKind || (!r.optimized && h[0] > gitCatalogKind) || n > maxRecord && !(r.optimized && h[0] == bodyKind && n <= maxBody+(maxBody>>8)+(1<<20)) {
			return fmt.Errorf("invalid record at %d", off)
		}
		if int64(n) > st.Size()-off-headerSize {
			return r.trim(off)
		}
		data := make([]byte, int(n))
		if _, err := r.f.ReadAt(data, off+headerSize); err != nil {
			return err
		}
		if h[0] == bodyKind {
			if !r.optimized {
				return errors.New("native body in legacy file")
			}
			id := ID(hex.EncodeToString(h[9:]))
			loc, err := r.inspectBody(data, off+headerSize)
			if err != nil {
				return err
			}
			r.objects[key(id)] = loc
			if err := r.registerBodyGit(id, data); err != nil {
				return err
			}
			off += headerSize + int64(n)
			continue
		}
		id := digest(h[0], data)
		if string(id) != hex.EncodeToString(h[9:]) {
			return fmt.Errorf("checksum mismatch at %d", off)
		}
		if h[0] >= checkpointPage {
			off += headerSize + int64(n)
			continue
		}
		if h[0] == refsKind {
			var c catalog
			if err := json.Unmarshal(data, &c); err != nil || c.Refs == nil {
				return fmt.Errorf("invalid roots at %d", off)
			}
			for name, id := range c.Refs {
				loc, ok := r.lookupObject(key(id))
				if !validName(name) || !ok || loc.kind != snapshotKind {
					return fmt.Errorf("invalid workspace root %q", name)
				}
			}
			r.refs = c.Refs
		} else {
			r.objects[key(id)] = location{offset: off + headerSize, size: int(n), kind: h[0]}
			if h[0] == gitObjectKind {
				if err := r.registerGit(id, data, true); err != nil {
					return fmt.Errorf("Git descriptor at %d: %w", off, err)
				}
			}
			if h[0] == gitCatalogKind {
				var c GitCatalog
				if err := json.Unmarshal(data, &c); err != nil {
					return err
				}
				if err := r.validateGitCatalog(c); err != nil {
					return err
				}
				if r.gitCatalogs == nil {
					r.gitCatalogs = map[string]ID{}
				}
				r.gitCatalogs[c.Name] = id
			}
		}
		off += headerSize + int64(n)
	}
	return nil
}
func (r *Repository) trim(off int64) error {
	if err := r.f.Truncate(off); err != nil {
		return err
	}
	return r.f.Sync()
}
func (r *Repository) ready() error {
	if r.f == nil {
		return errors.New("repository is closed")
	}
	if r.poisoned != nil {
		return fmt.Errorf("repository must be reopened after write failure: %w", r.poisoned)
	}
	return nil
}
func (r *Repository) append(kind byte, data []byte) (ID, error) {
	if err := r.ready(); err != nil {
		return "", err
	}
	if len(data) > maxRecord {
		return "", errors.New("record exceeds 64 MiB format limit")
	}
	id := digest(kind, data)
	if _, ok := r.lookupObject(key(id)); ok && kind != refsKind {
		return id, nil
	}
	return r.appendEncoded(kind, id, data, len(data), 0)
}
func (r *Repository) appendEncoded(kind byte, id ID, data []byte, logical int, depth byte) (ID, error) {
	if err := r.ready(); err != nil {
		return "", err
	}
	if err := r.discardCheckpoint(); err != nil {
		return "", err
	}
	off := r.end
	if r.writer == nil {
		var err error
		off, err = r.f.Seek(0, io.SeekEnd)
		if err != nil {
			return "", err
		}
	}
	var h [headerSize]byte
	h[0] = kind
	binary.BigEndian.PutUint64(h[1:9], uint64(len(data)))
	raw, _ := hex.DecodeString(string(id))
	copy(h[9:], raw)
	var w io.Writer = r.f
	if r.writer != nil {
		w = r.writer
	}
	err := writePart(w, h[:])
	if err == nil {
		err = writePart(w, data)
	}
	if err != nil {
		r.poisoned = err
		return "", err
	}
	r.end = off + headerSize + int64(len(data))
	if kind != refsKind {
		loc := location{offset: off + headerSize, size: logical, kind: kind, depth: depth}
		if kind == bodyKind {
			loc.stored = len(data)
		}
		if r.fast != nil {
			old, exists := r.lookupObject(key(id))
			if r.poisoned != nil {
				return "", r.poisoned
			}
			if exists {
				addLocationStats(&r.fast.manifest.Stats, old, -1)
			} else {
				r.fast.manifest.Stats.ContentObjects++
			}
			addLocationStats(&r.fast.manifest.Stats, loc, 1)
			r.fast.dirty[key(id)] = loc
		}
		r.objects[key(id)] = loc
	} else if r.fast != nil {
		var c catalog
		if err := json.Unmarshal(data, &c); err != nil {
			r.poisoned = err
			return "", err
		}
		r.fast.pendingRefs = c.Refs
	}
	if kind == gitCatalogKind && r.fast != nil {
		var c GitCatalog
		if err := json.Unmarshal(data, &c); err != nil {
			r.poisoned = err
			return "", err
		}
		catalogs := map[string]ID{}
		for k, v := range r.gitCatalogs {
			catalogs[k] = v
		}
		catalogs[c.Name] = id
		r.fast.pendingCatalogs = catalogs
	}
	return id, nil
}
func (r *Repository) putJSON(kind byte, v any) (ID, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return r.append(kind, data)
}
func (r *Repository) get(id ID, kind byte) ([]byte, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid object ID %q", id)
	}
	return r.getRaw(key(id), kind)
}
func (r *Repository) getRaw(id objectKey, kind byte) ([]byte, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	loc, ok := r.lookupObject(id)
	if !ok || loc.kind != kind {
		return nil, fmt.Errorf("missing object %s (kind %d)", id, kind)
	}
	if kind == bodyKind {
		return r.readBody(id, loc)
	}
	if err := r.flush(); err != nil {
		return nil, err
	}
	b := make([]byte, loc.size)
	if _, err := r.f.ReadAt(b, loc.offset); err != nil {
		return nil, err
	}
	if digestKey(kind, b) != id {
		return nil, fmt.Errorf("corrupt object %s", id)
	}
	return b, nil
}
func (r *Repository) getJSON(id ID, kind byte, v any) error {
	b, err := r.get(id, kind)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (r *Repository) flush() error {
	if r.writer != nil {
		if err := r.writer.Flush(); err != nil {
			r.poisoned = err
			return err
		}
	}
	return nil
}
func (r *Repository) sync() error {
	if err := r.sealFast(); err != nil {
		r.poisoned = err
		return err
	}
	if err := r.flush(); err != nil {
		return err
	}
	if err := r.f.Sync(); err != nil {
		r.poisoned = err
		return err
	}
	return nil
}
func (r *Repository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	// Never retry buffered writes after a storage failure. In particular, a
	// failed fsync must not turn into a successful Close merely because Flush
	// has nothing left to write. Reopening determines the recovered root.
	err := r.poisoned
	if err == nil {
		if r.fast != nil && r.fast.sealed != r.end {
			err = r.sync()
		} else {
			err = r.flush()
		}
	}
	closeErr := r.f.Close()
	if err == nil {
		err = closeErr
	}
	if r.codec != nil {
		r.codec.close()
	}
	if r.fast != nil && r.fast.dec != nil {
		r.fast.dec.Close()
	}
	r.f = nil
	return err
}

// Refs returns a copy of the last published named roots.
func (r *Repository) Refs() map[string]ID {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]ID{}
	for n, id := range r.refs {
		out[n] = id
	}
	return out
}

func (r *Repository) closeFailedOpen() {
	r.f.Close()
	if r.codec != nil {
		r.codec.close()
	}
	if r.fast != nil && r.fast.dec != nil {
		r.fast.dec.Close()
	}
	r.f = nil
}
