package c2r

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/tinyrange/trex/storage"
)

const maxBlock = 64 << 20

type hashRecord struct {
	offset, size int64
	digest       [32]byte
}
type block struct{ logical, stored hashRecord }

// Entry is a borrowed, lazy stream member. Paths are package-relative, not
// installed Windows paths. Reading verifies stored block digests; Verify also
// checks the complete decoded file digest.
type Entry struct {
	Path     string
	Tags     int64
	Packages []string
	blocks   []block
	hash     hashRecord
	archive  *Archive
}
type Archive struct {
	Entries []*Entry
	source  storage.Reader
	mu      sync.Mutex
	cached  *block
	data    []byte
}

func (d *Database) table(name, types string) (map[int64][]Cell, error) {
	rows, ok := d.Tables[name]
	if !ok {
		return nil, fmt.Errorf("c2r: missing table %s", name)
	}
	out := map[int64][]Cell{}
	for _, r := range rows {
		if len(r) != len(types) {
			return nil, fmt.Errorf("c2r: %s column count", name)
		}
		for i, c := range r {
			if c.IsText != (types[i] == 's') {
				return nil, fmt.Errorf("c2r: %s column type", name)
			}
		}
		if r[0].Number <= 0 || out[r[0].Number] != nil {
			return nil, fmt.Errorf("c2r: %s invalid/duplicate ID", name)
		}
		out[r[0].Number] = r
	}
	return out, nil
}
func safePath(s string) (string, error) {
	s = strings.ReplaceAll(s, "\\", "/")
	if strings.HasPrefix(s, "/") || strings.ContainsAny(s, ":\x00") {
		return "", fmt.Errorf("c2r: unsafe path %q", s)
	}
	var parts []string
	for _, p := range strings.Split(s, "/") {
		if p == ".." || p == "." {
			return "", fmt.Errorf("c2r: unsafe path %q", s)
		}
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("c2r: empty path")
	}
	return strings.Join(parts, "/"), nil
}

// Open indexes a full stream and its UnityDB. It does not select a product,
// apply deltas, interpret installation manifests, or authenticate the publisher.
func Open(database, stream storage.Reader) (*Archive, error) {
	d, err := ReadDatabase(database)
	if err != nil {
		return nil, err
	}
	return openDatabase(d, stream)
}
func openDatabase(d *Database, stream storage.Reader) (*Archive, error) {
	schemas := map[string]string{"SchemaVersions": "nns", "Builds": "nnnnn", "Algorithms": "ns", "Digests": "ns", "Hashes": "nnnnn", "Directories": "ns", "Paths": "nnsn", "Files": "nnnnnnn", "Blocks": "nnnn", "BlockSource": "nnnn", "Media": "nnnss", "Packages": "nnnsn", "PackagesToPaths": "nnnn"}
	tables := map[string]map[int64][]Cell{}
	for name, types := range schemas {
		t, err := d.table(name, types)
		if err != nil {
			return nil, err
		}
		tables[name] = t
	}
	if len(tables["SchemaVersions"]) != 1 || tables["SchemaVersions"][1] == nil || tables["SchemaVersions"][1][1].Number != 5 {
		return nil, fmt.Errorf("c2r: unsupported schema")
	}
	if len(tables["Builds"]) != 1 || tables["Builds"][1] == nil || len(tables["Media"]) != 1 || tables["Media"][1] == nil || tables["Media"][1][1].Number != 1 || tables["Media"][1][2].Number != 1 {
		return nil, fmt.Errorf("c2r: expected single full stream")
	}
	hashes := map[int64]hashRecord{}
	for id, r := range tables["Hashes"] {
		alg, ok := tables["Algorithms"][r[1].Number]
		if !ok || alg[1].Text != "SHA256" {
			return nil, fmt.Errorf("c2r: unsupported hash algorithm")
		}
		dr, ok := tables["Digests"][r[4].Number]
		if !ok {
			return nil, fmt.Errorf("c2r: missing digest")
		}
		digest, err := base64.StdEncoding.Strict().DecodeString(dr[1].Text)
		if err != nil || len(digest) != 32 {
			return nil, fmt.Errorf("c2r: invalid digest")
		}
		if r[2].Number < 0 || r[3].Number < 0 || r[2].Number > 1<<40 || r[3].Number > 1<<40 {
			return nil, fmt.Errorf("c2r: invalid hash extent")
		}
		h := hashRecord{offset: r[2].Number, size: r[3].Number}
		copy(h.digest[:], digest)
		hashes[id] = h
	}
	paths := map[int64]string{}
	for id, r := range tables["Paths"] {
		dir, ok := tables["Directories"][r[1].Number]
		if !ok {
			return nil, fmt.Errorf("c2r: missing directory")
		}
		joined := r[2].Text
		if dir[1].Text != "" {
			joined = dir[1].Text + "/" + joined
		}
		name, err := safePath(joined)
		if err != nil {
			return nil, err
		}
		paths[id] = name
	}
	packages := map[int64][]string{}
	for _, r := range tables["PackagesToPaths"] {
		pkg, ok := tables["Packages"][r[3].Number]
		if !ok || paths[r[2].Number] == "" || r[1].Number != 1 || pkg[1].Number != 1 {
			return nil, fmt.Errorf("c2r: invalid package reference")
		}
		packages[r[2].Number] = append(packages[r[2].Number], pkg[3].Text)
	}
	for id := range packages {
		sort.Strings(packages[id])
	}
	a := &Archive{source: stream}
	files := map[int64]*Entry{}
	seen := map[string]bool{}
	for _, r := range d.Tables["Files"] {
		h, ok := hashes[r[3].Number]
		name := paths[r[2].Number]
		if !ok || h.offset != 0 || name == "" || paths[r[5].Number] == "" || r[1].Number != 1 || r[4].Number != 1 || (r[6].Number != 1024 && r[6].Number != 0) {
			return nil, fmt.Errorf("c2r: unsupported file record")
		}
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("c2r: duplicate member path %q", name)
		}
		seen[strings.ToLower(name)] = true
		e := &Entry{Path: name, Tags: r[6].Number, Packages: packages[r[2].Number], hash: h, archive: a}
		files[r[0].Number] = e
		a.Entries = append(a.Entries, e)
	}
	sources := map[int64]hashRecord{}
	for _, r := range tables["BlockSource"] {
		h, ok := hashes[r[3].Number]
		if !ok || r[1].Number != 1 || tables["Blocks"][r[2].Number] == nil || h.size <= 0 || h.size > maxBlock || h.offset > stream.Size() || h.size > stream.Size()-h.offset {
			return nil, fmt.Errorf("c2r: invalid source block")
		}
		if _, ok := sources[r[2].Number]; ok {
			return nil, fmt.Errorf("c2r: multiple block sources unsupported")
		}
		sources[r[2].Number] = h
	}
	for id, r := range tables["Blocks"] {
		h, ok := hashes[r[3].Number]
		source, has := sources[id]
		e := files[r[2].Number]
		if !ok || !has || e == nil || r[1].Number != 1 || h.size > maxBlock || h.size <= 0 || h.digest != source.digest || h.offset > e.Size() || h.size > e.Size()-h.offset {
			return nil, fmt.Errorf("c2r: invalid logical block")
		}
		e.blocks = append(e.blocks, block{logical: h, stored: source})
	}
	for _, e := range a.Entries {
		sort.Slice(e.blocks, func(i, j int) bool { return e.blocks[i].logical.offset < e.blocks[j].logical.offset })
		var end int64
		for _, b := range e.blocks {
			if b.logical.offset != end {
				return nil, fmt.Errorf("c2r: gapped/overlapping blocks in %s", e.Path)
			}
			end += b.logical.size
		}
		if end != e.Size() {
			return nil, fmt.Errorf("c2r: incomplete member %s", e.Path)
		}
	}
	return a, nil
}
func (e *Entry) Size() int64 { return e.hash.size }
func (a *Archive) decode(b *block) ([]byte, error) {
	if a.cached == b {
		return a.data, nil
	}
	encoded := make([]byte, b.stored.size)
	if _, err := a.source.ReadAt(encoded, b.stored.offset); err != nil {
		return nil, err
	}
	if sha256.Sum256(encoded) != b.stored.digest {
		return nil, fmt.Errorf("c2r: stored block SHA-256 mismatch")
	}
	data, err := inflate(encoded, b.logical.size)
	if err != nil {
		return nil, err
	}
	a.cached = b
	a.data = data
	return data, nil
}
func (e *Entry) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("c2r: negative read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= e.Size() {
		return 0, io.EOF
	}
	a := e.archive
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	i := sort.Search(len(e.blocks), func(i int) bool { return e.blocks[i].logical.offset+e.blocks[i].logical.size > off })
	for i < len(e.blocks) && n < len(p) {
		b := &e.blocks[i]
		data, err := a.decode(b)
		if err != nil {
			return n, err
		}
		copied := copy(p[n:], data[off-b.logical.offset:])
		n += copied
		off += int64(copied)
		i++
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (e *Entry) Verify() error {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(e, 0, e.Size())); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), e.hash.digest[:]) {
		return fmt.Errorf("c2r: file SHA-256 mismatch: %s", e.Path)
	}
	return nil
}
