package repo

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"

	"github.com/pjbgf/sha1cd"
)

// GitOID keeps Git's compatibility namespace separate from native SHA-256 IDs.
// Byte 32 is the digest length (20 or 32); unused bytes are zero.
type GitOID [33]byte

func GitOIDFromBytes(raw []byte) (GitOID, error) {
	var id GitOID
	if len(raw) != 20 && len(raw) != 32 {
		return id, errors.New("invalid Git object ID length")
	}
	copy(id[:], raw)
	id[32] = byte(len(raw))
	return id, nil
}
func ParseGitOID(text string) (GitOID, error) {
	raw, err := hex.DecodeString(text)
	if err != nil {
		return GitOID{}, err
	}
	return GitOIDFromBytes(raw)
}
func (id GitOID) Valid() bool {
	if id[32] == 32 {
		return true
	}
	if id[32] != 20 {
		return false
	}
	for _, b := range id[20:32] {
		if b != 0 {
			return false
		}
	}
	return true
}
func (id GitOID) String() string {
	if !id.Valid() {
		return ""
	}
	return hex.EncodeToString(id[:id[32]])
}

const (
	GitCommit byte = 1
	GitTree   byte = 2
	GitBlob   byte = 3
	GitTag    byte = 4
)

func GitTypeName(kind byte) string {
	switch kind {
	case GitCommit:
		return "commit"
	case GitTree:
		return "tree"
	case GitBlob:
		return "blob"
	case GitTag:
		return "tag"
	}
	return "invalid"
}
func GitType(name string) byte {
	switch name {
	case "commit":
		return GitCommit
	case "tree":
		return GitTree
	case "blob":
		return GitBlob
	case "tag":
		return GitTag
	}
	return 0
}

type gitLocation struct {
	Body objectKey
	ID   objectKey
	Size int64
	Kind byte
}
type GitObject struct {
	Body   ID
	OID    GitOID
	ID     ID
	Kind   byte
	Size   int64
	Blocks []ID
}
type GitTypeStats struct {
	Objects uint64 `json:"objects"`
	Bytes   uint64 `json:"bytes"`
}
type GitStats struct {
	Objects uint64                  `json:"objects"`
	Bytes   uint64                  `json:"logical_bytes"`
	Types   map[string]GitTypeStats `json:"types"`
}
type GitCatalog struct {
	Name         string            `json:"name"`
	Remote       string            `json:"remote"`
	Head         string            `json:"head"`
	Refs         map[string]string `json:"refs"`
	SymbolicRefs map[string]string `json:"symbolic_refs"`
	Peeled       map[string]string `json:"peeled"`
	PackBytes    int64             `json:"transport_bytes"`
	PackHash     string            `json:"transport_hash"`
	Objects      uint64            `json:"objects"`
}

// Git descriptor payload: version:u8, type:u8, digest length:u8, Git digest,
// body size:u64, then native block IDs (32 raw bytes each). No Git pack, deltas,
// index, or compression are retained. The exact canonical body is reconstructible.
func decodeGitDescriptor(data []byte) (GitOID, byte, int64, []byte, error) {
	if len(data) < 31 || (data[0] != 1 && data[0] != 2) || data[1] < GitCommit || data[1] > GitTag {
		return GitOID{}, 0, 0, nil, errors.New("invalid native Git descriptor")
	}
	n := int(data[2])
	if (n != 20 && n != 32) || len(data) < 3+n+8 {
		return GitOID{}, 0, 0, nil, errors.New("invalid Git digest")
	}
	oid, _ := GitOIDFromBytes(data[3 : 3+n])
	size := binary.BigEndian.Uint64(data[3+n : 3+n+8])
	if size > math.MaxInt64 {
		return GitOID{}, 0, 0, nil, errors.New("invalid Git object size")
	}
	ids := data[3+n+8:]
	if data[0] == 2 {
		if len(ids) != 32 {
			return GitOID{}, 0, 0, nil, errors.New("invalid native body descriptor")
		}
		return oid, data[1], int64(size), ids, nil
	}
	count := size / BlockSize
	if size%BlockSize != 0 {
		count++
	}
	if len(ids)%32 != 0 || uint64(len(ids)/32) != count {
		return GitOID{}, 0, 0, nil, errors.New("invalid Git block count")
	}
	return oid, data[1], int64(size), ids, nil
}
func (r *Repository) registerGit(id ID, data []byte, validate bool) error {
	oid, kind, size, blocks, err := decodeGitDescriptor(data)
	if err != nil {
		return err
	}
	if old, ok := r.lookupGit(oid); ok {
		if old.ID != key(id) {
			return errors.New("Git ID collision with a different native object")
		}
		return nil
	}
	var body ID
	if data[0] == 2 {
		body = ID(hex.EncodeToString(blocks))
		loc, ok := r.lookupObject(key(body))
		if !ok || loc.kind != bodyKind || int64(loc.size) != size || !r.earlier(body, id) {
			return errors.New("invalid native body descriptor reference")
		}
	}
	if validate && data[0] == 1 {
		for i := 0; i < len(blocks); i += 32 {
			b := ID(hex.EncodeToString(blocks[i : i+32]))
			loc, ok := r.lookupObject(key(b))
			expected := BlockSize
			if i+32 == len(blocks) && size%BlockSize != 0 {
				expected = int(size % BlockSize)
			}
			if !ok || loc.kind != blockKind || loc.size != expected || !r.earlier(b, id) {
				return errors.New("missing, forward, or invalid Git chunk")
			}
		}
	}
	if r.gitObjects == nil {
		r.gitObjects = map[GitOID]gitLocation{}
	}
	r.gitObjects[oid] = gitLocation{ID: key(id), Size: size, Kind: kind, Body: key(body)}
	if r.fast != nil {
		r.fast.dirtyGit[oid] = key(id)
	}
	r.gitStats.Objects++
	r.gitStats.Bytes += uint64(size)
	if r.gitStats.Types == nil {
		r.gitStats.Types = map[string]GitTypeStats{}
	}
	s := r.gitStats.Types[GitTypeName(kind)]
	s.Objects++
	s.Bytes += uint64(size)
	r.gitStats.Types[GitTypeName(kind)] = s
	return nil
}

// PutGitObject streams and verifies a canonical Git body into ordinary native
// 4 KiB chunks. Visibility of its typed descriptor is atomic on successful input.
// An unsuccessful ingestion may leave reusable unreferenced chunks, not a ref.
func (r *Repository) PutGitObject(ctx context.Context, oid GitOID, kind byte, size int64, input io.Reader) (ID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !oid.Valid() || kind < GitCommit || kind > GitTag || size < 0 {
		return "", errors.New("invalid Git object header")
	}
	if r.optimized {
		if size > maxBody {
			return "", errors.New("native body limit")
		}
		b, err := io.ReadAll(io.LimitReader(input, size+1))
		if err != nil {
			return "", err
		}
		if int64(len(b)) != size {
			return "", errors.New("Git body size mismatch")
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		_, id, _, err := r.ingestBody(ctx, kind, b, GitOID{}, nil, uint64(size), oid)
		return id, err
	}
	count := size/BlockSize + boolInt(size%BlockSize != 0)
	if count > (maxRecord-43)/32 {
		return "", errors.New("Git object exceeds native descriptor capacity")
	}
	var h hash.Hash
	if oid[32] == 20 {
		h = sha1cd.New()
	} else {
		h = sha256.New()
	}
	fmt.Fprintf(h, "%s %d%c", GitTypeName(kind), size, 0)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return "", err
	}
	data := make([]byte, 0, 3+int(oid[32])+8+int(count)*32)
	data = append(data, 1, kind, oid[32])
	data = append(data, oid[:oid[32]]...)
	data = binary.BigEndian.AppendUint64(data, uint64(size))
	var buf [BlockSize]byte
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n := int(min(remaining, BlockSize))
		if _, err := io.ReadFull(input, buf[:n]); err != nil {
			return "", err
		}
		h.Write(buf[:n])
		id, err := r.append(blockKind, buf[:n])
		if err != nil {
			return "", err
		}
		start := len(data)
		data = append(data, make([]byte, 32)...)
		if _, err = hex.Decode(data[start:], []byte(id)); err != nil {
			return "", err
		}
		remaining -= int64(n)
	}
	var extra [1]byte
	n, err := input.Read(extra[:])
	if err != io.EOF || n != 0 {
		if err != nil && err != io.EOF {
			return "", err
		}
		return "", errors.New("Git body exceeds declared size")
	}
	if got := h.Sum(nil); !equalDigest(got, oid[:oid[32]]) {
		return "", errors.New("Git object checksum mismatch")
	}
	id, err := r.append(gitObjectKind, data)
	if err != nil {
		return "", err
	}
	if err = r.registerGit(id, data, false); err != nil {
		return "", err
	}
	return id, nil
}
func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
func (r *Repository) GitObjectHeader(oid GitOID) (byte, int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.lookupGit(oid)
	return v.Kind, v.Size, ok
}
func (r *Repository) gitObject(oid GitOID) (GitObject, error) {
	v, ok := r.lookupGit(oid)
	if !ok {
		return GitObject{}, errors.New("Git object not found: " + oid.String())
	}
	if v.ID == v.Body && v.Body != (objectKey{}) {
		return GitObject{OID: oid, ID: v.ID.ID(), Body: v.Body.ID(), Kind: v.Kind, Size: v.Size}, nil
	}
	data, err := r.getRaw(v.ID, gitObjectKind)
	if err != nil {
		return GitObject{}, err
	}
	got, kind, size, raw, err := decodeGitDescriptor(data)
	if err != nil {
		return GitObject{}, err
	}
	if got != oid {
		return GitObject{}, errors.New("Git index mismatch")
	}
	if data[0] == 2 {
		return GitObject{OID: oid, ID: v.ID.ID(), Kind: kind, Size: size, Body: v.Body.ID()}, nil
	}
	obj := GitObject{OID: oid, ID: v.ID.ID(), Kind: kind, Size: size, Blocks: make([]ID, 0, len(raw)/32)}
	for i := 0; i < len(raw); i += 32 {
		obj.Blocks = append(obj.Blocks, ID(hex.EncodeToString(raw[i:i+32])))
	}
	return obj, nil
}
func (r *Repository) GitObject(oid GitOID) (GitObject, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gitObject(oid)
}
func (r *Repository) OpenGitObject(oid GitOID) (*Reader, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	obj, err := r.gitObject(oid)
	if err != nil {
		return nil, err
	}
	return &Reader{r: r, entry: Entry{Kind: "file", Size: obj.Size, Blocks: obj.Blocks, Body: obj.Body}, cachedBlock: -1}, nil
}
func (r *Repository) GitStatistics() GitStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.gitStats
	s.Types = map[string]GitTypeStats{}
	for k, v := range r.gitStats.Types {
		s.Types[k] = v
	}
	return s
}
func (r *Repository) GitObjectIDs() []GitOID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fast != nil {
		out, err := r.fastGitIDs()
		if err != nil {
			r.poisoned = err
			return nil
		}
		return out
	}
	out := make([]GitOID, 0, len(r.gitObjects))
	for id := range r.gitObjects {
		out = append(out, id)
	}
	return out
}
func (r *Repository) GitCatalog(name string) (GitCatalog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.gitCatalogs[name]
	if !ok {
		return GitCatalog{}, errors.New("Git repository not found")
	}
	var c GitCatalog
	err := r.getJSON(id, gitCatalogKind, &c)
	if err == nil && (c.Name != name || !validName(c.Name) || c.Refs == nil) {
		err = errors.New("invalid Git catalog")
	}
	return c, err
}
func (r *Repository) validateGitCatalog(c GitCatalog) error {
	if !validName(c.Name) || c.Refs == nil {
		return errors.New("invalid Git catalog")
	}
	refs := make([]string, 0, len(c.Refs)+len(c.Peeled)+1)
	for _, id := range c.Refs {
		refs = append(refs, id)
	}
	for _, id := range c.Peeled {
		refs = append(refs, id)
	}
	if c.Head != "" {
		refs = append(refs, c.Head)
	}
	for _, text := range refs {
		id, err := ParseGitOID(text)
		if err != nil {
			return err
		}
		if _, ok := r.lookupGit(id); !ok {
			return errors.New("Git catalog references a missing object")
		}
	}
	return nil
}

// PublishGit makes refs durable only after the decoded objects and complete
// graph have been verified by the importer. Existing names are never replaced.
func (r *Repository) PublishGit(c GitCatalog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	if _, ok := r.gitCatalogs[c.Name]; ok {
		return ErrConflict
	}
	if err := r.validateGitCatalog(c); err != nil {
		return err
	}
	if err := r.sync(); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	id, err := r.append(gitCatalogKind, data)
	if err != nil {
		return err
	}
	if err = r.sync(); err != nil {
		return err
	}
	if r.gitCatalogs == nil {
		r.gitCatalogs = map[string]ID{}
	}
	r.gitCatalogs[c.Name] = id
	return nil
}

// GitStorageBytes avoids scanning the whole index during progress/resource checks.
func (r *Repository) GitStorageBytes() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return 0, err
	}
	if r.optimized {
		return r.end, nil
	}
	s, err := r.f.Stat()
	if err != nil {
		return 0, err
	}
	return s.Size(), nil
}
