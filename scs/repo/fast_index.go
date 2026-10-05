package repo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/klauspost/compress/zstd"
	"sort"
)

// Immutable sorted runs, incremental manifests, and a fixed-size tail locator.
// All are native records in the same file, never external backing files.
const fastPageKind byte = 12
const fastRunKind byte = 13
const fastRootKind byte = 14
const fastEndKind byte = 15
const fastPageEntries = 1024
const fastFooterSize = headerSize + 44

type fastRef struct {
	Offset int64
	Size   uint32
	Hash   objectKey
}
type fastRunRef struct {
	Ref   fastRef
	Level uint8
}
type fastPageRef struct {
	First [33]byte
	Ref   fastRef
}
type fastRun struct {
	Objects, Git          uint64
	NativePages, GitPages []fastPageRef
}
type fastManifest struct {
	Version  int
	Runs     []fastRunRef
	Refs     map[string]ID
	Catalogs map[string]ID
	GitStats GitStats
	Stats    StorageStats
}
type fastState struct {
	manifest        fastManifest
	runs            map[int64]*fastRun
	pages           map[int64][]byte
	dec             *zstd.Decoder
	dirty           map[objectKey]location
	dirtyGit        map[GitOID]objectKey
	pendingRefs     map[string]ID
	pendingCatalogs map[string]ID
	sealed          int64
}

func newFast(m fastManifest) *fastState {
	return &fastState{manifest: m, runs: map[int64]*fastRun{}, pages: map[int64][]byte{}, dirty: map[objectKey]location{}, dirtyGit: map[GitOID]objectKey{}}
}
func appendFastRef(b []byte, ref fastRef) []byte {
	b = binary.BigEndian.AppendUint64(b, uint64(ref.Offset))
	b = binary.BigEndian.AppendUint32(b, ref.Size)
	return append(b, ref.Hash[:]...)
}
func decodeFastRef(b []byte) fastRef {
	return fastRef{int64(binary.BigEndian.Uint64(b)), binary.BigEndian.Uint32(b[8:]), keyBytes(b[12:44])}
}
func (r *Repository) writeFast(kind byte, data []byte) (fastRef, error) {
	off := r.end + headerSize
	id, e := r.appendCheckpointRecord(kind, data)
	return fastRef{off, uint32(len(data)), key(id)}, e
}
func (r *Repository) readFast(ref fastRef, kind byte) ([]byte, error) {
	if ref.Offset < int64(len(magic))+headerSize || ref.Size > maxRecord || ref.Offset > r.end || int64(ref.Size) > r.end-ref.Offset {
		return nil, errors.New("invalid persistent index reference")
	}
	if e := r.flush(); e != nil {
		return nil, e
	}
	b := make([]byte, headerSize+int(ref.Size))
	if _, e := r.f.ReadAt(b, ref.Offset-headerSize); e != nil {
		return nil, e
	}
	if b[0] != kind || binary.BigEndian.Uint64(b[1:9]) != uint64(ref.Size) || keyBytes(b[9:41]) != ref.Hash || digestKey(kind, b[headerSize:]) != ref.Hash {
		return nil, errors.New("persistent index checksum mismatch")
	}
	return b[headerSize:], nil
}
func (r *Repository) fastRun(ref fastRef) (*fastRun, error) {
	if run := r.fast.runs[ref.Offset]; run != nil {
		return run, nil
	}
	b, e := r.readFast(ref, fastRunKind)
	if e != nil {
		return nil, e
	}
	if len(b) < 25 || b[0] != 1 {
		return nil, errors.New("invalid persistent index directory")
	}
	run := &fastRun{Objects: binary.BigEndian.Uint64(b[1:]), Git: binary.BigEndian.Uint64(b[9:])}
	if run.Objects > uint64(ref.Offset/headerSize) || run.Git > run.Objects {
		return nil, errors.New("invalid persistent index object count")
	}
	n, g := int(binary.BigEndian.Uint32(b[17:])), int(binary.BigEndian.Uint32(b[21:]))
	b = b[25:]
	if n != (int(run.Objects)+fastPageEntries-1)/fastPageEntries || g != (int(run.Git)+fastPageEntries-1)/fastPageEntries || n < 0 || g < 0 || n+g > maxRecord/77 || len(b) != (n+g)*77 {
		return nil, errors.New("invalid persistent index page count")
	}
	parse := func(count int) ([]fastPageRef, error) {
		out := make([]fastPageRef, count)
		for i := range out {
			copy(out[i].First[:], b[:33])
			out[i].Ref = decodeFastRef(b[33:77])
			b = b[77:]
			if out[i].Ref.Offset >= ref.Offset || out[i].Ref.Offset+int64(out[i].Ref.Size) > ref.Offset-headerSize || i > 0 && bytes.Compare(out[i-1].First[:], out[i].First[:]) >= 0 {
				return nil, errors.New("invalid persistent index page ordering")
			}
		}
		return out, nil
	}
	run.NativePages, e = parse(n)
	if e != nil {
		return nil, e
	}
	run.GitPages, e = parse(g)
	if e != nil {
		return nil, e
	}
	r.fast.runs[ref.Offset] = run
	return run, nil
}
func (r *Repository) fastPage(p fastPageRef, tag byte, count int) ([]byte, error) {
	if b, ok := r.fast.pages[p.Ref.Offset]; ok {
		return b, nil
	}
	b, e := r.readFast(p.Ref, fastPageKind)
	if e != nil {
		return nil, e
	}
	if r.fast.dec == nil {
		r.fast.dec, e = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(1<<20))
		if e != nil {
			return nil, e
		}
	}
	b, e = r.fast.dec.DecodeAll(b, nil)
	if e != nil {
		return nil, e
	}
	width := 50
	if tag == 1 {
		width = 41
	}
	if count <= 0 || count > fastPageEntries || len(b) != 1+count*width || b[0] != tag {
		return nil, errors.New("invalid persistent index page size")
	}
	b = b[1:]
	for i := 0; i < count; i++ {
		keylen := 32
		if tag == 1 {
			keylen = 33
		}
		entry := b[i*width : (i+1)*width]
		if i == 0 && !bytes.Equal(entry[:keylen], p.First[:keylen]) || i > 0 && bytes.Compare(b[(i-1)*width:(i-1)*width+keylen], entry[:keylen]) >= 0 {
			return nil, errors.New("unsorted persistent index page")
		}
		if tag == 0 {
			loc := decodeLocation(entry)
			physical := loc.size
			if loc.kind == bodyKind {
				physical = loc.stored
			}
			if loc.offset < int64(len(magic))+headerSize || loc.offset > p.Ref.Offset || int64(physical) > p.Ref.Offset-loc.offset || loc.kind < blockKind || loc.kind > bodyKind || loc.kind == refsKind || loc.depth > maxBodyDepth || loc.size > maxBody || loc.kind != bodyKind && (loc.size > maxRecord || loc.stored != 0 || loc.depth != 0) || loc.kind == bodyKind && (loc.stored < 74 || loc.stored > maxBody+(maxBody>>8)+(1<<20)) {
				return nil, errors.New("invalid indexed native location")
			}
		} else {
			var oid GitOID
			copy(oid[:], entry[:33])
			if !oid.Valid() {
				return nil, errors.New("invalid indexed Git identity")
			}
		}
	}
	// Bound decoded page caching independently of the history size.
	if len(r.fast.pages) >= 128 {
		clear(r.fast.pages)
	}
	r.fast.pages[p.Ref.Offset] = b
	return b, nil
}
func decodeLocation(b []byte) location {
	return location{offset: int64(binary.BigEndian.Uint64(b[32:40])), size: int(binary.BigEndian.Uint32(b[40:44])), stored: int(binary.BigEndian.Uint32(b[44:48])), kind: b[48], depth: b[49]}
}
func pageCount(total uint64, page int) int {
	return int(min(uint64(fastPageEntries), total-uint64(page*fastPageEntries)))
}
func (r *Repository) nativeAt(run *fastRun, ordinal uint64) (objectKey, location, error) {
	if ordinal >= run.Objects {
		return objectKey{}, location{}, errors.New("invalid Git index ordinal")
	}
	p := int(ordinal / fastPageEntries)
	b, e := r.fastPage(run.NativePages[p], 0, pageCount(run.Objects, p))
	if e != nil {
		return objectKey{}, location{}, e
	}
	b = b[int(ordinal%fastPageEntries)*50:]
	return keyBytes(b[:32]), decodeLocation(b), nil
}
func (r *Repository) lookupObject(id objectKey) (location, bool) {
	if loc, ok := r.objects[id]; ok {
		return loc, true
	}
	if r.fast == nil {
		return location{}, false
	}
	for _, rr := range r.fast.manifest.Runs {
		run, e := r.fastRun(rr.Ref)
		if e != nil {
			r.poisoned = e
			return location{}, false
		}
		p := sort.Search(len(run.NativePages), func(i int) bool { return bytes.Compare(run.NativePages[i].First[:32], id[:]) > 0 }) - 1
		if p < 0 {
			continue
		}
		b, e := r.fastPage(run.NativePages[p], 0, pageCount(run.Objects, p))
		if e != nil {
			r.poisoned = e
			return location{}, false
		}
		n := len(b) / 50
		i := sort.Search(n, func(i int) bool { return bytes.Compare(b[i*50:i*50+32], id[:]) >= 0 })
		if i < n && bytes.Equal(b[i*50:i*50+32], id[:]) {
			return decodeLocation(b[i*50:]), true
		}
	}
	return location{}, false
}
func (r *Repository) lookupGit(oid GitOID) (gitLocation, bool) {
	if v, ok := r.gitObjects[oid]; ok {
		return v, true
	}
	if r.fast == nil {
		return gitLocation{}, false
	}
	for _, rr := range r.fast.manifest.Runs {
		run, e := r.fastRun(rr.Ref)
		if e != nil {
			r.poisoned = e
			return gitLocation{}, false
		}
		p := sort.Search(len(run.GitPages), func(i int) bool { return bytes.Compare(run.GitPages[i].First[:], oid[:]) > 0 }) - 1
		if p < 0 {
			continue
		}
		b, e := r.fastPage(run.GitPages[p], 1, pageCount(run.Git, p))
		if e != nil {
			r.poisoned = e
			return gitLocation{}, false
		}
		n := len(b) / 41
		i := sort.Search(n, func(i int) bool { return bytes.Compare(b[i*41:i*41+33], oid[:]) >= 0 })
		if i == n || !bytes.Equal(b[i*41:i*41+33], oid[:]) {
			continue
		}
		id, loc, e := r.nativeAt(run, binary.BigEndian.Uint64(b[i*41+33:]))
		if e != nil {
			r.poisoned = e
			return gitLocation{}, false
		}
		// The compatibility index points to a native record; validate its original
		// typed identity rather than trusting an unverified duplicated header.
		var v gitLocation
		if loc.kind == bodyKind {
			data := make([]byte, loc.stored)
			_, e = r.f.ReadAt(data, loc.offset)
			if e == nil {
				var got GitOID
				var kind byte
				_, e = r.inspectBody(data, loc.offset)
				if e == nil {
					got, kind, _, e = bodyIdentity(data)
					if got != oid {
						e = errors.New("Git index identity mismatch")
					}
					v = gitLocation{ID: id, Body: id, Size: int64(loc.size), Kind: kind}
				}
			}
		} else if loc.kind == gitObjectKind {
			var data []byte
			data, e = r.getRaw(id, gitObjectKind)
			if e == nil {
				var got GitOID
				var kind byte
				var size int64
				var raw []byte
				got, kind, size, raw, e = decodeGitDescriptor(data)
				if got != oid {
					e = errors.New("Git index identity mismatch")
				}
				v = gitLocation{ID: id, Size: size, Kind: kind}
				if e == nil && data[0] == 2 {
					v.Body = keyBytes(raw)
					bodyLoc, ok := r.lookupObject(v.Body)
					if !ok || bodyLoc.kind != bodyKind || int64(bodyLoc.size) != size || !r.earlierKey(v.Body, id) {
						e = errors.New("invalid indexed Git body reference")
					}
				}
				if e == nil && data[0] == 1 {
					for j := 0; j < len(raw); j += 32 {
						block := keyBytes(raw[j : j+32])
						bl, ok := r.lookupObject(block)
						want := BlockSize
						if j+32 == len(raw) && size%BlockSize != 0 {
							want = int(size % BlockSize)
						}
						if !ok || bl.kind != blockKind || bl.size != want || !r.earlierKey(block, id) {
							e = errors.New("invalid indexed Git block reference")
							break
						}
					}
				}
			}
		} else {
			e = errors.New("Git index references untyped object")
		}
		if e != nil {
			r.poisoned = e
			return gitLocation{}, false
		}
		return v, true
	}
	return gitLocation{}, false
}

func (r *Repository) writeRun(objects map[objectKey]location, git map[GitOID]objectKey) (fastRunRef, error) {
	ids := make([]objectKey, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	ord := make(map[objectKey]uint64, len(ids))
	for i, id := range ids {
		ord[id] = uint64(i)
	}
	run := fastRun{Objects: uint64(len(ids)), Git: uint64(len(git))}
	emit := func(data []byte, first [33]byte) (fastPageRef, error) {
		b := r.bodyCodec().enc.EncodeAll(data, nil)
		ref, e := r.writeFast(fastPageKind, b)
		return fastPageRef{first, ref}, e
	}
	for start := 0; start < len(ids); start += fastPageEntries {
		end := min(start+fastPageEntries, len(ids))
		b := make([]byte, 1, 1+50*(end-start))
		b[0] = 0
		for _, id := range ids[start:end] {
			loc := objects[id]
			b = append(b, id[:]...)
			b = binary.BigEndian.AppendUint64(b, uint64(loc.offset))
			b = binary.BigEndian.AppendUint32(b, uint32(loc.size))
			b = binary.BigEndian.AppendUint32(b, uint32(loc.stored))
			b = append(b, loc.kind, loc.depth)
		}
		var first [33]byte
		copy(first[:], ids[start][:])
		p, e := emit(b, first)
		if e != nil {
			return fastRunRef{}, e
		}
		run.NativePages = append(run.NativePages, p)
	}
	oids := make([]GitOID, 0, len(git))
	for oid := range git {
		oids = append(oids, oid)
	}
	sort.Slice(oids, func(i, j int) bool { return bytes.Compare(oids[i][:], oids[j][:]) < 0 })
	for start := 0; start < len(oids); start += fastPageEntries {
		end := min(start+fastPageEntries, len(oids))
		b := make([]byte, 1, 1+41*(end-start))
		b[0] = 1
		for _, oid := range oids[start:end] {
			idx, ok := ord[git[oid]]
			if !ok {
				return fastRunRef{}, errors.New("Git run missing native object")
			}
			b = append(b, oid[:]...)
			b = binary.BigEndian.AppendUint64(b, idx)
		}
		p, e := emit(b, [33]byte(oids[start]))
		if e != nil {
			return fastRunRef{}, e
		}
		run.GitPages = append(run.GitPages, p)
	}
	b := []byte{1}
	b = binary.BigEndian.AppendUint64(b, run.Objects)
	b = binary.BigEndian.AppendUint64(b, run.Git)
	b = binary.BigEndian.AppendUint32(b, uint32(len(run.NativePages)))
	b = binary.BigEndian.AppendUint32(b, uint32(len(run.GitPages)))
	for _, pages := range [][]fastPageRef{run.NativePages, run.GitPages} {
		for _, p := range pages {
			b = append(b, p.First[:]...)
			b = appendFastRef(b, p.Ref)
		}
	}
	ref, e := r.writeFast(fastRunKind, b)
	return fastRunRef{Ref: ref}, e
}
func (r *Repository) readRunEntries(rr fastRunRef, objects map[objectKey]location, git map[GitOID]objectKey) error {
	run, e := r.fastRun(rr.Ref)
	if e != nil {
		return e
	}
	for p, ref := range run.NativePages {
		b, e := r.fastPage(ref, 0, pageCount(run.Objects, p))
		if e != nil {
			return e
		}
		for len(b) > 0 {
			objects[keyBytes(b[:32])] = decodeLocation(b)
			b = b[50:]
		}
	}
	for p, ref := range run.GitPages {
		b, e := r.fastPage(ref, 1, pageCount(run.Git, p))
		if e != nil {
			return e
		}
		for len(b) > 0 {
			var oid GitOID
			copy(oid[:], b[:33])
			id, _, e := r.nativeAt(run, binary.BigEndian.Uint64(b[33:41]))
			if e != nil {
				return e
			}
			git[oid] = id
			b = b[41:]
		}
	}
	return nil
}
func (r *Repository) mergeFastRuns() error {
	// Four equal tiers become one next-tier run. The imported immutable base is
	// level 255 and never rewritten by ordinary workspace edits.
	for {
		runs := r.fast.manifest.Runs
		changed := false
		for i := 0; i+3 < len(runs); i++ {
			level := runs[i].Level
			if level >= 254 {
				continue
			}
			same := true
			for j := 1; j < 4; j++ {
				if runs[i+j].Level != level {
					same = false
				}
			}
			if !same {
				continue
			}
			objects := map[objectKey]location{}
			git := map[GitOID]objectKey{}
			for j := i + 3; j >= i; j-- {
				if e := r.readRunEntries(runs[j], objects, git); e != nil {
					return e
				}
			}
			rr, e := r.writeRun(objects, git)
			if e != nil {
				return e
			}
			rr.Level = level + 1
			next := append([]fastRunRef{}, runs[:i]...)
			next = append(next, rr)
			next = append(next, runs[i+4:]...)
			r.fast.manifest.Runs = next
			for _, old := range runs[i : i+4] {
				delete(r.fast.runs, old.Ref.Offset)
			}
			changed = true
			break
		}
		if !changed {
			return nil
		}
	}
}
func (r *Repository) sealFast() error {
	if r.fast == nil || r.fast.sealed == r.end {
		return nil
	}
	if e := r.ready(); e != nil {
		return e
	}
	f := r.fast
	if len(f.dirty) > 0 {
		rr, e := r.writeRun(f.dirty, f.dirtyGit)
		if e != nil {
			return e
		}
		f.manifest.Runs = append([]fastRunRef{rr}, f.manifest.Runs...)
		if e := r.mergeFastRuns(); e != nil {
			return e
		}
	}
	m := f.manifest
	m.Refs = r.refs
	if f.pendingRefs != nil {
		m.Refs = f.pendingRefs
	}
	m.Catalogs = r.gitCatalogs
	if f.pendingCatalogs != nil {
		m.Catalogs = f.pendingCatalogs
	}
	m.GitStats = r.gitStats
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	ref, e := r.writeFast(fastRootKind, b)
	if e != nil {
		return e
	}
	if _, e = r.writeFast(fastEndKind, appendFastRef(nil, ref)); e != nil {
		return e
	}
	f.manifest = m
	f.sealed = r.end
	clear(f.dirty)
	clear(f.dirtyGit)
	f.pendingRefs = nil
	f.pendingCatalogs = nil
	return nil
}
func (r *Repository) buildFastIndex() error {
	if r.fast != nil {
		return r.sync()
	}
	if e := r.sync(); e != nil {
		return e
	}
	if e := r.discardCheckpoint(); e != nil {
		return e
	}
	s := StorageStats{ContentObjects: int64(len(r.objects))}
	for _, loc := range r.objects {
		addLocationStats(&s, loc, 1)
	}
	git := make(map[GitOID]objectKey, len(r.gitObjects))
	for oid, v := range r.gitObjects {
		git[oid] = v.ID
	}
	rr, e := r.writeRun(r.objects, git)
	if e != nil {
		return e
	}
	rr.Level = 255
	r.fast = newFast(fastManifest{Version: 1, Runs: []fastRunRef{rr}, Stats: s})
	if e := r.sync(); e != nil {
		return e
	}
	// Maps now represent the small session overlay, not the full history.
	r.objects = map[objectKey]location{}
	r.gitObjects = map[GitOID]gitLocation{}
	return nil
}
func addLocationStats(s *StorageStats, loc location, sign int64) {
	if loc.kind == bodyKind {
		s.NativeBodies += sign
		s.NativeBodyBytes += sign * int64(loc.size)
		s.EncodedBodyBytes += sign * int64(loc.stored)
		s.MaxDeltaDepth = max(s.MaxDeltaDepth, loc.depth)
	}
	if loc.kind == blockKind {
		s.UniqueBlocks += sign
		s.UniqueBlockBytes += sign * int64(loc.size)
	}
}

func (r *Repository) loadFastIndex(fileSize int64) (bool, int64, error) {
	if !r.optimized || fileSize < int64(len(magic))+fastFooterSize {
		return false, 0, nil
	}
	r.end = fileSize
	// A missing/torn tail locator falls back to verified physical scanning.
	// Never discover a root by searching arbitrary user payload bytes.
	start := fileSize - fastFooterSize
	tail := make([]byte, fileSize-start)
	if _, e := r.f.ReadAt(tail, start); e != nil {
		return false, 0, e
	}
	for i := len(tail) - fastFooterSize; i >= 0; i-- {
		b := tail[i : i+fastFooterSize]
		if b[0] != fastEndKind || binary.BigEndian.Uint64(b[1:9]) != 44 {
			continue
		}
		if digestKey(fastEndKind, b[headerSize:]) != keyBytes(b[9:41]) {
			continue
		}
		ref := decodeFastRef(b[headerSize:])
		footer := start + int64(i)
		if ref.Offset+int64(ref.Size) != footer {
			return false, 0, errors.New("invalid index manifest position")
		}
		data, e := r.readFast(ref, fastRootKind)
		if e != nil {
			return false, 0, e
		}
		var m fastManifest
		if e = json.Unmarshal(data, &m); e != nil {
			return false, 0, e
		}
		if m.Version != 1 || m.Refs == nil || len(m.Runs) == 0 || len(m.Runs) > 1024 || m.Stats.ContentObjects < 0 {
			return false, 0, errors.New("invalid persistent manifest")
		}
		for _, rr := range m.Runs {
			if rr.Ref.Offset < int64(len(magic))+headerSize || rr.Ref.Offset+int64(rr.Ref.Size) > ref.Offset-headerSize {
				return false, 0, errors.New("invalid index run reference")
			}
		}
		r.fast = newFast(m)
		r.fast.sealed = footer + fastFooterSize
		r.refs = m.Refs
		r.gitCatalogs = m.Catalogs
		r.gitStats = m.GitStats
		r.gitObjects = map[GitOID]gitLocation{}
		for name, id := range r.refs {
			loc, ok := r.lookupObject(key(id))
			if !validName(name) || !validID(id) || !ok || loc.kind != snapshotKind {
				return false, 0, errors.New("invalid indexed workspace root")
			}
		}
		return true, footer + fastFooterSize, nil
	}
	return false, 0, nil
}

// Full enumeration is deliberately an explicit O(history) operation, unlike open.
func (r *Repository) fastGitIDs() ([]GitOID, error) {
	seen := map[GitOID]bool{}
	for oid := range r.gitObjects {
		seen[oid] = true
	}
	for _, rr := range r.fast.manifest.Runs {
		run, e := r.fastRun(rr.Ref)
		if e != nil {
			return nil, e
		}
		for p, ref := range run.GitPages {
			b, e := r.fastPage(ref, 1, pageCount(run.Git, p))
			if e != nil {
				return nil, e
			}
			for len(b) > 0 {
				var oid GitOID
				copy(oid[:], b[:33])
				seen[oid] = true
				b = b[41:]
			}
		}
	}
	out := make([]GitOID, 0, len(seen))
	for oid := range seen {
		out = append(out, oid)
	}
	return out, nil
}
