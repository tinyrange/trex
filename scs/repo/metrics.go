package repo

// OperationStats are cumulative engine counters, not total device I/O or RAM.
// Object reads count requested stored payload bytes; BodyDecodedBytes measures
// whole reconstructed bodies on cache misses, including delta bases.
type OperationStats struct {
	RecordsAppended, BytesAppended               uint64
	ObjectReads, ObjectBytesRead                 uint64
	BodyDecodes, BodyDecodedBytes, BodyCacheHits uint64
	DerivedHits, DerivedMisses                   uint64
}

func (r *Repository) OperationStats() OperationStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.metrics
}

// DerivedIndexVersion is independent of authoritative snapshot serialization.
// The bounded revision-summary index is process-local and entirely rebuildable.
const DerivedIndexVersion = 1

type derivedKey struct {
	Version  int
	Snapshot ID
}

func (r *Repository) ClearDerivedIndexes() { r.mu.Lock(); defer r.mu.Unlock(); r.derived = nil }
func cloneRevision(v Revision) Revision    { v.Parents = append([]ID(nil), v.Parents...); return v }
func (r *Repository) indexedRevision(id ID) (Revision, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return Revision{}, err
	}
	key := derivedKey{Version: DerivedIndexVersion, Snapshot: id}
	if v, ok := r.derived[key]; ok {
		r.metrics.DerivedHits++
		return cloneRevision(v), nil
	}
	r.metrics.DerivedMisses++
	v, err := r.revisionLocked(id)
	if err != nil {
		return Revision{}, err
	}
	// Bound retained metadata and avoid an unbounded history cache. Clearing the
	// index affects performance only, not correctness or authoritative data.
	if r.derived == nil || len(r.derived) >= 4096 {
		r.derived = map[derivedKey]Revision{}
	}
	r.derived[key] = cloneRevision(v)
	return v, nil
}
