package block

// readBase never acquires mu. Callers may hold it for a partial-chunk write,
// so a clean reader must release baseMu before reacquiring mu.
func (d *SparseOverlay) readBase(p []byte, off int64) (int, error) {
	if !d.baseConcurrent {
		d.baseMu.Lock()
		defer d.baseMu.Unlock()
	}
	return ReadFullAt(d.base, p, off)
}

// readRun requires mu and preserves contiguous requests to each backing.
func (d *SparseOverlay) readRun(pos int64, remaining int) (int, bool) {
	size := min(remaining, int(SparseChunkSize-pos%SparseChunkSize))
	_, dirty := d.dirty[pos/SparseChunkSize]
	for size < remaining {
		_, nextDirty := d.dirty[(pos+int64(size))/SparseChunkSize]
		if nextDirty != dirty {
			break
		}
		size += min(remaining-size, int(SparseChunkSize))
	}
	return size, dirty
}

func (d *SparseOverlay) ReadAt(p []byte, off int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil {
		return 0, d.failure
	}
	if err := ValidateRange(d.geometry.Size, off, int64(len(p))); err != nil {
		return 0, err
	}

	// Reconstruct only clean ranges without excluding unrelated overlay I/O.
	// The base is immutable and dirty membership is monotonic. A concurrent
	// writer can turn a clean chunk dirty, but never the reverse.
	for done := 0; done < len(p); {
		pos := off + int64(done)
		size, dirty := d.readRun(pos, len(p)-done)
		if !dirty {
			d.mu.Unlock()
			_, err := d.readBase(p[done:done+size], pos)
			d.mu.Lock()
			if err != nil {
				return 0, d.fail(err)
			}
			if d.failure != nil {
				return 0, d.failure
			}
		}
		done += size
	}
	// Linearize the whole read here. Re-read all current dirty ranges, even
	// those written while a slow clean range was being reconstructed. Backing
	// reads and writes remain serialized, so partial chunks cannot leak.
	for done := 0; done < len(p); {
		pos := off + int64(done)
		size, dirty := d.readRun(pos, len(p)-done)
		if dirty {
			n, err := ReadFullAt(d.backing, p[done:done+size], pos)
			if err != nil {
				return done + n, d.fail(err)
			}
		}
		done += size
	}
	return len(p), nil
}
