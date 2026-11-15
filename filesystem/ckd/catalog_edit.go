package ckd

import (
	"bytes"
	"fmt"
	"sort"
)

// Uncatalog removes the entries for the named data sets from an ICF
// catalog (BCS) whose data component is on this volume: records keyed by
// one of the names, sphere records whose component cells name one, and
// records that refer to one (aliases and connectors of a removed user
// catalog). Each affected control interval is rewritten in place: the
// remaining records keep their order, packed from the start, with record
// definition fields as VSAM writes them (paired RDFs for runs of equal
// lengths) and a CIDF describing the freed space. The index is not
// changed: a sequence-set entry's key is the highest a control interval may
// hold, and remains valid when fewer records remain. Spanned records are
// not rewritten (an error). It returns the names of the deleted records.
func (e *Edit) Uncatalog(catalog string, names []string) ([]string, error) {
	ds, err := e.dataset(catalog)
	if err != nil {
		return nil, err
	}
	records, meta, err := ds.VSAMRecords(10000000)
	if err != nil {
		return nil, fmt.Errorf("ckd uncatalog %s: %w", catalog, err)
	}
	if meta.KeyLength != 45 || meta.KeyOffset != 9 {
		return nil, fmt.Errorf("ckd uncatalog %s: not a BCS (key %d at %d)", catalog, meta.KeyLength, meta.KeyOffset)
	}
	gone := map[string]bool{}
	for _, n := range names {
		gone[n] = true
	}
	byCI := map[uint64]map[uint64]bool{} // CI -> record offsets to delete
	var deleted []string
	for _, r := range records {
		rec, err := ParseCatalogRecord(r.Data)
		if err != nil {
			continue // unrecognised record kinds are kept
		}
		drop := gone[rec.Name]
		var walk func([]CatalogCell)
		walk = func(cells []CatalogCell) {
			for _, c := range cells {
				if c.Name != "" && gone[c.Name] {
					drop = true
				}
				walk(c.Children)
			}
		}
		walk(rec.Cells)
		for _, ref := range rec.References {
			if gone[ref] {
				drop = true
			}
		}
		if !drop || rec.Name == "" {
			continue
		}
		ci := r.RBA / uint64(meta.CIBytes)
		if byCI[ci] == nil {
			byCI[ci] = map[uint64]bool{}
		}
		byCI[ci][r.RBA%uint64(meta.CIBytes)] = true
		deleted = append(deleted, rec.Name)
	}
	pages, err := ds.OpenVSAMPages(meta.CIBytes)
	if err != nil {
		return nil, err
	}
	if pages.suffixBytes != 0 {
		return nil, fmt.Errorf("ckd uncatalog %s: extended-format catalogs are not rewritten", catalog)
	}
	cis := make([]uint64, 0, len(byCI))
	for ci := range byCI {
		cis = append(cis, ci)
	}
	sort.Slice(cis, func(i, j int) bool { return cis[i] < cis[j] })
	for _, ci := range cis {
		b, err := pages.Page(ci)
		if err != nil {
			return nil, err
		}
		nb, err := removeCIRecords(b, byCI[ci])
		if err != nil {
			return nil, fmt.Errorf("ckd uncatalog %s CI %d: %w", catalog, ci, err)
		}
		rel := uint32(ci / uint64(pages.PerTrack))
		number := byte(ci%uint64(pages.PerTrack)) + 1
		abs, ok := ds.absoluteTrack(rel)
		if !ok {
			return nil, fmt.Errorf("ckd uncatalog %s: CI %d outside the data set", catalog, ci)
		}
		base, err := e.Disk.Track(abs)
		if err != nil {
			return nil, err
		}
		rs := e.writableTrack(abs, base)
		found := false
		for i := range rs {
			if rs[i].Number == number && len(rs[i].Data) == len(nb) {
				rs[i].Data = nb
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("ckd uncatalog %s: CI %d has no record %d on its track", catalog, ci, number)
		}
	}
	sort.Strings(deleted)
	return deleted, nil
}

// absoluteTrack maps a data-set-relative track to the volume track.
func (ds *Dataset) absoluteTrack(rel uint32) (uint32, bool) {
	for _, x := range ds.Extents {
		if rel <= x.Last-x.First {
			return x.First + rel, true
		}
		rel -= x.Last - x.First + 1
	}
	return 0, false
}

// removeCIRecords rebuilds a KSDS data control interval without the records
// at the given offsets.
func removeCIRecords(b []byte, drop map[uint64]bool) ([]byte, error) {
	ci, err := ParseVSAMInterval(b, VSAMKSDS)
	if err != nil {
		return nil, err
	}
	if ci.Segment != nil || ci.EOF {
		return nil, fmt.Errorf("spanned or empty control interval")
	}
	var keep [][]byte
	off := uint64(0)
	removed := 0
	for _, r := range ci.Records {
		if drop[off] {
			removed++
		} else {
			keep = append(keep, r)
		}
		off += uint64(len(r))
	}
	if removed != len(drop) {
		return nil, fmt.Errorf("%d of %d records to delete not found at record boundaries", removed, len(drop))
	}
	out := make([]byte, len(b))
	pos := 0
	for _, r := range keep {
		pos += copy(out[pos:], r)
	}
	// RDFs from the end, the first record's (group's) rightmost.
	end := len(b) - 4
	rdf := end
	for i := 0; i < len(keep); {
		j := i
		for j < len(keep) && len(keep[j]) == len(keep[i]) {
			j++
		}
		n := j - i
		if n >= 2 {
			rdf -= 3
			out[rdf], out[rdf+1], out[rdf+2] = 0x40, byte(len(keep[i])>>8), byte(len(keep[i]))
			rdf -= 3
			out[rdf], out[rdf+1], out[rdf+2] = 0x08, byte(n>>8), byte(n)
		} else {
			rdf -= 3
			out[rdf], out[rdf+1], out[rdf+2] = 0, byte(len(keep[i])>>8), byte(len(keep[i]))
		}
		i = j
	}
	if rdf < pos {
		return nil, fmt.Errorf("records and RDFs exceed the control interval")
	}
	be.PutUint16(out[end:], uint16(pos))
	be.PutUint16(out[end+2:], uint16(rdf-pos))
	// The rebuilt interval must parse to the kept records.
	check, err := ParseVSAMInterval(out, VSAMKSDS)
	if err != nil || len(check.Records) != len(keep) {
		return nil, fmt.Errorf("rebuilt control interval does not parse: %v", err)
	}
	if !bytes.Equal(out[:pos], bytes.Join(keep, nil)) {
		return nil, fmt.Errorf("rebuilt control interval lost record data")
	}
	return out, nil
}
