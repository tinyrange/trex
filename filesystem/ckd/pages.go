package ckd

import (
	"fmt"
	"io"
	"sync"
)

// Pages maps fixed-size data records onto dataset-relative bytes. It excludes
// CKD framing and record zero, but does not mistake zero-filled pages for EOF.
// This is the common storage boundary for PDSE, HFS and VSAM linear datasets.
// Physical count-field CCHH values are not used as logical addresses.
type Pages struct {
	dataset            *Dataset
	PageSize, PerTrack uint32
	suffixBytes        uint32
	mu                 sync.Mutex
	cachedTrack        uint32
	cached             bool
	records            []Record
}

func (ds *Dataset) OpenPages(pageSize uint32) (*Pages, error) {
	return ds.openPages(pageSize, 0)
}

// OpenVSAMPages excludes the validated 32-byte suffix in the observed
// uncompressed extended-format profile. Logical CI addresses never include it.
// Ordinary OpenPages remains an exact physical-record view.
func (ds *Dataset) OpenVSAMPages(pageSize uint32) (*Pages, error) {
	suffix := uint32(0)
	if ds.Flags&0x80 != 0 {
		return nil, fmt.Errorf("ckd pages: compressed extended-format VSAM is unsupported")
	}
	if ds.SMSFlags&0x04 != 0 {
		suffix = 32
	}
	return ds.openPages(pageSize, suffix)
}

func (ds *Dataset) openPages(pageSize, suffix uint32) (*Pages, error) {
	if pageSize < 512 || pageSize > 65535 || ds.Tracks() == 0 {
		return nil, fmt.Errorf("ckd pages: invalid page size or empty allocation")
	}
	rs, e := ds.Track(0)
	if e != nil {
		return nil, e
	}
	p := &Pages{dataset: ds, PageSize: pageSize, suffixBytes: suffix}
	for _, r := range rs {
		if r.Number == 0 {
			continue
		}
		if _, err := p.recordData(r); err != nil {
			return nil, err
		}
		if uint32(r.Number) != p.PerTrack+1 {
			return nil, fmt.Errorf("ckd pages: noncontiguous first-track record numbers")
		}
		p.PerTrack++
	}
	if p.PerTrack == 0 {
		return nil, fmt.Errorf("ckd pages: empty first track")
	}
	return p, nil
}
func (p *Pages) Count() uint64 { return uint64(p.dataset.Tracks()) * uint64(p.PerTrack) }
func (p *Pages) Size() int64   { return int64(p.Count()) * int64(p.PageSize) }
func (p *Pages) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ckd pages: negative offset")
	}
	if len(b) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for len(b) > 0 {
		if off >= p.Size() {
			return n, io.EOF
		}
		page := uint64(off / int64(p.PageSize))
		track := uint32(page / uint64(p.PerTrack))
		slot := int(page % uint64(p.PerTrack))
		if !p.cached || p.cachedTrack != track {
			rs, e := p.dataset.Track(track)
			if e != nil {
				return n, e
			}
			records := make([]Record, 0, p.PerTrack)
			for _, r := range rs {
				if r.Number != 0 {
					data, err := p.recordData(r)
					if err != nil {
						return n, err
					}
					if int(r.Number) != len(records)+1 {
						return n, fmt.Errorf("ckd pages: invalid record on relative track %d", track)
					}
					r.Data = data
					records = append(records, r)
				}
			}
			if len(records) > int(p.PerTrack) {
				return n, fmt.Errorf("ckd pages: inconsistent records per track at %d", track)
			}
			p.records = records
			p.cachedTrack = track
			p.cached = true
		}
		if slot >= len(p.records) {
			return n, fmt.Errorf("ckd pages: missing page slot %d on relative track %d", slot, track)
		}
		count := copy(b, p.records[slot].Data[off%int64(p.PageSize):])
		off += int64(count)
		n += count
		b = b[count:]
	}
	return n, nil
}
func (p *Pages) Page(index uint64) ([]byte, error) {
	if index >= p.Count() {
		return nil, fmt.Errorf("ckd pages: page %d outside allocation", index)
	}
	b := make([]byte, p.PageSize)
	_, e := p.ReadAt(b, int64(index)*int64(p.PageSize))
	return b, e
}
