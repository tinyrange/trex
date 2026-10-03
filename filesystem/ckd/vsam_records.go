package ckd

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/storage"
)

// VSAMOrganization determines whether vacant slots or spanning are meaningful.
type VSAMOrganization string

const (
	VSAMESDS VSAMOrganization = "esds"
	VSAMKSDS VSAMOrganization = "ksds"
	VSAMRRDS VSAMOrganization = "rrds"
)

type VSAMSlot struct {
	Offset uint16
	Length uint16
	Vacant bool
	Data   []byte
}
type VSAMSegment struct {
	Kind   byte
	Update uint16
	Data   []byte
}

// ParseVSAMInterval decodes the documented ESDS/KSDS spanning and fixed RRDS
// slot conventions. Ordinary records, slots and segments are deliberately
// separate, so a fragment or deleted slot cannot become a complete record.
// Returned byte slices borrow b. See IBM DFSMS Using Data Sets, chapter 11.
func ParseVSAMInterval(b []byte, organization VSAMOrganization) (*ControlInterval, error) {
	if organization != VSAMESDS && organization != VSAMKSDS && organization != VSAMRRDS {
		return nil, fmt.Errorf("vsam: invalid organization")
	}
	if len(b) < 512 || len(b) > 32768 || len(b)%512 != 0 {
		return nil, fmt.Errorf("vsam CI: invalid size")
	}
	end := len(b) - 4
	c := &ControlInterval{FreeOffset: be.Uint16(b[end:]), FreeLength: be.Uint16(b[end+2:])}
	if c.FreeOffset == 0 && c.FreeLength == 0 {
		c.EOF = true
		return c, nil
	}
	stop := int(c.FreeOffset) + int(c.FreeLength)
	if stop > end || (end-stop)%3 != 0 {
		return nil, fmt.Errorf("vsam CI: invalid free-space boundary")
	}
	if organization == VSAMRRDS {
		off := 0
		for pos := end - 3; pos >= stop; pos -= 3 {
			flag, n := b[pos], int(be.Uint16(b[pos+1:]))
			if (flag != 0 && flag != 4) || n == 0 || n > int(c.FreeOffset)-off {
				return nil, fmt.Errorf("vsam RRDS: invalid slot")
			}
			if len(c.Slots) > 0 && n != int(c.Slots[0].Length) {
				return nil, fmt.Errorf("vsam RRDS: varying slot length")
			}
			slot := VSAMSlot{Offset: uint16(off), Length: uint16(n), Vacant: flag == 4}
			if !slot.Vacant {
				slot.Data = b[off : off+n]
			}
			c.Slots = append(c.Slots, slot)
			off += n
		}
		if off != int(c.FreeOffset) {
			return nil, fmt.Errorf("vsam RRDS: slots do not cover data area")
		}
		return c, nil
	}
	if end-stop == 6 {
		kind := b[end-3]
		if kind == 0x50 || kind == 0x60 || kind == 0x70 {
			length := int(be.Uint16(b[end-2:]))
			updateFlag := b[end-6]
			if updateFlag != ((kind&0x30)|8) || length == 0 || length != int(c.FreeOffset) || (kind != 0x60 && c.FreeLength != 0) {
				return nil, fmt.Errorf("vsam CI: invalid spanned segment")
			}
			c.Segment = &VSAMSegment{Kind: kind, Update: be.Uint16(b[end-5:]), Data: b[:length]}
			return c, nil
		}
	}
	return ParseControlInterval(b)
}

// VSAMReadOptions describes a resolved data component, not a format guess.
// UsedBytes is the catalog high-used RBA (exclusive), not allocated capacity.
// KSDS requires active data-CI order from its index, including segment order;
// sorting physical CIs or keys is not a substitute for index resolution.
type VSAMReadOptions struct {
	Organization         VSAMOrganization
	CIBytes              uint32
	UsedBytes            uint64
	CIsPerCA             uint32
	Order                []uint64
	KeyOffset, KeyLength uint32
	MaxRecords           int
	MaxRecordBytes       int
	MaxIntervals         uint64
	MaxBytes             uint64
}
type VSAMRecord struct {
	RBA    uint64
	Number uint64
	Data   []byte
}

// ReadVSAMRecords preserves record boundaries, assembles spanning and retains
// fixed RRDS record numbers across vacant slots. It reads an immutable snapshot.
func ReadVSAMRecords(source storage.Reader, o VSAMReadOptions) ([]VSAMRecord, error) {
	bad := func(s string) ([]VSAMRecord, error) { return nil, fmt.Errorf("vsam records: %s", s) }
	if source == nil || source.Size() < 0 || o.CIBytes < 512 || o.CIBytes > 32768 || o.CIBytes%512 != 0 || o.UsedBytes > uint64(source.Size()) || o.UsedBytes%uint64(o.CIBytes) != 0 || o.MaxRecords <= 0 || o.MaxRecordBytes <= 0 || o.MaxIntervals == 0 || o.MaxBytes == 0 {
		return bad("invalid component bounds or limits")
	}
	if o.Organization != VSAMESDS && o.Organization != VSAMKSDS && o.Organization != VSAMRRDS {
		return bad("invalid organization")
	}
	count := o.UsedBytes / uint64(o.CIBytes)
	if o.Organization == VSAMKSDS && ((count > 0 && len(o.Order) == 0) || o.KeyLength == 0 || o.CIsPerCA == 0) {
		return bad("KSDS requires resolved index order and key geometry")
	}
	if o.Organization != VSAMKSDS && len(o.Order) != 0 {
		return bad("explicit order is only valid for KSDS")
	}
	steps := count
	if o.Organization == VSAMKSDS {
		steps = uint64(len(o.Order))
	}
	if steps > o.MaxIntervals {
		return bad("interval budget exceeded")
	}
	var total uint64
	seen := map[uint64]bool{}
	var out []VSAMRecord
	var active []byte
	var start, area, number uint64
	var update uint16
	var previousKey []byte
	slotsPerCI, slotLength := 0, 0
	emit := func(rba, num uint64, data []byte) error {
		if len(out) >= o.MaxRecords {
			return fmt.Errorf("vsam records: record-count budget %d exceeded", o.MaxRecords)
		}
		if len(data) > o.MaxRecordBytes {
			return fmt.Errorf("vsam records: individual record-size budget exceeded")
		}
		if uint64(len(data)) > o.MaxBytes-total {
			return fmt.Errorf("vsam records: aggregate byte budget %d exceeded", o.MaxBytes)
		}
		if o.Organization == VSAMKSDS {
			if uint64(o.KeyOffset)+uint64(o.KeyLength) > uint64(len(data)) {
				return fmt.Errorf("vsam records: key outside record")
			}
			key := data[o.KeyOffset : o.KeyOffset+o.KeyLength]
			if previousKey != nil && bytes.Compare(previousKey, key) >= 0 {
				return fmt.Errorf("vsam records: index order is not strictly keyed")
			}
			previousKey = bytes.Clone(key)
		}
		total += uint64(len(data))
		out = append(out, VSAMRecord{rba, num, bytes.Clone(data)})
		return nil
	}
	for i := uint64(0); i < steps; i++ {
		id := i
		if o.Organization == VSAMKSDS {
			id = o.Order[i]
			if id >= count || seen[id] {
				return bad("duplicate or out-of-range index child")
			}
			seen[id] = true
		}
		rba := id * uint64(o.CIBytes)
		b := make([]byte, o.CIBytes)
		if _, err := source.ReadAt(b, int64(rba)); err != nil {
			return nil, err
		}
		ci, err := ParseVSAMInterval(b, o.Organization)
		if err != nil {
			return nil, fmt.Errorf("vsam CI at %#x: %w", rba, err)
		}
		if ci.EOF {
			if active != nil {
				return bad("EOF inside spanned record")
			}
			if o.Organization == VSAMESDS {
				break
			}
			return bad("EOF in active indexed/relative interval")
		}
		if ci.Segment != nil {
			s := ci.Segment
			if o.CIsPerCA == 0 {
				return bad("spanning requires control-area geometry")
			}
			if s.Kind == 0x50 {
				if o.Organization == VSAMKSDS && uint64(o.KeyOffset)+uint64(o.KeyLength) > uint64(len(s.Data)) {
					return bad("key outside first segment")
				}
				if active != nil {
					return bad("nested first segment")
				}
				start, area, update = rba, id/uint64(o.CIsPerCA), s.Update
				active = make([]byte, 0, len(s.Data))
			} else if active == nil {
				return bad("orphan continuation")
			}
			if area != id/uint64(o.CIsPerCA) || update != s.Update {
				return bad("spanned record crosses CA or update generation")
			}
			if len(s.Data) > o.MaxRecordBytes-len(active) {
				return bad("spanned record exceeds limit")
			}
			active = append(active, s.Data...)
			if s.Kind == 0x60 {
				number++
				if err := emit(start, number, active); err != nil {
					return nil, err
				}
				active = nil
			}
			continue
		}
		if active != nil {
			return bad("interrupted spanned record")
		}
		if o.Organization == VSAMRRDS {
			if len(ci.Slots) == 0 {
				return bad("RRDS interval without slots")
			}
			if slotsPerCI == 0 {
				slotsPerCI, slotLength = len(ci.Slots), int(ci.Slots[0].Length)
			}
			if len(ci.Slots) != slotsPerCI || int(ci.Slots[0].Length) != slotLength {
				return bad("inconsistent RRDS geometry")
			}
			for j, s := range ci.Slots {
				if !s.Vacant {
					if err := emit(rba+uint64(s.Offset), id*uint64(slotsPerCI)+uint64(j)+1, s.Data); err != nil {
						return nil, err
					}
				}
			}
		} else {
			offset := uint64(0)
			for _, data := range ci.Records {
				number++
				if err := emit(rba+offset, number, data); err != nil {
					return nil, err
				}
				offset += uint64(len(data))
			}
		}
	}
	if active != nil {
		return bad("truncated spanned record")
	}
	return out, nil
}
