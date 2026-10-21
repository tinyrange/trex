package ckd

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/storage"
)

type VSAMIndexEntry struct {
	Pointer             uint64
	HighKey             []byte
	SpannedContinuation bool
}
type VSAMIndexRecord struct {
	Level   byte
	Flags   byte
	BaseRBA uint32
	Entries []VSAMIndexEntry
	FreeCIs []uint64
}

// ParseVSAMIndex decodes the documented 24-byte index header, free-CI list,
// right-to-left FLP entries and backward section displacements. High keys are
// expanded with the architected implicit FF suffix, not guessed from data CIs.
func ParseVSAMIndex(ci []byte, keyLength int) (*VSAMIndexRecord, error) {
	bad := func(s string) (*VSAMIndexRecord, error) { return nil, fmt.Errorf("vsam index: %s", s) }
	if keyLength < 1 || keyLength > 255 {
		return bad("invalid key length")
	}
	parsed, err := ParseControlInterval(ci)
	if err != nil {
		return nil, err
	}
	if parsed.EOF || len(parsed.Records) != 1 {
		return bad("expected one index record")
	}
	b := parsed.Records[0]
	if len(b) < 24 || int(be.Uint16(b)) != len(b) {
		return bad("invalid logical length")
	}
	width := int(b[2])
	level := b[16]
	if width < 3 || width > 5 || level < 1 || level > 32 || b[3] != byte((1<<uint(width-2))-1) || b[17]&0x3f != 0 {
		return bad("invalid pointer width or level")
	}
	out := &VSAMIndexRecord{Level: level, Flags: b[17], BaseRBA: be.Uint32(b[4:])}
	floor := int(be.Uint16(b[18:]))
	if floor < 24 || floor > len(b) || (floor-24)%(width-2) != 0 {
		return bad("free-CI array outside record")
	}
	integer := func(v []byte) uint64 {
		var n uint64
		for _, x := range v {
			n = n<<8 | uint64(x)
		}
		return n
	}
	for off := 24; off < floor; off += width - 2 {
		out.FreeCIs = append(out.FreeCIs, integer(b[off:off+width-2]))
	}
	last, section := int(be.Uint16(b[20:])), int(be.Uint16(b[22:]))
	pos := len(b) - width
	if last < floor || last > pos || section < last || section > pos {
		return bad("invalid entry or section offset")
	}
	var previous, high []byte
	for {
		if pos < floor || pos > len(b)-width || pos < last {
			return bad("entry outside record")
		}
		f, n := int(b[pos]), int(b[pos+1])
		ref := previous
		if pos == section {
			ref = high
		}
		if f > len(ref) || f+n > keyLength || pos-n < floor {
			return bad("invalid key compression")
		}
		key := bytes.Repeat([]byte{255}, keyLength)
		copy(key, ref[:f])
		copy(key[f:], b[pos-n:pos])
		// Consecutive null-key entries precede the final (key-bearing) segment.
		nullKey := f == 0 && n == 0
		if len(out.Entries) > 0 && !nullKey && !out.Entries[len(out.Entries)-1].SpannedContinuation && bytes.Compare(previous, key) > 0 {
			return bad("unordered high keys")
		}
		out.Entries = append(out.Entries, VSAMIndexEntry{integer(b[pos+2 : pos+width]), key, nullKey})
		previous = key
		isSection := pos == section
		next := pos - n - width
		if isSection {
			if pos-n-2 < floor {
				return bad("section displacement outside record")
			}
			delta := int(be.Uint16(b[pos-n-2:]))
			high = key
			next -= 2
			if pos == last {
				if delta != 0 {
					return bad("nonzero final section displacement")
				}
				break
			}
			if delta == 0 || delta > section-last {
				return bad("invalid section chain")
			}
			section -= delta
		} else if pos == last || next < section {
			return bad("missing section boundary")
		}
		pos = next
	}
	if level != 1 && (len(out.FreeCIs) > 0 || width != 5 || out.BaseRBA != 0) {
		return bad("invalid higher-level pointer geometry")
	}
	// A single null key at the upper end is an ordinary FF high-key sentinel.
	for i := range out.Entries {
		if out.Entries[i].SpannedContinuation && i == len(out.Entries)-1 {
			out.Entries[i].SpannedContinuation = false
		}
	}
	return out, nil
}

// VSAMIndexOrder follows a resolved root, descending only active index links.
// Sequence pointers are CI numbers relative to their control area's base RBA;
// higher-level pointers are CI numbers in the index component. Free CIs are excluded.
func VSAMIndexOrder(source storage.Reader, ciBytes uint32, usedBytes, rootRBA uint64, dataCI uint32, dataUsed uint64, keyLength, maxEntries int) ([]uint64, error) {
	bad := func(s string) ([]uint64, error) { return nil, fmt.Errorf("vsam index tree: %s", s) }
	if source == nil || source.Size() < 0 || ciBytes < 512 || ciBytes > 32768 || ciBytes%512 != 0 || usedBytes > uint64(source.Size()) || usedBytes%uint64(ciBytes) != 0 || dataCI < 512 || dataCI > 32768 || dataCI%512 != 0 || dataUsed%uint64(dataCI) != 0 || maxEntries <= 0 {
		return bad("invalid bounds")
	}
	if usedBytes == 0 {
		if dataUsed != 0 {
			return bad("missing index")
		}
		return nil, nil
	}
	type pending struct {
		rba    uint64
		parent byte
	}
	stack := []pending{{rootRBA, 0}}
	seen := map[uint64]bool{}
	dataSeen := map[uint64]bool{}
	var order []uint64
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.rba%uint64(ciBytes) != 0 || item.rba >= usedBytes || seen[item.rba] || len(seen) >= maxEntries {
			return bad("invalid, repeated or over-limit index pointer")
		}
		seen[item.rba] = true
		b := make([]byte, ciBytes)
		if _, err := source.ReadAt(b, int64(item.rba)); err != nil {
			return nil, err
		}
		rec, err := ParseVSAMIndex(b, keyLength)
		if err != nil {
			return nil, err
		}
		if item.parent != 0 && rec.Level != item.parent-1 {
			return bad("invalid child level")
		}
		if len(rec.Entries) == 0 {
			return bad("empty active index")
		}
		if rec.Level == 1 {
			if uint64(rec.BaseRBA)%uint64(dataCI) != 0 {
				return bad("unaligned data base")
			}
			free := map[uint64]bool{}
			for _, id := range rec.FreeCIs {
				if free[id] {
					return bad("duplicate free CI")
				}
				free[id] = true
			}
			for _, e := range rec.Entries {
				id := uint64(rec.BaseRBA)/uint64(dataCI) + e.Pointer
				if id >= dataUsed/uint64(dataCI) || dataSeen[id] || free[e.Pointer] || len(order) >= maxEntries {
					return bad("invalid, free, duplicate or over-limit data child")
				}
				dataSeen[id] = true
				order = append(order, id)
			}
		} else {
			if len(rec.Entries) > maxEntries-len(stack) {
				return bad("pending index limit")
			}
			for i := len(rec.Entries) - 1; i >= 0; i-- {
				stack = append(stack, pending{uint64(rec.BaseRBA) + rec.Entries[i].Pointer*uint64(ciBytes), rec.Level})
			}
		}
	}
	return order, nil
}
