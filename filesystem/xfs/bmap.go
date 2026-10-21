package xfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash/crc32"
	"math"
)

type extent struct {
	logical, physical, length uint64
	unwritten                 bool
}

func checkCRC(b []byte, offset int) error {
	if offset < 0 || offset+4 > len(b) {
		return fmt.Errorf("xfs: truncated checksum field")
	}
	expected := binary.LittleEndian.Uint32(b[offset:])
	copyData := append([]byte(nil), b...)
	clear(copyData[offset : offset+4])
	if crc32.Checksum(copyData, crc32.MakeTable(crc32.Castagnoli)) != expected {
		return fmt.Errorf("xfs: metadata checksum mismatch")
	}
	return nil
}
func (r *reader) metadata(b []byte, crc, uuid, owner, block int, inode, physical uint64) error {
	if err := checkCRC(b, crc); err != nil {
		return err
	}
	if !bytes.Equal(b[uuid:uuid+16], r.uuid[:]) || be.Uint64(b[owner:]) != inode || be.Uint64(b[block:]) != physical/512 {
		return fmt.Errorf("xfs: metadata UUID, owner or block address mismatch")
	}
	return nil
}
func decodeExtent(b []byte) extent {
	hi, lo := be.Uint64(b), be.Uint64(b[8:])
	return extent{(hi >> 9) & ((uint64(1) << 54) - 1), ((hi & 511) << 43) | (lo >> 21), lo & ((1 << 21) - 1), hi>>63 != 0}
}

// bmap reads an inode-resident root and every referenced block. Internal pointer
// arrays start after the maximum key capacity, not after the live key count.
// Exact levels, separator keys, sibling chains, cycles and record counts are
// checked before publishing a data view.
func (r *reader) bmap(root []byte, expected uint64, owner uint64) ([]extent, error) {
	if len(root) < 4 || expected == 0 || expected > 1<<20 {
		return nil, fmt.Errorf("xfs: invalid bmap root or extent count")
	}
	level, count := int(be.Uint16(root)), int(be.Uint16(root[2:]))
	capacity := (len(root) - 4) / 16
	if level < 1 || level > 32 || count < 1 || count > capacity {
		return nil, fmt.Errorf("xfs: invalid bmap root level or count")
	}
	seen := map[uint64]bool{}
	type link struct{ address, left, right uint64 }
	levels := map[int][]link{}
	records := []extent{}
	var visit func(uint64, int, uint64, uint64) error
	visit = func(address uint64, want int, low, high uint64) error {
		if seen[address] || len(seen) >= 1<<20 {
			return fmt.Errorf("xfs: bmap cycle, alias or block limit")
		}
		seen[address] = true
		off, err := r.physical(address, 1)
		if err != nil {
			return err
		}
		b := make([]byte, r.block)
		if _, err = starfile.ReadFullAt(r.file, b, int64(off)); err != nil {
			return err
		}
		header := 24
		magic := uint32(0x424d4150)
		if r.v5 {
			header = 72
			magic = 0x424d4133
		}
		if be.Uint32(b) != magic || int(be.Uint16(b[4:])) != want {
			return fmt.Errorf("xfs: invalid bmap magic or level")
		}
		if r.v5 {
			if err = r.metadata(b, 64, 40, 56, 24, owner, off); err != nil {
				return err
			}
		}
		n := int(be.Uint16(b[6:]))
		cap := (len(b) - header) / 16
		if n < 1 || n > cap {
			return fmt.Errorf("xfs: invalid bmap block record count")
		}
		levels[want] = append(levels[want], link{address, be.Uint64(b[8:]), be.Uint64(b[16:])})
		if want == 0 {
			if uint64(len(records)+n) > expected {
				return fmt.Errorf("xfs: too many bmap extent records")
			}
			for i := 0; i < n; i++ {
				e := decodeExtent(b[header+i*16:])
				if e.logical < low || e.logical >= high {
					return fmt.Errorf("xfs: bmap extent outside parent key range")
				}
				records = append(records, e)
			}
			if records[len(records)-n].logical != low {
				return fmt.Errorf("xfs: bmap separator mismatch")
			}
			return nil
		}
		if be.Uint64(b[header:]) != low {
			return fmt.Errorf("xfs: bmap separator mismatch")
		}
		for i := 0; i < n; i++ {
			key := be.Uint64(b[header+i*8:])
			end := high
			if i+1 < n {
				end = be.Uint64(b[header+(i+1)*8:])
			}
			if key < low || key >= end || end > high {
				return fmt.Errorf("xfs: unsorted bmap keys")
			}
			ptr := be.Uint64(b[header+cap*8+i*8:])
			if err = visit(ptr, want-1, key, end); err != nil {
				return err
			}
		}
		return nil
	}
	for i := 0; i < count; i++ {
		key := be.Uint64(root[4+i*8:])
		end := uint64(1) << 54
		if i+1 < count {
			end = be.Uint64(root[4+(i+1)*8:])
		}
		if key >= end {
			return nil, fmt.Errorf("xfs: unsorted bmap root keys")
		}
		if err := visit(be.Uint64(root[4+capacity*8+i*8:]), level-1, key, end); err != nil {
			return nil, err
		}
	}
	for _, nodes := range levels {
		for i, n := range nodes {
			left, right := uint64(math.MaxUint64), uint64(math.MaxUint64)
			if i > 0 {
				left = nodes[i-1].address
			}
			if i+1 < len(nodes) {
				right = nodes[i+1].address
			}
			if n.left != left || n.right != right {
				return nil, fmt.Errorf("xfs: inconsistent bmap sibling links")
			}
		}
	}
	if uint64(len(records)) != expected {
		return nil, fmt.Errorf("xfs: bmap extent count mismatch")
	}
	return records, nil
}
func (r *reader) dataExtents(records []extent, size uint64, realtime bool) ([]filesystem.ExtentSpec, error) {
	var result []filesystem.ExtentSpec
	var previous uint64
	for _, e := range records {
		if e.length == 0 || e.logical < previous || e.logical > math.MaxInt64/r.block || e.length > math.MaxInt64/r.block-e.logical {
			return nil, fmt.Errorf("xfs: invalid logical extent")
		}
		previous = e.logical + e.length
		source := r.file
		var off uint64
		var err error
		if realtime {
			source = r.realtime
			if source == nil {
				return nil, fmt.Errorf("xfs: realtime data fork requires realtime_file")
			}
			if e.physical >= r.rtBlocks || e.length > r.rtBlocks-e.physical || e.physical > math.MaxInt64/r.block || (e.physical+e.length)*r.block > uint64(source.Size()) {
				return nil, fmt.Errorf("xfs: extent outside realtime device")
			}
			off = e.physical * r.block
		} else {
			off, err = r.physical(e.physical, e.length)
			if err != nil {
				return nil, err
			}
		}
		start := e.logical * r.block
		if start < size && !e.unwritten {
			result = append(result, filesystem.ExtentSpec{Start: int64(start), Size: int64(min(e.length*r.block, size-start)), File: source, Offset: int64(off)})
		}
	}
	return result, nil
}
func (r *reader) directoryPhysical(e Entry, logical uint64) (uint64, error) {
	for _, x := range e.extents {
		if logical >= x.logical*r.block && logical < x.logical*r.block+x.length*r.block && !x.unwritten {
			start, err := r.physical(x.physical, x.length)
			return start + logical - x.logical*r.block, err
		}
	}
	return 0, fmt.Errorf("xfs: directory data block is not mapped")
}
