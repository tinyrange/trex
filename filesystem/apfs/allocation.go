package apfs

import (
	"bytes"
	"fmt"
	"io"
	"sort"
)

// BlockRange uses container blocks, not byte offsets.
type BlockRange struct{ Start, Count uint64 }

type CheckpointMapping struct {
	Type, Subtype, Size     uint32
	Filesystem, ID, Address uint64
}

type AllocationChunk struct {
	Transaction, Start, Count, Free, BitmapAddress, CIBAddress uint64
	// Bitmap is a private copy; bit one marks an allocated main-device block.
	// A nil bitmap represents a wholly free chunk.
	Bitmap []byte
}

type Allocation struct {
	Transaction, Superblock, SpaceManager, NextID, NextTransaction uint64
	DescriptorArea, DataArea, InternalPool, InternalPoolBitmaps    BlockRange
	DescriptorIndex, DescriptorLength, DataIndex, DataLength       uint32
	BlocksPerChunk, ChunksPerCIB, CIBsPerCAB                       uint32
	FreeBlocks                                                     uint64
	Mappings                                                       []CheckpointMapping
	Chunks                                                         []AllocationChunk
	Free                                                           []BlockRange
}

// Allocation validates the selected checkpoint's ephemeral objects and the
// main-device allocation map. It does not mutate the image or infer free space
// from unreferenced file extents. Internal-pool blocks are never reported free.
// Fusion and noncontiguous checkpoint areas are intentionally unsupported.
func (c *Container) Allocation() (*Allocation, error) {
	base, err := c.object(0, 1)
	if err != nil {
		return nil, err
	}
	descCount, dataCount := le.Uint32(base[104:]), le.Uint32(base[108:])
	if descCount == 0 || descCount > 65536 || dataCount == 0 || dataCount > 1<<20 {
		return nil, fmt.Errorf("apfs: unsupported checkpoint area geometry")
	}
	descBase, dataBase := le.Uint64(base[112:]), le.Uint64(base[120:])
	validRange := func(start, count uint64) bool { return start < c.Blocks && count > 0 && count <= c.Blocks-start }
	if !validRange(descBase, uint64(descCount)) || !validRange(dataBase, uint64(dataCount)) {
		return nil, fmt.Errorf("apfs: checkpoint area outside container")
	}
	var nx []byte
	var superblock uint64
	for i := uint64(0); i < uint64(descCount); i++ {
		b, e := c.raw(descBase + i)
		if e != nil {
			return nil, e
		}
		if string(b[32:36]) == "NXSB" && verify(b) == nil && le.Uint32(b[24:])&0xffff == 1 && le.Uint64(b[16:]) == c.Transaction && le.Uint32(b[36:]) == c.BlockSize && le.Uint64(b[40:]) == c.Blocks && bytes.Equal(b[72:88], base[72:88]) {
			if nx != nil {
				return nil, fmt.Errorf("apfs: ambiguous selected checkpoint")
			}
			nx, superblock = b, descBase+i
		}
	}
	if nx == nil {
		return nil, fmt.Errorf("apfs: selected checkpoint superblock is absent")
	}
	if le.Uint32(nx[104:]) != descCount || le.Uint32(nx[108:]) != dataCount || le.Uint64(nx[112:]) != descBase || le.Uint64(nx[120:]) != dataBase {
		return nil, fmt.Errorf("apfs: checkpoint area geometry changed")
	}
	a := &Allocation{Transaction: c.Transaction, Superblock: superblock, NextID: le.Uint64(nx[88:]), NextTransaction: le.Uint64(nx[96:]), DescriptorArea: BlockRange{descBase, uint64(descCount)}, DataArea: BlockRange{dataBase, uint64(dataCount)}, DescriptorIndex: le.Uint32(nx[136:]), DescriptorLength: le.Uint32(nx[140:]), DataIndex: le.Uint32(nx[144:]), DataLength: le.Uint32(nx[148:])}
	if a.DescriptorIndex >= descCount || a.DescriptorLength < 2 || a.DescriptorLength > descCount || a.DataIndex >= dataCount || a.DataLength == 0 || a.DataLength > dataCount || superblock != descBase+uint64((a.DescriptorIndex+a.DescriptorLength-1)%descCount) || le.Uint32(nx[128:]) != (a.DescriptorIndex+a.DescriptorLength)%descCount || le.Uint32(nx[132:]) != (a.DataIndex+a.DataLength)%dataCount {
		return nil, fmt.Errorf("apfs: inconsistent checkpoint ring")
	}
	usedData := map[uint64]bool{}
	seenIDs := map[[2]uint64]bool{}
	var sm []byte
	for i := uint32(0); i < a.DescriptorLength-1; i++ {
		b, e := c.object(descBase+uint64((a.DescriptorIndex+i)%descCount), 12)
		if e != nil {
			return nil, e
		}
		flags, count := le.Uint32(b[32:]), le.Uint32(b[36:])
		last := i == a.DescriptorLength-2
		if le.Uint64(b[16:]) != a.Transaction || flags&^uint32(1) != 0 || (flags&1 != 0) != last || count > uint32((len(b)-40)/40) {
			return nil, fmt.Errorf("apfs: invalid checkpoint map")
		}
		for j := uint32(0); j < count; j++ {
			r := b[40+j*40:]
			m := CheckpointMapping{le.Uint32(r), le.Uint32(r[4:]), le.Uint32(r[8:]), le.Uint64(r[16:]), le.Uint64(r[24:]), le.Uint64(r[32:])}
			key := [2]uint64{m.Filesystem, m.ID}
			if seenIDs[key] || m.Type&0xc0000000 != 0x80000000 || m.ID == 0 || m.Size == 0 || m.Size%c.BlockSize != 0 || m.Size > 16<<20 || !validRange(m.Address, uint64(m.Size/c.BlockSize)) {
				return nil, fmt.Errorf("apfs: invalid/duplicate ephemeral mapping")
			}
			seenIDs[key] = true
			for k := uint64(0); k < uint64(m.Size/c.BlockSize); k++ {
				pa := m.Address + k
				if pa < dataBase || pa-dataBase >= uint64(dataCount) || (pa-dataBase+uint64(dataCount)-uint64(a.DataIndex))%uint64(dataCount) >= uint64(a.DataLength) || usedData[pa] {
					return nil, fmt.Errorf("apfs: ephemeral mapping outside active data ring or overlapping")
				}
				usedData[pa] = true
			}
			object := make([]byte, m.Size)
			if _, e := io.ReadFull(io.NewSectionReader(c.Source, int64(m.Address*uint64(c.BlockSize)), int64(m.Size)), object); e != nil {
				return nil, e
			}
			if e := verify(object); e != nil {
				return nil, fmt.Errorf("apfs: ephemeral object %d: %w", m.ID, e)
			}
			if le.Uint64(object[8:]) != m.ID || le.Uint64(object[16:]) != a.Transaction || le.Uint32(object[24:]) != m.Type || le.Uint32(object[28:]) != m.Subtype {
				return nil, fmt.Errorf("apfs: ephemeral object disagrees with mapping")
			}
			a.Mappings = append(a.Mappings, m)
			if m.Filesystem == 0 && m.ID == le.Uint64(nx[152:]) {
				if m.Type&0xffff != 5 {
					return nil, fmt.Errorf("apfs: wrong space-manager object type")
				}
				sm = object
				a.SpaceManager = m.Address
			}
		}
	}
	if uint32(len(usedData)) != a.DataLength || len(sm) < 344 {
		return nil, fmt.Errorf("apfs: checkpoint data incomplete or space manager absent")
	}
	if le.Uint32(sm[32:]) != c.BlockSize || le.Uint64(sm[48:]) != c.Blocks || le.Uint64(sm[96:]) != 0 || le.Uint32(sm[144:]) != 1 || le.Uint32(sm[336:]) != 1 || le.Uint32(sm[340:]) < 2520 || uint64(le.Uint32(sm[340:])) > uint64(len(sm)) {
		return nil, fmt.Errorf("apfs: unsupported space-manager version/geometry")
	}
	a.BlocksPerChunk, a.ChunksPerCIB, a.CIBsPerCAB = le.Uint32(sm[36:]), le.Uint32(sm[40:]), le.Uint32(sm[44:])
	if a.BlocksPerChunk == 0 || uint64(a.BlocksPerChunk) > uint64(c.BlockSize)*8 || a.ChunksPerCIB == 0 || uint64(a.ChunksPerCIB) > uint64(c.BlockSize-40)/32 || a.CIBsPerCAB == 0 || uint64(a.CIBsPerCAB) > uint64(c.BlockSize-40)/8 {
		return nil, fmt.Errorf("apfs: invalid chunk geometry")
	}
	chunkCount, cibCount, cabCount := le.Uint64(sm[56:]), uint64(le.Uint32(sm[64:])), uint64(le.Uint32(sm[68:]))
	if chunkCount != (c.Blocks+uint64(a.BlocksPerChunk)-1)/uint64(a.BlocksPerChunk) || chunkCount > (64<<20)/uint64(c.BlockSize) || cibCount != (chunkCount+uint64(a.ChunksPerCIB)-1)/uint64(a.ChunksPerCIB) || cabCount != 0 && cabCount != (cibCount+uint64(a.CIBsPerCAB)-1)/uint64(a.CIBsPerCAB) {
		return nil, fmt.Errorf("apfs: inconsistent chunk counts")
	}
	a.FreeBlocks = le.Uint64(sm[72:])
	a.InternalPool = BlockRange{le.Uint64(sm[176:]), le.Uint64(sm[152:])}
	a.InternalPoolBitmaps = BlockRange{le.Uint64(sm[168:]), uint64(le.Uint32(sm[164:]))}
	if !validRange(a.InternalPool.Start, a.InternalPool.Count) || !validRange(a.InternalPoolBitmaps.Start, a.InternalPoolBitmaps.Count) {
		return nil, fmt.Errorf("apfs: invalid internal-pool range")
	}
	addressOffset := uint64(le.Uint32(sm[80:]))
	addressCount := cibCount
	if cabCount != 0 {
		addressCount = cabCount
	}
	if addressOffset < uint64(le.Uint32(sm[340:])) || addressOffset%8 != 0 || addressOffset > uint64(len(sm)) || addressCount > (uint64(len(sm))-addressOffset)/8 {
		return nil, fmt.Errorf("apfs: invalid space-manager address array")
	}
	var cibs []uint64
	reserved := []BlockRange{{0, 1}, a.DescriptorArea, a.DataArea, a.InternalPool, a.InternalPoolBitmaps, {le.Uint64(nx[160:]), 1}}
	for i := uint64(0); i < addressCount; i++ {
		pa := le.Uint64(sm[addressOffset+i*8:])
		if cabCount == 0 {
			cibs = append(cibs, pa)
			continue
		}
		cab, e := c.object(pa, 6)
		if e != nil {
			return nil, e
		}
		count := le.Uint32(cab[36:])
		if le.Uint32(cab[32:]) != uint32(i) || uint64(count) != min(uint64(a.CIBsPerCAB), cibCount-uint64(len(cibs))) {
			return nil, fmt.Errorf("apfs: inconsistent chunk address block")
		}
		reserved = append(reserved, BlockRange{pa, 1})
		for j := uint32(0); j < count; j++ {
			cibs = append(cibs, le.Uint64(cab[40+j*8:]))
		}
	}
	var start, free uint64
	seenMetadata := map[uint64]bool{}
	for i, pa := range cibs {
		if seenMetadata[pa] {
			return nil, fmt.Errorf("apfs: repeated chunk information block")
		}
		seenMetadata[pa] = true
		cib, e := c.object(pa, 7)
		if e != nil {
			return nil, e
		}
		count := le.Uint32(cib[36:])
		if le.Uint32(cib[32:]) != uint32(i) || uint64(count) != min(uint64(a.ChunksPerCIB), chunkCount-uint64(len(a.Chunks))) {
			return nil, fmt.Errorf("apfs: inconsistent chunk information block")
		}
		reserved = append(reserved, BlockRange{pa, 1})
		for j := uint32(0); j < count; j++ {
			r := cib[40+j*32:]
			ch := AllocationChunk{Transaction: le.Uint64(r), Start: le.Uint64(r[8:]), Count: uint64(le.Uint32(r[16:])), Free: uint64(le.Uint32(r[20:])), BitmapAddress: le.Uint64(r[24:]), CIBAddress: pa}
			if ch.Transaction > a.Transaction || ch.Start != start || ch.Count != min(uint64(a.BlocksPerChunk), c.Blocks-start) || ch.Free > ch.Count {
				return nil, fmt.Errorf("apfs: inconsistent chunk extent")
			}
			if ch.BitmapAddress == 0 {
				if ch.Free != ch.Count {
					return nil, fmt.Errorf("apfs: non-free chunk has no bitmap")
				}
			} else {
				if seenMetadata[ch.BitmapAddress] {
					return nil, fmt.Errorf("apfs: repeated allocation bitmap")
				}
				seenMetadata[ch.BitmapAddress] = true
				ch.Bitmap, e = c.raw(ch.BitmapAddress)
				if e != nil {
					return nil, e
				}
				reserved = append(reserved, BlockRange{ch.BitmapAddress, 1})
			}
			var actualFree uint64
			for k := uint64(0); k < ch.Count; k++ {
				if ch.Bitmap != nil && ch.Bitmap[k/8]&(1<<uint(k%8)) != 0 {
					continue
				}
				actualFree++
				if n := len(a.Free); n != 0 && a.Free[n-1].Start+a.Free[n-1].Count == ch.Start+k {
					a.Free[n-1].Count++
				} else {
					if len(a.Free) >= 1<<20 {
						return nil, fmt.Errorf("apfs: excessive allocation fragmentation")
					}
					a.Free = append(a.Free, BlockRange{ch.Start + k, 1})
				}
			}
			if actualFree != ch.Free {
				return nil, fmt.Errorf("apfs: bitmap/free-count mismatch in chunk %d", len(a.Chunks))
			}
			free += ch.Free
			start += ch.Count
			a.Chunks = append(a.Chunks, ch)
		}
	}
	if start != c.Blocks || free != a.FreeBlocks {
		return nil, fmt.Errorf("apfs: space-manager total/free count mismatch")
	}
	for _, r := range reserved {
		if !validRange(r.Start, r.Count) {
			return nil, fmt.Errorf("apfs: reserved metadata outside container")
		}
		end := r.Start + r.Count
		i := sort.Search(len(a.Free), func(i int) bool { return a.Free[i].Start+a.Free[i].Count > r.Start })
		if i < len(a.Free) && a.Free[i].Start < end {
			return nil, fmt.Errorf("apfs: reserved metadata is marked free at block %d", max(r.Start, a.Free[i].Start))
		}
	}
	return a, nil
}
