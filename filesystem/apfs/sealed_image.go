package apfs

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/tinyrange/trex/storage"
)

// SealedImage is a standalone container image borrowing unchanged file data.
// Construction is immutable: errors and successful results leave Source intact.
type SealedImage struct {
	File                         storage.Reader
	RootHash                     []byte
	Transaction, TreeNodes       uint64
	AllocatedBlocks, FreedBlocks uint64
	SnapshotName                 string
	SnapshotTransaction          uint64
	SnapshotUUID                 [16]byte
}

type imageBlocks struct {
	c      *Container
	blocks map[uint64][]byte
}

func (w *imageBlocks) read(pa uint64) ([]byte, error) {
	if b, ok := w.blocks[pa]; ok {
		return b, nil
	}
	b, err := w.c.raw(pa)
	if err != nil {
		return nil, err
	}
	w.blocks[pa] = b
	return b, nil
}

func (w *imageBlocks) write(pa uint64, b []byte) error {
	if pa >= w.c.Blocks || len(b) != int(w.c.BlockSize) {
		return fmt.Errorf("apfs: image block outside container")
	}
	w.blocks[pa] = append([]byte(nil), b...)
	return nil
}

func (w *imageBlocks) file() (storage.Reader, error) {
	addresses := make([]uint64, 0, len(w.blocks))
	for pa := range w.blocks {
		addresses = append(addresses, pa)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
	var ranges []storage.Range
	var offset int64
	for _, pa := range addresses {
		start := int64(pa * uint64(w.c.BlockSize))
		if start > offset {
			ranges = append(ranges, storage.Range{Source: w.c.Source, Offset: offset, Length: start - offset})
		}
		ranges = append(ranges, storage.Range{Source: bytes.NewReader(w.blocks[pa]), Length: int64(w.c.BlockSize)})
		offset = start + int64(w.c.BlockSize)
	}
	if offset < w.c.Source.Size() {
		ranges = append(ranges, storage.Range{Source: w.c.Source, Offset: offset, Length: w.c.Source.Size() - offset})
	}
	return storage.Compose(ranges...)
}

// SealImage constructs a fresh, single-checkpoint image of a snapshot-free,
// unencrypted container. It preserves file extents, installs authenticated
// records, and retires historical checkpoints in the returned image. This is
// image construction, not a journal transaction against a live mounted disk.
// The supplied external root hash is mandatory and must match before any image
// metadata is prepared. File-content digest verification belongs to the caller.
func (v *Volume) SealImage(records []Record, expected []byte) (*SealedImage, error) {
	return v.SealImageWithOptions(records, expected, SealImageOptions{})
}

func (v *Volume) SealImageWithOptions(records []Record, expected []byte, options SealImageOptions) (*SealedImage, error) {
	c := v.container
	if c == nil || v.Flags&1 == 0 || v.SnapshotCount != 0 || v.Incompatible&^uint64(0x3b) != 0 || len(expected) != 32 || v.Superblock == nil {
		return nil, fmt.Errorf("apfs: sealing requires a snapshot-free unencrypted volume and external SHA-256 root")
	}
	tree, err := EncodeSealedTree(records, c.BlockSize, 1)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tree.RootHash, expected) {
		return nil, fmt.Errorf("apfs: constructed metadata does not match external root seal")
	}
	a, err := c.Allocation()
	if err != nil {
		return nil, err
	}
	if a.NextTransaction <= a.Transaction || a.NextTransaction == ^uint64(0) || a.NextID == 0 || tree.Nodes+1 > ^uint64(0)-a.NextID {
		return nil, fmt.Errorf("apfs: invalid sealing transaction/object identifiers")
	}
	xid, rootID := a.NextTransaction, a.NextID
	sealedXID := xid
	if options.SnapshotName != "" {
		if xid >= ^uint64(0)-1 || xid >= 1<<60 {
			return nil, fmt.Errorf("apfs: snapshot transaction overflow")
		}
		xid++
	}
	integrityID, nextID := rootID+tree.Nodes, rootID+tree.Nodes+1
	w := &imageBlocks{c, map[uint64][]byte{}}
	nx, err := c.raw(a.Superblock)
	if err != nil {
		return nil, err
	}
	containerMap, err := c.readMap(le.Uint64(nx[160:]), c.Transaction)
	if err != nil {
		return nil, err
	}
	volumePA, err := resolve(containerMap, v.ID)
	if err != nil {
		return nil, err
	}
	vol, err := w.read(volumePA)
	if err != nil {
		return nil, err
	}
	omapPA := le.Uint64(vol[128:])
	omap, err := w.read(omapPA)
	if err != nil {
		return nil, err
	}
	if le.Uint32(omap[36:]) != 0 || le.Uint32(omap[32:]) != 0 {
		return nil, fmt.Errorf("apfs: volume object-map snapshots/encryption unsupported for sealing")
	}
	// Blocks replaced by this construction are freed only after all source
	// trees have been read. Old checkpoints are then explicitly retired.
	replaced := map[uint64]bool{}
	oldFS := map[uint64]bool{}
	ignore := func([]byte, []byte) error { return nil }
	collect := func(pa uint64, _ []byte) error { replaced[pa] = true; return nil }
	fsCollect := func(pa uint64, _ []byte) error { replaced[pa], oldFS[pa] = true, true; return nil }
	oldRoot, err := v.rootAddress(v.RootTree, v.RootTreeType)
	if err != nil {
		return nil, err
	}
	resolver := func(id uint64) (uint64, error) { return v.rootAddress(id, v.RootTreeType) }
	var oldHash []byte
	var oldHashType uint32
	if v.Incompatible&0x20 != 0 {
		s, e := v.SealInformation()
		if e != nil || s.Flags != 0 {
			return nil, fmt.Errorf("apfs: invalid source volume seal: %v", e)
		}
		oldHash, oldHashType, resolver = s.RootHash, s.HashType, v.sealedResolver(s)
		replaced[s.IntegrityAddress] = true
		oldFS[s.IntegrityAddress] = true
	}
	if err := c.walkTreeNodes(oldRoot, resolver, oldHashType, oldHash, ignore, fsCollect); err != nil {
		return nil, err
	}
	if err := c.walkTreeNodes(le.Uint64(omap[48:]), nil, 0, nil, ignore, collect); err != nil {
		return nil, err
	}
	containerOMAPPA := le.Uint64(nx[160:])
	containerOMAP, err := w.read(containerOMAPPA)
	if err != nil {
		return nil, err
	}
	if le.Uint32(containerOMAP[36:]) != 0 {
		return nil, fmt.Errorf("apfs: container object-map snapshots unsupported")
	}
	containerNodes := map[uint64]bool{}
	if err := c.walkTreeNodes(le.Uint64(containerOMAP[48:]), nil, 0, nil, ignore, func(pa uint64, _ []byte) error {
		replaced[pa], containerNodes[pa] = true, true
		return nil
	}); err != nil {
		return nil, err
	}
	var extents []Record
	if v.Incompatible&0x20 != 0 {
		pa, e := v.rootAddress(v.ExtentTree, v.ExtentTreeType)
		if e != nil {
			return nil, e
		}
		if e := c.walkTreeNodes(pa, nil, 0, nil, func(k, b []byte) error {
			extents = append(extents, Record{append([]byte(nil), k...), append([]byte(nil), b...)})
			return nil
		}, collect); e != nil {
			return nil, e
		}
	} else {
		source, e := v.Records()
		if e != nil {
			return nil, e
		}
		for _, r := range source {
			if le.Uint64(r.Key)>>60 != 8 {
				continue
			}
			if len(r.Key) != 16 || len(r.Value) != 24 || le.Uint64(r.Value[16:]) != 0 {
				return nil, fmt.Errorf("apfs: invalid/encrypted source file extent")
			}
			key := append([]byte(nil), r.Key...)
			le.PutUint64(key, le.Uint64(key)&0x0fffffffffffffff)
			extents = append(extents, Record{key, append([]byte(nil), r.Value[:16]...)})
		}
	}
	// The single current checkpoint owns its active internal-pool bitmap. A
	// previously bitmap-less device chunk obtains a bitmap from this pool.
	sm, err := w.read(a.SpaceManager)
	if err != nil {
		return nil, err
	}
	if le.Uint32(sm[160:]) != 1 || a.InternalPool.Count > uint64(c.BlockSize)*8 {
		return nil, fmt.Errorf("apfs: unsupported multi-block internal-pool bitmap")
	}
	indexOffset, xidOffset := int(le.Uint32(sm[328:])), int(le.Uint32(sm[324:]))
	if indexOffset < 344 || indexOffset > len(sm)-2 || xidOffset < 344 || xidOffset > len(sm)-8 {
		return nil, fmt.Errorf("apfs: invalid internal-pool bitmap arrays")
	}
	bitmapIndex := uint64(le.Uint16(sm[indexOffset:]))
	if bitmapIndex >= a.InternalPoolBitmaps.Count {
		return nil, fmt.Errorf("apfs: invalid current internal-pool bitmap index")
	}
	ipBitmap, err := w.read(a.InternalPoolBitmaps.Start + bitmapIndex)
	if err != nil {
		return nil, err
	}
	allocatePool := func() (uint64, error) {
		for i := uint64(0); i < a.InternalPool.Count; i++ {
			if ipBitmap[i/8]&(1<<uint(i%8)) == 0 {
				ipBitmap[i/8] |= 1 << uint(i%8)
				return a.InternalPool.Start + i, nil
			}
		}
		return 0, fmt.Errorf("apfs: internal allocation pool exhausted")
	}
	freeRanges := append([]BlockRange(nil), a.Free...)
	sort.Slice(freeRanges, func(i, j int) bool { return freeRanges[i].Count > freeRanges[j].Count })
	var allocated, freed uint64
	setAllocated := func(pa uint64, used bool) error {
		if pa >= c.Blocks {
			return fmt.Errorf("apfs: allocation outside container")
		}
		if pa >= a.InternalPool.Start && pa-a.InternalPool.Start < a.InternalPool.Count {
			i := pa - a.InternalPool.Start
			if used == (ipBitmap[i/8]&(1<<uint(i%8)) != 0) {
				return fmt.Errorf("apfs: repeated internal allocation/free")
			}
			if used {
				ipBitmap[i/8] |= 1 << uint(i%8)
			} else {
				ipBitmap[i/8] &^= 1 << uint(i%8)
			}
			return nil
		}
		idx := pa / uint64(a.BlocksPerChunk)
		ch := &a.Chunks[idx]
		if ch.BitmapAddress == 0 {
			if !used {
				return fmt.Errorf("apfs: freeing an unallocated chunk")
			}
			ch.BitmapAddress, err = allocatePool()
			if err != nil {
				return err
			}
			bitmap := make([]byte, c.BlockSize)
			for bit := ch.Count; bit < uint64(c.BlockSize)*8; bit++ {
				bitmap[bit/8] |= 1 << uint(bit%8)
			}
			if err := w.write(ch.BitmapAddress, bitmap); err != nil {
				return err
			}
		}
		bm, e := w.read(ch.BitmapAddress)
		if e != nil {
			return e
		}
		i := pa - ch.Start
		if used == (bm[i/8]&(1<<uint(i%8)) != 0) {
			return fmt.Errorf("apfs: repeated device allocation/free at %d", pa)
		}
		if used {
			bm[i/8] |= 1 << uint(i%8)
			ch.Free--
			allocated++
		} else {
			bm[i/8] &^= 1 << uint(i%8)
			ch.Free++
			freed++
		}
		ch.Transaction = xid
		return nil
	}
	allocate := func() (uint64, error) {
		for i := range freeRanges {
			if freeRanges[i].Count == 0 {
				continue
			}
			pa := freeRanges[i].Start
			freeRanges[i].Start++
			freeRanges[i].Count--
			if err := setAllocated(pa, true); err != nil {
				return 0, err
			}
			return pa, nil
		}
		return 0, fmt.Errorf("apfs: no free blocks for sealed metadata")
	}
	newMap := make(map[uint64]mapping, len(v.omap)+int(tree.Nodes)+1)
	for id, m := range v.omap {
		if !oldFS[m.address] {
			newMap[id] = m
		}
	}
	for i := uint64(0); i < tree.Nodes; i++ {
		id := rootID + i
		if _, exists := newMap[id]; exists {
			return nil, fmt.Errorf("apfs: new sealed object identifier collides")
		}
		pa, e := allocate()
		if e != nil {
			return nil, e
		}
		b := make([]byte, c.BlockSize)
		if _, e := tree.File.ReadAt(b, int64(i*uint64(c.BlockSize))); e != nil {
			return nil, e
		}
		if e := w.write(pa, b); e != nil {
			return nil, e
		}
		newMap[id] = mapping{sealedXID, pa, 8, c.BlockSize}
	}
	integrityPA, err := allocate()
	if err != nil {
		return nil, err
	}
	if _, exists := newMap[integrityID]; exists {
		return nil, fmt.Errorf("apfs: integrity object identifier collides")
	}
	im := make([]byte, c.BlockSize)
	le.PutUint64(im[8:], integrityID)
	le.PutUint64(im[16:], sealedXID)
	le.PutUint32(im[24:], 30)
	le.PutUint32(im[32:], 2)
	le.PutUint32(im[40:], 1)
	le.PutUint32(im[44:], 128)
	copy(im[128:], tree.RootHash)
	le.PutUint64(im, checksum(im))
	if err := w.write(integrityPA, im); err != nil {
		return nil, err
	}
	newMap[integrityID] = mapping{sealedXID, integrityPA, 0, c.BlockSize}
	fextRoot, _, err := encodePhysicalTree(extents, c.BlockSize, 31, sealedXID, allocate, w.write)
	if err != nil {
		return nil, err
	}
	companionStart := allocated
	if err := prepareCompanionVolumes(w, nx, vol, containerMap, xid, &nextID, options.Companions, allocate); err != nil {
		return nil, err
	}
	companionAllocated := allocated - companionStart
	snapshot, err := prepareImageSnapshot(w, vol, newMap, xid, sealedXID, &nextID, options, expected, allocate)
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		rows := []Record{{le.AppendUint64(nil, sealedXID), make([]byte, 16)}}
		snapRoot, _, e := encodeFixedPhysicalTree(rows, c.BlockSize, 19, 8, xid, allocate, w.write)
		if e != nil {
			return nil, e
		}
		le.PutUint32(omap[36:], 1)
		le.PutUint32(omap[44:], 0x40000002)
		le.PutUint64(omap[56:], snapRoot)
		le.PutUint64(omap[64:], sealedXID)
	}
	mapRecords := func(m map[uint64]mapping) []Record {
		ids := make([]uint64, 0, len(m))
		for id := range m {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		rows := make([]Record, len(ids))
		for i, id := range ids {
			m := m[id]
			key := le.AppendUint64(le.AppendUint64(nil, id), m.xid)
			value := le.AppendUint64(le.AppendUint32(le.AppendUint32(nil, m.flags), m.size), m.address)
			rows[i] = Record{key, value}
		}
		return rows
	}
	omapRoot, _, err := encodePhysicalTree(mapRecords(newMap), c.BlockSize, 11, xid, allocate, w.write)
	if err != nil {
		return nil, err
	}
	volumeAllocated := allocated - companionAllocated
	volumeFreed := uint64(len(replaced) - len(containerNodes))
	volumeMapping := containerMap[v.ID]
	volumeMapping.xid = xid
	containerMap[v.ID] = volumeMapping
	containerRoot, _, err := encodePhysicalTree(mapRecords(containerMap), c.BlockSize, 11, xid, allocate, w.write)
	if err != nil {
		return nil, err
	}
	for pa := range replaced {
		if pa == volumePA || pa == omapPA || pa == containerOMAPPA {
			return nil, fmt.Errorf("apfs: source metadata trees overlap object headers")
		}
		if err := setAllocated(pa, false); err != nil {
			return nil, err
		}
	}
	le.PutUint64(omap[16:], xid)
	le.PutUint64(omap[48:], omapRoot)
	le.PutUint64(omap, checksum(omap))
	le.PutUint64(containerOMAP[16:], xid)
	le.PutUint64(containerOMAP[48:], containerRoot)
	le.PutUint64(containerOMAP, checksum(containerOMAP))
	if le.Uint64(vol[88:]) > ^uint64(0)-volumeAllocated || le.Uint64(vol[88:])+volumeAllocated < volumeFreed {
		return nil, fmt.Errorf("apfs: volume block accounting overflow")
	}
	le.PutUint64(vol[16:], xid)
	le.PutUint64(vol[56:], v.Incompatible|0x20)
	le.PutUint64(vol[88:], le.Uint64(vol[88:])+volumeAllocated-volumeFreed)
	le.PutUint32(vol[116:], 2)
	le.PutUint64(vol[136:], rootID)
	// The lifetime allocation/free counters describe user data, whose extents
	// are preserved. Metadata-only reconstruction changes fs_alloc_count.
	le.PutUint64(vol[1024:], integrityID)
	le.PutUint64(vol[1032:], fextRoot)
	le.PutUint32(vol[1040:], 0x40000002)
	if snapshot != nil {
		snapVol := append([]byte(nil), vol...)
		le.PutUint64(snapVol[8:], snapshot.sb)
		le.PutUint64(snapVol[16:], sealedXID)
		le.PutUint32(snapVol[24:], 0x4000000d)
		le.PutUint64(snapVol[968:], 0)
		le.PutUint64(snapVol, checksum(snapVol))
		if err := w.write(snapshot.sb, snapVol); err != nil {
			return nil, err
		}
		le.PutUint32(vol[120:], 0x40000002)
		le.PutUint64(vol[144:], snapshot.extent)
		le.PutUint32(vol[124:], 0x40000002)
		le.PutUint64(vol[152:], snapshot.tree)
		le.PutUint64(vol[216:], 1)
		le.PutUint64(vol[256:], snapshot.time)
		le.PutUint64(vol[968:], sealedXID)
		le.PutUint64(vol[1000:], snapshot.sme)
	}
	le.PutUint64(vol, checksum(vol))
	// Update the selected chunk records and bitmap accounting. Existing CIBs
	// and pool bitmap slots are retained because historical checkpoints are
	// deliberately absent from this newly constructed standalone image.
	cibs := map[uint64][]byte{}
	for _, ch := range a.Chunks {
		cib, ok := cibs[ch.CIBAddress]
		if !ok {
			cib, err = w.read(ch.CIBAddress)
			if err != nil {
				return nil, err
			}
			cibs[ch.CIBAddress] = cib
		}
		found := false
		for j := uint32(0); j < le.Uint32(cib[36:]); j++ {
			r := cib[40+j*32:]
			if le.Uint64(r[8:]) == ch.Start {
				le.PutUint64(r, ch.Transaction)
				le.PutUint32(r[20:], uint32(ch.Free))
				le.PutUint64(r[24:], ch.BitmapAddress)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("apfs: chunk disappeared during construction")
		}
	}
	for _, cib := range cibs {
		le.PutUint64(cib[16:], xid)
		le.PutUint64(cib, checksum(cib))
	}
	le.PutUint64(sm[72:], a.FreeBlocks+freed-allocated)
	le.PutUint64(sm[xidOffset:], xid)
	// Every ephemeral object belongs to the one retained checkpoint.
	for _, m := range a.Mappings {
		object := make([]byte, m.Size)
		for off := uint32(0); off < m.Size; off += c.BlockSize {
			b, e := w.read(m.Address + uint64(off/c.BlockSize))
			if e != nil {
				return nil, e
			}
			copy(object[off:], b)
		}
		le.PutUint64(object[16:], xid)
		le.PutUint64(object, checksum(object))
		for off := uint32(0); off < m.Size; off += c.BlockSize {
			if e := w.write(m.Address+uint64(off/c.BlockSize), object[off:off+c.BlockSize]); e != nil {
				return nil, e
			}
		}
	}
	active := map[uint64]bool{}
	for i := uint32(0); i < a.DescriptorLength; i++ {
		pa := a.DescriptorArea.Start + uint64((a.DescriptorIndex+i)%uint32(a.DescriptorArea.Count))
		active[pa] = true
		if pa == a.Superblock {
			continue
		}
		b, e := w.read(pa)
		if e != nil {
			return nil, e
		}
		le.PutUint64(b[16:], xid)
		le.PutUint64(b, checksum(b))
	}
	for i := uint64(0); i < a.DescriptorArea.Count; i++ {
		pa := a.DescriptorArea.Start + i
		if !active[pa] {
			if err := w.write(pa, make([]byte, c.BlockSize)); err != nil {
				return nil, err
			}
		}
	}
	le.PutUint64(nx[16:], xid)
	le.PutUint64(nx[88:], nextID)
	le.PutUint64(nx[96:], xid+1)
	le.PutUint64(nx, checksum(nx))
	if err := w.write(0, nx); err != nil {
		return nil, err
	}
	if err := w.write(a.Superblock, nx); err != nil {
		return nil, err
	}
	changed := make([]uint64, 0, len(w.blocks))
	for pa := range w.blocks {
		changed = append(changed, pa)
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i] < changed[j] })
	for _, r := range extents {
		if len(r.Key) != 16 || len(r.Value) != 16 {
			return nil, fmt.Errorf("apfs: invalid preserved file extent")
		}
		length, pa := le.Uint64(r.Value)&0x00ffffffffffffff, le.Uint64(r.Value[8:])
		blocks := (length + uint64(c.BlockSize) - 1) / uint64(c.BlockSize)
		if length == 0 {
			return nil, fmt.Errorf("apfs: empty preserved file extent")
		}
		if pa == 0 { // sparse extent
			continue
		}
		if pa >= c.Blocks || blocks > c.Blocks-pa {
			return nil, fmt.Errorf("apfs: preserved file extent outside container")
		}
		i := sort.Search(len(changed), func(i int) bool { return changed[i] >= pa })
		if i < len(changed) && changed[i] < pa+blocks {
			return nil, fmt.Errorf("apfs: metadata construction would overwrite file data at %d", changed[i])
		}
	}
	file, err := w.file()
	if err != nil {
		return nil, err
	}
	// Reopen through the independent readers before returning any constructed
	// image. This validates checksums, mappings, all node hashes and bit counts.
	check, err := Open(file)
	if err != nil {
		return nil, fmt.Errorf("apfs: constructed container: %w", err)
	}
	if _, err := check.Allocation(); err != nil {
		return nil, fmt.Errorf("apfs: constructed allocation: %w", err)
	}
	for _, spec := range options.Companions {
		found := false
		for _, volume := range check.Volumes {
			if volume.Name != spec.Name {
				continue
			}
			found = true
			if volume.Role != spec.Role || volume.Flags != 1 || volume.Incompatible != 0 {
				return nil, fmt.Errorf("apfs: constructed companion layout differs")
			}
			if _, err := volume.Entries(false); err != nil {
				return nil, fmt.Errorf("apfs: constructed companion directories: %w", err)
			}
		}
		if !found {
			return nil, fmt.Errorf("apfs: constructed companion volume absent")
		}
	}
	for _, volume := range check.Volumes {
		if volume.ID == v.ID {
			if _, _, err := volume.VerifySeal(expected); err != nil {
				return nil, fmt.Errorf("apfs: constructed seal: %w", err)
			}
			result := &SealedImage{File: file, RootHash: append([]byte(nil), expected...), Transaction: xid, TreeNodes: tree.Nodes, AllocatedBlocks: allocated, FreedBlocks: freed}
			if snapshot != nil {
				sv, e := volume.SnapshotVolume(snapshot.name)
				if e != nil {
					return nil, fmt.Errorf("apfs: constructed snapshot: %w", e)
				}
				if _, _, e = sv.VerifySeal(expected); e != nil {
					return nil, fmt.Errorf("apfs: constructed snapshot seal: %w", e)
				}
				result.SnapshotName, result.SnapshotTransaction, result.SnapshotUUID = snapshot.name, sealedXID, snapshot.uuid
			}
			return result, nil
		}
	}
	return nil, fmt.Errorf("apfs: constructed volume absent")
}
