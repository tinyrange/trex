package apfs

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// VolumeSpec constructs an unencrypted, case-sensitive companion filesystem.
// Directories are absolute volume-relative paths; missing parents are created.
// Creation time is explicit APFS nanoseconds. UUIDs are deterministic within
// the source system's volume group. No host filesystem or clock is consulted.
type VolumeSpec struct {
	Name        string
	Role        uint16
	Created     uint64
	Directories []string
	// Entries supplies plaintext initial contents with volume-relative paths.
	// Source IDs and compression are deliberately not carried into the new volume.
	Entries []Entry
}

type companionStats struct{ directories, files, symlinks, dataBlocks uint64 }

func companionContents(w *imageBlocks, spec VolumeSpec, allocate func() (uint64, error)) ([]Record, []Record, uint64, companionStats, error) {
	paths := append([]string(nil), spec.Directories...)
	entries := map[string]Entry{}
	for _, e := range spec.Entries {
		if e.Path == "/" || e.Path == "" || path.Clean(e.Path) != e.Path || !strings.HasPrefix(e.Path, "/") || strings.IndexByte(e.Path, 0) >= 0 || !utf8.ValidString(e.Path) || len(e.Path) > 4096 || len(path.Base(e.Path)) > 255 || len(entries) >= 1024 {
			return nil, nil, 0, companionStats{}, fmt.Errorf("apfs: invalid companion entry path")
		}
		if _, ok := entries[e.Path]; ok {
			return nil, nil, 0, companionStats{}, fmt.Errorf("apfs: duplicate companion entry")
		}
		if e.Kind != "directory" && e.Kind != "file" && e.Kind != "symlink" || e.Mode&0xf000 != map[string]uint16{"directory": 0x4000, "file": 0x8000, "symlink": 0xa000}[e.Kind] {
			return nil, nil, 0, companionStats{}, fmt.Errorf("apfs: invalid companion entry kind/mode")
		}
		if e.Kind == "directory" {
			paths = append(paths, e.Path)
		} else {
			paths = append(paths, path.Dir(e.Path))
		}
		entries[e.Path] = e
	}
	rows, next, err := companionDirectoryRecords(paths, spec.Created)
	if err != nil {
		return nil, nil, 0, companionStats{}, err
	}
	stats := companionStats{directories: next - 16 + 2}
	ids := map[string]uint64{"/": 2}
	// The directory constructor assigns IDs in sorted path order.
	dirs := map[string]bool{"/": true}
	for _, p := range paths {
		for p != "/" {
			if e, ok := entries[p]; ok && e.Kind != "directory" {
				return nil, nil, 0, stats, fmt.Errorf("apfs: non-directory companion parent")
			}
			dirs[p] = true
			p = path.Dir(p)
		}
	}
	ordered := make([]string, 0, len(dirs))
	for p := range dirs {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	for i, p := range ordered {
		if p != "/" {
			ids[p] = uint64(i-1) + 16
		}
	}
	for p, e := range entries {
		if e.Kind != "directory" {
			continue
		}
		id := ids[p]
		for i := range rows {
			if le.Uint64(rows[i].Key) == id|3<<60 {
				le.PutUint32(rows[i].Value[72:], e.UID)
				le.PutUint32(rows[i].Value[76:], e.GID)
				le.PutUint16(rows[i].Value[80:], e.Mode)
			}
		}
	}
	ordered = nil
	for p, e := range entries {
		if e.Kind != "directory" {
			ordered = append(ordered, p)
		}
	}
	sort.Strings(ordered)
	var refs []Record
	for _, p := range ordered {
		e := entries[p]
		id := next
		next++
		parent := ids[path.Dir(p)]
		if parent == 0 {
			return nil, nil, 0, stats, fmt.Errorf("apfs: missing companion parent")
		}
		name := path.Base(p)
		value := make([]byte, 104)
		le.PutUint64(value, parent)
		le.PutUint64(value[8:], id)
		for off := 16; off < 48; off += 8 {
			le.PutUint64(value[off:], spec.Created)
		}
		le.PutUint64(value[48:], 0x8000)
		le.PutUint32(value[56:], 1)
		le.PutUint32(value[64:], 1)
		le.PutUint32(value[72:], e.UID)
		le.PutUint32(value[76:], e.GID)
		le.PutUint16(value[80:], e.Mode)
		le.PutUint16(value[92:], 2)
		value[96], value[97] = 4, 2
		le.PutUint16(value[98:], uint16(len(name)+1))
		nameSize := (len(name) + 8) &^ 7
		value[100], value[101] = 8, 2
		le.PutUint16(value[102:], 40)
		le.PutUint16(value[94:], uint16(nameSize+40))
		value = append(value, make([]byte, nameSize+40)...)
		copy(value[104:], name)
		stream := value[104+nameSize:]
		if e.Kind == "file" {
			stats.files++
			if e.Data == nil || e.Data.Size() < 0 || e.Data.Size() > 8<<20 {
				return nil, nil, 0, stats, fmt.Errorf("apfs: invalid companion file bounds")
			}
			le.PutUint64(stream, uint64(e.Data.Size()))
			blocks := (uint64(e.Data.Size()) + uint64(w.c.BlockSize) - 1) / uint64(w.c.BlockSize)
			if (stats.dataBlocks+blocks)*uint64(w.c.BlockSize) > 32<<20 {
				return nil, nil, 0, stats, fmt.Errorf("apfs: companion file allocation bounds")
			}
			if blocks != 0 {
				rows = append(rows, Record{le.AppendUint64(nil, id|6<<60), le.AppendUint32(nil, 1)})
			}
			le.PutUint64(stream[8:], blocks*uint64(w.c.BlockSize))
			le.PutUint64(stream[24:], uint64(e.Data.Size()))
			for off := int64(0); off < e.Data.Size(); off += int64(w.c.BlockSize) {
				pa, err := allocate()
				if err != nil {
					return nil, nil, 0, stats, err
				}
				b := make([]byte, w.c.BlockSize)
				n := min(int64(w.c.BlockSize), e.Data.Size()-off)
				got, err := e.Data.ReadAt(b[:n], off)
				if got != int(n) {
					return nil, nil, 0, stats, io.ErrUnexpectedEOF
				}
				if err != nil && err != io.EOF {
					return nil, nil, 0, stats, err
				}
				if err := w.write(pa, b); err != nil {
					return nil, nil, 0, stats, err
				}
				key := le.AppendUint64(le.AppendUint64(nil, id|8<<60), uint64(off))
				x := le.AppendUint64(le.AppendUint64(le.AppendUint64(nil, uint64(w.c.BlockSize)), pa), 0)
				rows = append(rows, Record{key, x})
				r := le.AppendUint32(le.AppendUint64(le.AppendUint64(nil, 1|1<<60), id), 1)
				refs = append(refs, Record{le.AppendUint64(nil, pa|2<<60), r})
				stats.dataBlocks++
			}
		} else {
			stats.symlinks++
			if len(e.Target) > 1023 || strings.IndexByte(e.Target, 0) >= 0 {
				return nil, nil, 0, stats, fmt.Errorf("apfs: invalid companion symlink")
			}
			k := le.AppendUint16(le.AppendUint64(nil, id|4<<60), uint16(len("com.apple.fs.symlink")+1))
			k = append(k, []byte("com.apple.fs.symlink\x00")...)
			v := le.AppendUint16(le.AppendUint16(nil, 2), uint16(len(e.Target)+1))
			v = append(append(v, e.Target...), 0)
			rows = append(rows, Record{k, v})
		}
		rows = append(rows, Record{le.AppendUint64(nil, id|3<<60), value})
		key := le.AppendUint16(le.AppendUint64(nil, parent|9<<60), uint16(len(name)+1))
		key = append(append(key, name...), 0)
		dtype := uint16(8)
		if e.Kind == "symlink" {
			dtype = 10
		}
		drec := le.AppendUint16(le.AppendUint64(le.AppendUint64(nil, id), spec.Created), dtype)
		rows = append(rows, Record{key, drec})
		for i := range rows {
			if le.Uint64(rows[i].Key) == parent|3<<60 {
				le.PutUint32(rows[i].Value[56:], le.Uint32(rows[i].Value[56:])+1)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := le.Uint64(rows[i].Key), le.Uint64(rows[j].Key)
		if a&0x0fffffffffffffff != b&0x0fffffffffffffff {
			return a&0x0fffffffffffffff < b&0x0fffffffffffffff
		}
		if a>>60 != b>>60 {
			return a>>60 < b>>60
		}
		if a>>60 == 8 {
			return le.Uint64(rows[i].Key[8:]) < le.Uint64(rows[j].Key[8:])
		}
		return bytes.Compare(rows[i].Key[10:], rows[j].Key[10:]) < 0
	})
	sort.Slice(refs, func(i, j int) bool { return le.Uint64(refs[i].Key) < le.Uint64(refs[j].Key) })
	return rows, refs, next, stats, nil
}

func companionDirectoryRecords(paths []string, timestamp uint64) ([]Record, uint64, error) {
	names := map[string]bool{"/": true}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.IndexByte(p, 0) >= 0 || !utf8.ValidString(p) || len(p) > 4096 {
			return nil, 0, fmt.Errorf("apfs: invalid companion directory path")
		}
		for p != "/" {
			if len(path.Base(p)) > 255 || len(names) >= 128 && !names[p] {
				return nil, 0, fmt.Errorf("apfs: companion directory bounds")
			}
			names[p] = true
			p = path.Dir(p)
		}
	}
	ordered := make([]string, 0, len(names))
	for p := range names {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	ids := map[string]uint64{"/": 2}
	next := uint64(16)
	children := map[string]uint32{}
	for _, p := range ordered {
		if p != "/" {
			ids[p] = next
			next++
			children[path.Dir(p)]++
		}
	}
	inode := func(id, parent uint64, name string, mode uint16, count uint32) Record {
		value := make([]byte, 100)
		le.PutUint64(value, parent)
		le.PutUint64(value[8:], id)
		for off := 16; off < 48; off += 8 {
			le.PutUint64(value[off:], timestamp)
		}
		le.PutUint64(value[48:], 0x8000)
		le.PutUint32(value[56:], count)
		le.PutUint32(value[64:], 1)
		le.PutUint16(value[80:], mode)
		le.PutUint16(value[92:], 1)
		size := (len(name) + 1 + 7) &^ 7
		le.PutUint16(value[94:], uint16(size))
		value[96], value[97] = 4, 2
		le.PutUint16(value[98:], uint16(len(name)+1))
		value = append(value, make([]byte, size)...)
		copy(value[100:], name)
		return Record{le.AppendUint64(nil, id|3<<60), value}
	}
	rows := []Record{inode(2, 1, "root", 0x41ed, children["/"]), inode(3, 1, "private-dir", 0x41a4, 0)}
	directoryEntry := func(parent, id uint64, name string) Record {
		key := le.AppendUint16(le.AppendUint64(nil, parent|9<<60), uint16(len(name)+1))
		key = append(append(key, name...), 0)
		value := le.AppendUint64(le.AppendUint64(nil, id), timestamp)
		value = le.AppendUint16(value, 4) // DT_DIR
		return Record{key, value}
	}
	// Mount resolves these names beneath the synthetic parent (inode 1),
	// rather than opening inode 2 and inode 3 directly.
	rows = append(rows, directoryEntry(1, 2, "root"), directoryEntry(1, 3, "private-dir"))
	for _, p := range ordered {
		if p == "/" {
			continue
		}
		parent, name := ids[path.Dir(p)], path.Base(p)
		rows = append(rows, inode(ids[p], parent, name, 0x41ed, children[p]))
		rows = append(rows, directoryEntry(parent, ids[p], name))
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := le.Uint64(rows[i].Key), le.Uint64(rows[j].Key)
		if a&0x0fffffffffffffff != b&0x0fffffffffffffff {
			return a&0x0fffffffffffffff < b&0x0fffffffffffffff
		}
		if a>>60 != b>>60 {
			return a>>60 < b>>60
		}
		return bytes.Compare(rows[i].Key[10:], rows[j].Key[10:]) < 0
	})
	return rows, next, nil
}

func prepareCompanionVolumes(w *imageBlocks, nx, system []byte, mappings map[uint64]mapping, xid uint64, nextID *uint64, specs []VolumeSpec, allocate func() (uint64, error)) error {
	if len(specs) == 0 {
		return nil
	}
	if len(specs) > 16 || le.Uint32(nx[180:]) > 100 {
		return fmt.Errorf("apfs: excessive companion volumes")
	}
	group := append([]byte(nil), system[1008:1024]...)
	grouped := !bytes.Equal(group, make([]byte, 16))
	uuidSeed := group
	if !grouped {
		uuidSeed = system[240:256]
	}
	roles := map[uint16]bool{}
	names := map[string]bool{}
	for _, existing := range w.c.Volumes {
		roles[existing.Role], names[existing.Name] = true, true
	}
	for _, spec := range specs {
		if spec.Name == "" || len(spec.Name) > 255 || !utf8.ValidString(spec.Name) || strings.IndexByte(spec.Name, 0) >= 0 || spec.Created == 0 || spec.Role == 0 || roles[spec.Role] || names[spec.Name] || *nextID > ^uint64(0)-2 {
			return fmt.Errorf("apfs: invalid companion name, role, time or identifier")
		}
		roles[spec.Role], names[spec.Name] = true, true
		var slot uint32
		for slot < le.Uint32(nx[180:]) && le.Uint64(nx[184+slot*8:]) != 0 {
			slot++
		}
		if slot == le.Uint32(nx[180:]) {
			// Restore images can declare only one usable slot even though
			// the container superblock retains the complete 100-entry array.
			if slot >= 100 || le.Uint64(nx[184+slot*8:]) != 0 {
				return fmt.Errorf("apfs: no free companion volume slot")
			}
			le.PutUint32(nx[180:], slot+1)
		}
		rows, extentRows, nextInode, stats, err := companionContents(w, spec, allocate)
		if err != nil {
			return err
		}
		id, rootID := *nextID, *nextID+1
		*nextID += 2
		addresses := make([]uint64, 5)
		for i := range addresses {
			addresses[i], err = allocate()
			if err != nil {
				return err
			}
		}
		sb, omap, root, extent, snapshots := addresses[0], addresses[1], addresses[2], addresses[3], addresses[4]
		first := true
		fsMap, err := encodeVariableVirtualTree(rows, w.c.BlockSize, rootID, xid, nextID, func() (uint64, error) {
			if first {
				first = false
				return root, nil
			}
			return allocate()
		}, w.write)
		if err != nil {
			return err
		}
		for i, pa := range []uint64{extent, snapshots} {
			var entries []Record
			if i == 0 {
				entries = extentRows
			}
			b, err := encodeVariablePhysicalLeaf(entries, w.c.BlockSize, uint32(15+i), pa, xid)
			if err != nil {
				return err
			}
			if err := w.write(pa, b); err != nil {
				return err
			}
		}
		sort.Slice(fsMap, func(i, j int) bool { return le.Uint64(fsMap[i].Key) < le.Uint64(fsMap[j].Key) })
		mapRoot, mapNodes, err := encodePhysicalTree(fsMap, w.c.BlockSize, 11, xid, allocate, w.write)
		if err != nil {
			return err
		}
		objectMap := make([]byte, w.c.BlockSize)
		le.PutUint64(objectMap[8:], omap)
		le.PutUint64(objectMap[16:], xid)
		le.PutUint32(objectMap[24:], 0x4000000b)
		le.PutUint32(objectMap[40:], 0x40000002)
		le.PutUint32(objectMap[44:], 0x40000002)
		le.PutUint64(objectMap[48:], mapRoot)
		le.PutUint64(objectMap, checksum(objectMap))
		if err := w.write(omap, objectMap); err != nil {
			return err
		}
		volume := make([]byte, w.c.BlockSize)
		le.PutUint64(volume[8:], id)
		le.PutUint64(volume[16:], xid)
		le.PutUint32(volume[24:], 13)
		copy(volume[32:], "APSB")
		le.PutUint32(volume[36:], slot)
		le.PutUint64(volume[40:], 2) // hardlink-map records
		// The volume superblock belongs to the container. All other blocks
		// here are volume metadata; none contain allocated user file data.
		le.PutUint64(volume[88:], uint64(len(addresses)-2+len(fsMap))+mapNodes+stats.dataBlocks)
		copy(volume[96:116], system[96:116])
		le.PutUint32(volume[116:], 2)
		le.PutUint32(volume[120:], 0x40000002)
		le.PutUint32(volume[124:], 0x40000002)
		le.PutUint64(volume[128:], omap)
		le.PutUint64(volume[136:], rootID)
		le.PutUint64(volume[144:], extent)
		le.PutUint64(volume[152:], snapshots)
		le.PutUint64(volume[176:], nextInode)
		le.PutUint64(volume[184:], stats.files)
		le.PutUint64(volume[192:], stats.directories)
		le.PutUint64(volume[200:], stats.symlinks)
		le.PutUint64(volume[224:], stats.dataBlocks)
		h := sha1.New()
		h.Write(uuidSeed)
		h.Write(le.AppendUint16(nil, spec.Role))
		h.Write([]byte(spec.Name))
		copy(volume[240:256], h.Sum(nil))
		volume[246] = volume[246]&15 | 0x50
		volume[248] = volume[248]&63 | 0x80
		le.PutUint64(volume[256:], spec.Created)
		le.PutUint64(volume[264:], 1)
		copy(volume[272:], "trex_apfs 0.1")
		le.PutUint64(volume[304:], spec.Created)
		le.PutUint64(volume[312:], xid)
		copy(volume[320:368], volume[272:320])
		copy(volume[704:960], spec.Name)
		le.PutUint32(volume[960:], 3)
		le.PutUint16(volume[964:], spec.Role)
		if spec.Role == 0x40 && grouped {
			le.PutUint64(volume[40:], 0x12)
			copy(volume[1008:1024], group)
		}
		le.PutUint64(volume, checksum(volume))
		if err := w.write(sb, volume); err != nil {
			return err
		}
		if _, exists := mappings[id]; exists {
			return fmt.Errorf("apfs: companion volume identifier collides")
		}
		mappings[id] = mapping{xid, sb, 0, w.c.BlockSize}
		le.PutUint64(nx[184+slot*8:], id)
	}
	return nil
}
