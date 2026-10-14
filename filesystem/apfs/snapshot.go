package apfs

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Snapshot identifies an immutable filesystem version, independently of disk
// paths or mounting. Superblock and ExtentReferenceTree are physical objects.
type Snapshot struct {
	Name                                                                  string
	Transaction, Superblock, ExtentReferenceTree, Created, Changed, Inode uint64
	ExtentReferenceTreeType, Flags                                        uint32
}

func snapshotName(b []byte, length int) (string, error) {
	if length < 2 || length > 256 || length != len(b) || b[length-1] != 0 || bytes.IndexByte(b[:length-1], 0) >= 0 || !utf8.Valid(b[:length-1]) || bytes.IndexByte(b, '/') >= 0 {
		return "", fmt.Errorf("apfs: invalid snapshot name")
	}
	return string(b[:length-1]), nil
}

// Snapshots validates the metadata/name index and returns snapshots in xid order.
func (v *Volume) Snapshots() ([]Snapshot, error) {
	if v.SnapshotTree == 0 {
		if v.SnapshotCount != 0 {
			return nil, fmt.Errorf("apfs: missing snapshot metadata tree")
		}
		return nil, nil
	}
	pa, err := v.rootAddress(v.SnapshotTree, v.SnapshotTreeType)
	if err != nil {
		return nil, err
	}
	var result []Snapshot
	names := map[string]uint64{}
	ids := map[uint64]bool{}
	err = v.container.walkTree(pa, func(id uint64) (uint64, error) { return v.rootAddress(id, v.SnapshotTreeType) }, func(k, b []byte) error {
		if len(k) < 8 {
			return fmt.Errorf("apfs: truncated snapshot key")
		}
		id, kind := le.Uint64(k)&0x0fffffffffffffff, le.Uint64(k)>>60
		switch kind {
		case 1:
			if len(k) != 8 || len(b) < 50 || id == 0 || id > v.Transaction || ids[id] || len(result) >= 100000 {
				return fmt.Errorf("apfs: invalid snapshot metadata")
			}
			name, e := snapshotName(b[50:], int(le.Uint16(b[48:])))
			if e != nil {
				return e
			}
			ids[id] = true
			result = append(result, Snapshot{name, id, le.Uint64(b[8:]), le.Uint64(b), le.Uint64(b[16:]), le.Uint64(b[24:]), le.Uint64(b[32:]), le.Uint32(b[40:]), le.Uint32(b[44:])})
		case 11:
			if id != 0x0fffffffffffffff || len(k) < 10 || len(b) != 8 {
				return fmt.Errorf("apfs: invalid snapshot name record")
			}
			name, e := snapshotName(k[10:], int(le.Uint16(k[8:])))
			if e != nil {
				return e
			}
			if _, ok := names[name]; ok {
				return fmt.Errorf("apfs: duplicate snapshot name")
			}
			names[name] = le.Uint64(b)
		default:
			return fmt.Errorf("apfs: unsupported snapshot record type %d", kind)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if uint64(len(result)) != v.SnapshotCount || len(names) != len(result) {
		return nil, fmt.Errorf("apfs: inconsistent snapshot counts")
	}
	for _, s := range result {
		if names[s.Name] != s.Transaction || s.Superblock >= v.container.Blocks || s.ExtentReferenceTree >= v.container.Blocks {
			return nil, fmt.Errorf("apfs: inconsistent snapshot name/address")
		}
	}
	return result, nil
}

// SnapshotVolume opens a named snapshot through its physical superblock and
// the volume object map as of that snapshot's transaction.
func (v *Volume) SnapshotVolume(name string) (*Volume, error) {
	rows, err := v.Snapshots()
	if err != nil {
		return nil, err
	}
	for _, s := range rows {
		if s.Name != name {
			continue
		}
		b, e := v.container.object(s.Superblock, 13)
		if e != nil {
			return nil, e
		}
		if le.Uint32(b[24:]) != 0x4000000d || le.Uint64(b[8:]) != s.Superblock || le.Uint64(b[16:]) != s.Transaction || le.Uint64(b[144:]) != s.ExtentReferenceTree || le.Uint32(b[120:]) != s.ExtentReferenceTreeType {
			return nil, fmt.Errorf("apfs: snapshot superblock identity mismatch")
		}
		return v.container.volume(b)
	}
	return nil, fmt.Errorf("apfs: snapshot %q absent", name)
}

// encodeVariablePhysicalLeaf encodes a bounded ordinary variable-size root.
// Snapshot metadata and an empty extent-reference tree require one leaf each.
func encodeVariablePhysicalLeaf(rows []Record, blockSize, subtype uint32, pa, xid uint64) ([]byte, error) {
	if blockSize < 4096 || blockSize > 65536 || blockSize&(blockSize-1) != 0 || len(rows) > 100000 {
		return nil, fmt.Errorf("apfs: invalid variable leaf geometry")
	}
	b := make([]byte, blockSize)
	le.PutUint64(b[8:], pa)
	le.PutUint64(b[16:], xid)
	le.PutUint32(b[24:], 0x40000002)
	le.PutUint32(b[28:], subtype)
	le.PutUint16(b[32:], 3)
	le.PutUint32(b[36:], uint32(len(rows)))
	tableSize := max(8, ((len(rows)+7)/8)*8) * 8
	if tableSize > len(b)-96 {
		return nil, fmt.Errorf("apfs: variable leaf table exceeds block")
	}
	le.PutUint16(b[42:], uint16(tableSize))
	le.PutUint16(b[48:], 65535)
	le.PutUint16(b[52:], 65535)
	base := 56 + tableSize
	kp, vp := base, len(b)-40
	info := b[len(b)-40:]
	le.PutUint32(info, 0x52)
	le.PutUint32(info[4:], blockSize)
	le.PutUint64(info[24:], uint64(len(rows)))
	le.PutUint64(info[32:], 1)
	for i, r := range rows {
		if len(r.Key) < 8 || len(r.Value) == 0 || len(r.Key)+len(r.Value) > vp-kp {
			return nil, fmt.Errorf("apfs: variable records exceed one leaf")
		}
		vp -= len(r.Value)
		toc := b[56+i*8:]
		le.PutUint16(toc, uint16(kp-base))
		le.PutUint16(toc[2:], uint16(len(r.Key)))
		le.PutUint16(toc[4:], uint16(len(b)-40-vp))
		le.PutUint16(toc[6:], uint16(len(r.Value)))
		copy(b[kp:], r.Key)
		copy(b[vp:], r.Value)
		kp += len(r.Key)
		le.PutUint32(info[16:], max(le.Uint32(info[16:]), uint32(len(r.Key))))
		le.PutUint32(info[20:], max(le.Uint32(info[20:]), uint32(len(r.Value))))
	}
	le.PutUint16(b[44:], uint16(kp-base))
	le.PutUint16(b[46:], uint16(vp-kp))
	le.PutUint64(b, checksum(b))
	return b, nil
}

// SealImageOptions adds a named immutable boot snapshot to a newly sealed image.
// Snapshot creation time is supplied explicitly; image construction uses no host clock.
type SealImageOptions struct {
	SnapshotName string
	SnapshotTime uint64
	Companions   []VolumeSpec
}

type imageSnapshot struct {
	name                             string
	xid, time, sb, tree, extent, sme uint64
	uuid                             [16]byte
}

func prepareImageSnapshot(w *imageBlocks, vol []byte, m map[uint64]mapping, xid, snapXID uint64, nextID *uint64, options SealImageOptions, rootHash []byte, allocate func() (uint64, error)) (*imageSnapshot, error) {
	name := options.SnapshotName
	if name == "" {
		return nil, nil
	}
	if len(name) > 255 || !utf8.ValidString(name) || strings.ContainsAny(name, "/\x00") || options.SnapshotTime == 0 || *nextID == ^uint64(0) {
		return nil, fmt.Errorf("apfs: invalid boot snapshot name/time/identifier")
	}
	s := &imageSnapshot{name: name, xid: snapXID, time: options.SnapshotTime, sme: *nextID}
	*nextID++
	if _, exists := m[s.sme]; exists {
		return nil, fmt.Errorf("apfs: snapshot metadata identifier collides")
	}
	h := sha1.New()
	h.Write(vol[240:256])
	h.Write(rootHash)
	h.Write([]byte(name))
	copy(s.uuid[:], h.Sum(nil))
	s.uuid[6] = s.uuid[6]&15 | 0x50
	s.uuid[8] = s.uuid[8]&63 | 0x80
	var err error
	for _, p := range []*uint64{&s.sb, &s.tree, &s.extent} {
		*p, err = allocate()
		if err != nil {
			return nil, err
		}
	}
	empty, err := encodeVariablePhysicalLeaf(nil, w.c.BlockSize, 15, s.extent, xid)
	if err != nil {
		return nil, err
	}
	if err = w.write(s.extent, empty); err != nil {
		return nil, err
	}
	value := make([]byte, 50+len(name)+1)
	le.PutUint64(value, le.Uint64(vol[144:]))
	le.PutUint64(value[8:], s.sb)
	le.PutUint64(value[16:], s.time)
	le.PutUint64(value[24:], s.time)
	le.PutUint32(value[40:], le.Uint32(vol[120:]))
	le.PutUint16(value[48:], uint16(len(name)+1))
	copy(value[50:], name)
	key := le.AppendUint16(le.AppendUint64(nil, 0xbfffffffffffffff), uint16(len(name)+1))
	key = append(key, []byte(name)...)
	key = append(key, 0)
	rows := []Record{{le.AppendUint64(nil, s.xid|1<<60), value}, {key, le.AppendUint64(nil, s.xid)}}
	meta, err := encodeVariablePhysicalLeaf(rows, w.c.BlockSize, 16, s.tree, xid)
	if err != nil {
		return nil, err
	}
	if err = w.write(s.tree, meta); err != nil {
		return nil, err
	}
	pa, err := allocate()
	if err != nil {
		return nil, err
	}
	ext := make([]byte, w.c.BlockSize)
	le.PutUint64(ext[8:], s.sme)
	le.PutUint64(ext[16:], xid)
	le.PutUint32(ext[24:], 29)
	le.PutUint32(ext[32:], 1)
	le.PutUint64(ext[40:], s.xid)
	copy(ext[48:], s.uuid[:])
	le.PutUint64(ext, checksum(ext))
	if err = w.write(pa, ext); err != nil {
		return nil, err
	}
	m[s.sme] = mapping{xid, pa, 0, w.c.BlockSize}
	return s, nil
}
