// Package apfs reads Apple File System containers and constructs authenticated
// metadata trees through portable byte views, without host mounting or tools.
// Layout reference: Apple File System Reference (2020-06-22),
// https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf.
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

var le = binary.LittleEndian

type Container struct {
	Source              storage.Reader
	Superblock          storage.Reader
	BlockSize           uint32
	Blocks, Transaction uint64
	Volumes             []*Volume
}

type Volume struct {
	container                                      *Container
	Superblock                                     storage.Reader
	Name                                           string
	UUID                                           [16]byte
	ID, Transaction, Features, Incompatible, Flags uint64
	Role                                           uint16
	RootTree, ExtentTree, Integrity                uint64
	RootTreeType, ExtentTreeType                   uint32
	SnapshotCount, SnapshotTree                    uint64
	SnapshotTreeType                               uint32
	omap                                           map[uint64]mapping
}

type mapping struct {
	xid, address uint64
	flags, size  uint32
}

func (v *Volume) rootAddress(id uint64, kind uint32) (uint64, error) {
	switch kind & 0xc0000000 {
	case 0x40000000:
		return id, nil
	case 0:
		return resolve(v.omap, id)
	default:
		return 0, fmt.Errorf("apfs: ephemeral tree unsupported")
	}
}

func checksum(b []byte) uint64 {
	const modulus uint64 = 0xffffffff
	var a, c uint64
	for i := 8; i < len(b); i += 4 {
		a = (a + uint64(le.Uint32(b[i:]))) % modulus
		c = (c + a) % modulus
	}
	x := (modulus - (a+c)%modulus) % modulus
	y := (modulus - (a+x)%modulus) % modulus
	return y<<32 | x
}

func (c *Container) raw(address uint64) ([]byte, error) {
	if address >= c.Blocks {
		return nil, fmt.Errorf("apfs: block %d outside container", address)
	}
	b := make([]byte, c.BlockSize)
	_, err := io.ReadFull(io.NewSectionReader(c.Source, int64(address*uint64(c.BlockSize)), int64(c.BlockSize)), b)
	return b, err
}

func verify(b []byte) error {
	if len(b) < 32 || le.Uint64(b) != checksum(b) {
		return fmt.Errorf("apfs: object checksum mismatch")
	}
	return nil
}

func (c *Container) object(address uint64, kind uint32) ([]byte, error) {
	b, err := c.raw(address)
	if err != nil {
		return nil, err
	}
	if err := verify(b); err != nil {
		return nil, fmt.Errorf("apfs: block %d: %w", address, err)
	}
	if le.Uint32(b[24:])&0xffff != kind {
		return nil, fmt.Errorf("apfs: block %d: expected object %d, got %x", address, kind, le.Uint32(b[24:]))
	}
	return b, nil
}

func Open(source storage.Reader) (*Container, error) {
	if source == nil || source.Size() < 4096 {
		return nil, fmt.Errorf("apfs: truncated container")
	}
	var h [40]byte
	if _, err := source.ReadAt(h[:], 0); err != nil {
		return nil, err
	}
	blockSize := le.Uint32(h[36:])
	if string(h[32:36]) != "NXSB" || blockSize < 4096 || blockSize > 65536 || blockSize&(blockSize-1) != 0 {
		return nil, fmt.Errorf("apfs: invalid container signature/block size")
	}
	c := &Container{Source: source, BlockSize: blockSize, Blocks: uint64(source.Size()) / uint64(blockSize)}
	super, err := c.object(0, 1)
	if err != nil {
		return nil, err
	}
	blocks := le.Uint64(super[40:])
	if blocks == 0 || blocks > c.Blocks {
		return nil, fmt.Errorf("apfs: declared container exceeds source")
	}
	c.Blocks = blocks
	if le.Uint64(super[64:]) & ^uint64(2) != 0 {
		return nil, fmt.Errorf("apfs: unsupported container features")
	}
	descriptors, base := uint64(le.Uint32(super[104:])), le.Uint64(super[112:])
	if descriptors > 65536 || base > c.Blocks || descriptors > c.Blocks-base {
		return nil, fmt.Errorf("apfs: unsupported or invalid checkpoint descriptor area")
	}
	for i := uint64(0); i < descriptors; i++ {
		b, err := c.raw(base + i)
		if err != nil {
			return nil, err
		}
		if string(b[32:36]) != "NXSB" || verify(b) != nil {
			continue
		}
		if le.Uint64(b[16:]) > le.Uint64(super[16:]) && le.Uint32(b[36:]) == blockSize && le.Uint64(b[40:]) == blocks && bytes.Equal(b[72:88], super[72:88]) {
			super = b
		}
	}
	c.Transaction = le.Uint64(super[16:])
	c.Superblock = bytes.NewReader(super)
	omap, err := c.readMap(le.Uint64(super[160:]), c.Transaction)
	if err != nil {
		return nil, err
	}
	maxVolumes := le.Uint32(super[180:])
	if maxVolumes > 100 {
		return nil, fmt.Errorf("apfs: excessive volume slots")
	}
	for i := uint32(0); i < maxVolumes; i++ {
		id := le.Uint64(super[184+8*i:])
		if id == 0 {
			continue
		}
		address, err := resolve(omap, id)
		if err != nil {
			return nil, err
		}
		b, err := c.object(address, 13)
		if err != nil {
			return nil, err
		}
		if string(b[32:36]) != "APSB" || le.Uint64(b[8:]) != id {
			return nil, fmt.Errorf("apfs: invalid volume superblock")
		}
		v, err := c.volume(b)
		if err != nil {
			return nil, err
		}
		c.Volumes = append(c.Volumes, v)
	}
	return c, nil
}

func (c *Container) volume(b []byte) (*Volume, error) {
	if len(b) < 1044 || string(b[32:36]) != "APSB" {
		return nil, fmt.Errorf("apfs: invalid volume superblock")
	}
	v := &Volume{container: c, Name: string(bytes.TrimRight(b[704:960], "\x00")), ID: le.Uint64(b[8:]), Transaction: le.Uint64(b[16:]),
		Features: le.Uint64(b[40:]), Incompatible: le.Uint64(b[56:]), Flags: le.Uint64(b[264:]), Role: le.Uint16(b[964:]),
		RootTree: le.Uint64(b[136:]), RootTreeType: le.Uint32(b[116:]), ExtentTree: le.Uint64(b[1032:]), ExtentTreeType: le.Uint32(b[1040:]), Integrity: le.Uint64(b[1024:])}
	v.Superblock = bytes.NewReader(append([]byte(nil), b...))
	v.SnapshotCount, v.SnapshotTree, v.SnapshotTreeType = le.Uint64(b[216:]), le.Uint64(b[152:]), le.Uint32(b[124:])
	copy(v.UUID[:], b[240:256])
	var err error
	v.omap, err = c.readMap(le.Uint64(b[128:]), v.Transaction)
	return v, err
}

func resolve(m map[uint64]mapping, id uint64) (uint64, error) {
	entry, ok := m[id]
	if !ok || entry.flags&1 != 0 {
		return 0, fmt.Errorf("apfs: object %d is absent/deleted", id)
	}
	if entry.flags&4 != 0 {
		return 0, fmt.Errorf("apfs: encrypted object %d unsupported", id)
	}
	return entry.address, nil
}

func (c *Container) readMap(address, xid uint64) (map[uint64]mapping, error) {
	b, err := c.object(address, 11)
	if err != nil {
		return nil, err
	}
	if le.Uint32(b[40:])&0xc0000000 != 0x40000000 {
		return nil, fmt.Errorf("apfs: object map tree must be physical")
	}
	result := map[uint64]mapping{}
	err = c.walkTree(le.Uint64(b[48:]), nil, func(k, v []byte) error {
		if len(k) != 16 || len(v) != 16 {
			return fmt.Errorf("apfs: invalid object map record")
		}
		id, transaction := le.Uint64(k), le.Uint64(k[8:])
		if transaction > xid {
			return nil
		}
		old, ok := result[id]
		if ok && old.xid == transaction {
			return fmt.Errorf("apfs: duplicate object mapping")
		}
		if !ok || transaction > old.xid {
			entry := mapping{transaction, le.Uint64(v[8:]), le.Uint32(v), le.Uint32(v[4:])}
			if entry.flags&1 == 0 && (entry.address >= c.Blocks || entry.size != c.BlockSize) {
				return fmt.Errorf("apfs: unsupported object map extent")
			}
			result[id] = entry
		}
		return nil
	})
	return result, err
}
