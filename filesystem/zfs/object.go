package zfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

type object struct {
	p         *pool
	raw       []byte
	o         binary.ByteOrder
	blockSize int64
	size      int64
}

func newObject(p *pool, b []byte, o binary.ByteOrder) (*object, error) {
	if len(b) < 512 {
		return nil, fmt.Errorf("zfs: truncated dnode")
	}
	size := 512 * (int(b[12]) + 1)
	if size > len(b) {
		return nil, fmt.Errorf("zfs: dnode slots truncated")
	}
	b = b[:size]
	block := int64(o.Uint16(b[8:])) * 512
	if b[0] == 0 || b[3] > 3 || int(b[3])*128+64 > len(b) || b[2] > 8 || (b[2] != 0 && (b[1] < 7 || b[1] > 20)) || block > maxBlock {
		return nil, fmt.Errorf("zfs: invalid dnode geometry (type=%d shift=%d levels=%d pointers=%d size=%d)", b[0], b[1], b[2], b[3], block)
	}
	max := o.Uint64(b[16:])
	if block > 0 && max >= uint64((1<<63-1)/block) {
		return nil, fmt.Errorf("zfs: oversized object")
	}
	return &object{p: p, raw: append([]byte(nil), b...), o: o, blockSize: block, size: int64(max+1) * block}, nil
}
func (o *object) bonus() []byte {
	start := 64 + int(o.raw[3])*128
	end := start + int(o.o.Uint16(o.raw[10:]))
	if end > len(o.raw) {
		return nil
	}
	return o.raw[start:end]
}
func (o *object) Size() int64 { return o.size }
func (o *object) block(id uint64) ([]byte, binary.ByteOrder, error) {
	if o.blockSize == 0 || o.raw[2] == 0 {
		return nil, nil, fmt.Errorf("zfs: object has no data")
	}
	levels := int(o.raw[2])
	shift := int(o.raw[1]) - 7
	topShift := shift * (levels - 1)
	if topShift >= 64 {
		return nil, nil, fmt.Errorf("zfs: excessive indirection")
	}
	slot := id >> topShift
	if slot >= uint64(o.raw[3]) {
		return make([]byte, o.blockSize), o.o, nil
	}
	bp := pointer{o.raw[64+int(slot)*128 : 64+int(slot+1)*128], o.o}
	for level := levels - 1; level > 0; level-- {
		b, bo, err := o.p.block(bp)
		if err != nil {
			return nil, nil, err
		}
		index := (id >> ((level - 1) * shift)) & ((1 << shift) - 1)
		at := index * 128
		if at+128 > uint64(len(b)) {
			return nil, nil, fmt.Errorf("zfs: indirect index out of bounds")
		}
		bp = pointer{b[at : at+128], bo}
	}
	b, bo, err := o.p.block(bp)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) != o.blockSize {
		if len(b) == 512 {
			zero := true
			for _, v := range bp.b[:48] {
				zero = zero && v == 0
			}
			if zero {
				return make([]byte, o.blockSize), bo, nil
			}
		}
		return nil, nil, fmt.Errorf("zfs: data block size mismatch")
	}
	return b, bo, nil
}
func (o *object) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("zfs: negative offset")
	}
	if len(b) == 0 {
		return 0, nil
	}
	if off >= o.size {
		return 0, io.EOF
	}
	n := 0
	for len(b) > 0 && off < o.size {
		data, _, err := o.block(uint64(off / o.blockSize))
		if err != nil {
			return n, err
		}
		at := off % o.blockSize
		count := min(len(b), len(data)-int(at), int(o.size-off))
		if count <= 0 {
			return n, io.ErrNoProgress
		}
		copy(b[:count], data[at:int(at)+count])
		b = b[count:]
		n += count
		off += int64(count)
	}
	if len(b) > 0 {
		return n, io.EOF
	}
	return n, nil
}

type objset struct {
	p    *pool
	meta *object
}

func (p *pool) objset(bp pointer) (*objset, error) {
	b, o, err := p.block(bp)
	if err != nil {
		return nil, err
	}
	meta, err := newObject(p, b, o)
	if err != nil {
		return nil, err
	}
	if meta.blockSize == 0 || meta.raw[2] == 0 {
		return nil, fmt.Errorf("zfs: empty metadnode")
	}
	return &objset{p, meta}, nil
}
func (s *objset) get(id uint64) (*object, error) {
	if s.meta.blockSize == 0 || id >= uint64(s.meta.Size())/512 {
		return nil, fmt.Errorf("zfs: object outside metadnode")
	}
	off := id * 512
	block, bo, err := s.meta.block(off / uint64(s.meta.blockSize))
	if err != nil {
		return nil, err
	}
	at := off % uint64(s.meta.blockSize)
	if at >= uint64(len(block)) {
		return nil, fmt.Errorf("zfs: object offset out of bounds")
	}
	return newObject(s.p, block[at:], bo)
}
