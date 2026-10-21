package zfs

import (
	"bytes"
	"fmt"
)

// ZAP integers inside array chunks are big-endian independently of block order.
func (s *objset) zap(id uint64) (map[string][]uint64, error) {
	obj, err := s.get(id)
	if err != nil {
		return nil, err
	}
	return obj.zap()
}
func (obj *object) zap() (map[string][]uint64, error) {
	b, o, err := obj.block(0)
	if err != nil {
		return nil, err
	}
	out := map[string][]uint64{}
	add := func(name []byte, values []uint64) error {
		if len(name) == 0 || name[len(name)-1] != 0 {
			return fmt.Errorf("zfs: unterminated ZAP key")
		}
		name = name[:len(name)-1]
		if bytes.IndexByte(name, 0) >= 0 {
			return fmt.Errorf("zfs: embedded NUL in ZAP key")
		}
		if _, ok := out[string(name)]; ok {
			return fmt.Errorf("zfs: duplicate ZAP key")
		}
		if len(out) >= obj.p.maximum {
			return fmt.Errorf("zfs: ZAP entry limit")
		}
		out[string(name)] = values
		return nil
	}
	if len(b) < 128 {
		return nil, fmt.Errorf("zfs: short ZAP")
	}
	if o.Uint64(b) == 0x8000000000000003 {
		for at := 64; at+64 <= len(b); at += 64 {
			if b[at+14] == 0 {
				continue
			}
			name := b[at+14 : at+64]
			i := bytes.IndexByte(name, 0)
			if i < 0 {
				return nil, fmt.Errorf("zfs: unterminated micro-ZAP name")
			}
			if err := add(name[:i+1], []uint64{o.Uint64(b[at:])}); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	if o.Uint64(b) != 0x8000000000000001 || o.Uint64(b[8:]) != 0x2f52ab2ab {
		return nil, fmt.Errorf("zfs: invalid ZAP header")
	}
	shift := o.Uint64(b[32:])
	if shift > 24 || uint64(1)<<shift > uint64(obj.p.maximum)*8 {
		return nil, fmt.Errorf("zfs: ZAP pointer limit")
	}
	count := 1 << shift
	first, nblocks := o.Uint64(b[16:]), o.Uint64(b[24:])
	leaves := map[uint64]bool{}
	for i := uint64(0); i < uint64(count); i++ {
		var id uint64
		if nblocks == 0 {
			at := len(b)/2 + int(i)*8
			if at+8 > len(b) {
				return nil, fmt.Errorf("zfs: embedded ZAP pointer table out of bounds")
			}
			id = o.Uint64(b[at:])
		} else {
			index := i * 8 / uint64(obj.blockSize)
			if index >= nblocks {
				return nil, fmt.Errorf("zfs: ZAP pointer table truncated")
			}
			data, bo, err := obj.block(first + index)
			if err != nil {
				return nil, err
			}
			id = bo.Uint64(data[i*8%uint64(obj.blockSize):])
		}
		if id != 0 {
			leaves[id] = true
		}
	}
	for id := range leaves {
		if id >= uint64(obj.size/obj.blockSize) {
			return nil, fmt.Errorf("zfs: leaf out of bounds")
		}
		leaf, bo, err := obj.block(id)
		if err != nil {
			return nil, err
		}
		if len(leaf) < 48 || bo.Uint64(leaf) != 0x8000000000000000 || bo.Uint32(leaf[24:]) != 0x2ab1eaf {
			return nil, fmt.Errorf("zfs: invalid ZAP leaf")
		}
		base := 48 + len(leaf)/16
		chunks := (len(leaf) - base) / 24
		array := func(start, n int) ([]byte, error) {
			if n < 0 || n > maxBlock {
				return nil, fmt.Errorf("zfs: ZAP array limit")
			}
			data := make([]byte, 0, n)
			seen := map[int]bool{}
			for len(data) < n {
				if start < 0 || start >= chunks || seen[start] {
					return nil, fmt.Errorf("zfs: invalid ZAP array chain")
				}
				seen[start] = true
				c := leaf[base+24*start : base+24*(start+1)]
				if c[0] != 251 {
					return nil, fmt.Errorf("zfs: expected ZAP array")
				}
				data = append(data, c[1:1+min(21, n-len(data))]...)
				start = int(bo.Uint16(c[22:]))
			}
			return data, nil
		}
		entries := 0
		for i := 0; i < chunks; i++ {
			c := leaf[base+24*i : base+24*(i+1)]
			if c[0] != 252 {
				continue
			}
			entries++
			name, err := array(int(bo.Uint16(c[4:])), int(bo.Uint16(c[6:])))
			if err != nil {
				return nil, err
			}
			width, n := int(c[1]), int(bo.Uint16(c[10:]))
			if width != 1 && width != 2 && width != 4 && width != 8 {
				return nil, fmt.Errorf("zfs: invalid ZAP integer width")
			}
			value, err := array(int(bo.Uint16(c[8:])), width*n)
			if err != nil {
				return nil, err
			}
			values := make([]uint64, n)
			for j := range values {
				for _, v := range value[j*width : (j+1)*width] {
					values[j] = values[j]<<8 | uint64(v)
				}
			}
			if err := add(name, values); err != nil {
				return nil, err
			}
		}
		if entries != int(bo.Uint16(leaf[30:])) {
			return nil, fmt.Errorf("zfs: ZAP leaf count mismatch")
		}
	}
	return out, nil
}
func scalar(m map[string][]uint64, name string) (uint64, error) {
	v := m[name]
	if len(v) != 1 {
		return 0, fmt.Errorf("zfs: missing/scalar attribute %q", name)
	}
	return v[0], nil
}
