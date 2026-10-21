package erofs

import (
	"fmt"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

type compression struct {
	base, count, logical uint64
	advise               uint16
	bits                 uint8
}
type cluster struct {
	kind                                     uint8
	offset, back, blocks, physical, nextPack uint64
}

func (n *inode) compression() (compression, error) {
	pos := (n.tail + 7) &^ uint64(7)
	h, err := n.fs.read(pos, 8)
	if err != nil {
		return compression{}, err
	}
	c := compression{base: pos + 8, advise: le.Uint16(h[4:]), bits: n.fs.bits + (h[7] & 15)}
	if h[6] != 0 || h[7]&^byte(15) != 0 || c.advise & ^uint16(23) != 0 || n.fs.algorithms&1 == 0 || n.layout == 1 && c.advise&1 != 0 {
		return c, fmt.Errorf("unsupported compression map or algorithm")
	}
	if c.advise&6 != 0 && n.fs.incompat&2 == 0 {
		return c, fmt.Errorf("big cluster lacks superblock feature")
	}
	if n.layout == 3 && (c.advise&2 != 0) != (c.advise&4 != 0) {
		return c, fmt.Errorf("inconsistent big cluster flags")
	}
	if n.layout == 3 && c.bits > 14 || c.bits > 20 {
		return c, fmt.Errorf("unsupported logical cluster size")
	}
	c.logical = uint64(1) << c.bits
	c.count = (n.size + c.logical - 1) / c.logical
	return c, nil
}

// index reads one logical-cluster record. Compact packs store bit fields and
// one physical base; block counts/deltas supply the position within that pack.
func (n *inode) index(c compression, index uint64) (cluster, error) {
	if index >= c.count {
		return cluster{}, fmt.Errorf("cluster index outside file")
	}
	if n.layout == 1 {
		pos := c.base + 8 + index*8
		b, err := n.fs.read(pos, 8)
		if err != nil {
			return cluster{}, err
		}
		flags := le.Uint16(b)
		if flags & ^uint16(3) != 0 {
			return cluster{}, fmt.Errorf("unsupported full cluster flags %#x", flags)
		}
		r := cluster{kind: uint8(flags & 3), nextPack: pos + 8}
		if r.kind == 2 {
			r.back = uint64(le.Uint16(b[4:]))
			if r.back&2048 != 0 {
				r.blocks = r.back &^ uint64(2048)
				r.back = 1
			}
		} else {
			r.offset = uint64(le.Uint16(b[2:]))
			r.physical = uint64(le.Uint32(b[4:]))
		}
		return n.validateCluster(c, r)
	}
	initial := (32 - c.base%32) / 4
	if initial == 8 {
		initial = 0
	}
	two := uint64(0)
	if c.advise&1 != 0 && initial < c.count {
		two = (c.count - initial) / 16 * 16
	}
	pos := c.base
	stride := uint64(4)
	within := index
	if index >= initial {
		pos += initial * 4
		within -= initial
		if within < two {
			stride = 2
		} else {
			pos += two * 2
			within -= two
		}
	}
	pos += within * stride
	entries := uint64(2)
	if stride == 2 {
		if c.bits > 12 {
			return cluster{}, fmt.Errorf("2-byte indexes require logical clusters at most 4KiB")
		}
		entries = 16
	}
	packSize := entries * stride
	packPos := pos / packSize * packSize
	b, err := n.fs.read(packPos, packSize)
	if err != nil {
		return cluster{}, err
	}
	item := (pos - packPos) / stride
	lowBits := max(uint8(12), c.bits)
	width := (packSize - 4) * 8 / entries
	decode := func(i uint64) (uint64, uint8) {
		bit := i * width
		at := bit / 8
		value := uint64(le.Uint32(b[at:])) >> (bit % 8)
		return value & ((uint64(1) << lowBits) - 1), uint8(value >> lowBits & 3)
	}
	low, kind := decode(item)
	r := cluster{kind: kind, nextPack: packPos + packSize}
	big := c.advise&2 != 0
	if kind == 2 {
		if low&2048 != 0 {
			if !big {
				return r, fmt.Errorf("block count in small physical cluster")
			}
			r.blocks = low &^ uint64(2048)
			r.back = 1
		} else if item+1 < entries {
			r.back = low
		} else {
			prior, t := decode(item - 1)
			if t != 2 {
				prior = 0
			} else if prior&2048 != 0 {
				prior = 1
			}
			r.back = prior + 1
		}
	} else {
		r.offset = low
		blocks := uint64(1)
		if big {
			blocks = 0
		}
		for previous := int(item) - 1; previous >= 0; previous-- {
			lo, t := decode(uint64(previous))
			if !big {
				if t == 2 {
					previous -= int(lo)
				}
				if previous >= 0 {
					blocks++
				}
			} else if t != 2 {
				blocks++
			} else if lo&2048 != 0 {
				previous--
				blocks += lo &^ uint64(2048)
			} else {
				if lo <= 1 {
					return r, fmt.Errorf("invalid big cluster back reference")
				}
				previous -= int(lo) - 2
			}
		}
		r.physical = uint64(le.Uint32(b[packSize-4:])) + blocks
	}
	return n.validateCluster(c, r)
}
func (n *inode) validateCluster(c compression, r cluster) (cluster, error) {
	if r.kind == 3 {
		return r, fmt.Errorf("unsupported HEAD2 cluster")
	}
	if r.kind == 2 {
		if r.back == 0 || r.blocks > 0 && (c.advise&6 == 0 || r.blocks*n.fs.block > 1<<20) {
			return r, fmt.Errorf("invalid cluster back reference or block count")
		}
	} else if r.offset >= c.logical || r.physical >= n.fs.used/n.fs.block {
		return r, fmt.Errorf("invalid cluster offset or physical address")
	}
	return r, nil
}

func (n *inode) compressed(at uint64) ([]byte, error) {
	c, err := n.compression()
	if err != nil {
		return nil, err
	}
	head := at / c.logical
	r, err := n.index(c, head)
	if err != nil {
		return nil, err
	}
	if r.kind != 2 && at%c.logical < r.offset {
		if head == 0 {
			return nil, fmt.Errorf("missing initial cluster")
		}
		head--
		r, err = n.index(c, head)
		if err != nil {
			return nil, err
		}
	}
	for steps := 0; r.kind == 2; steps++ {
		if steps > 12<<20/int(c.logical) || r.back > head {
			return nil, fmt.Errorf("invalid or excessive cluster lookback")
		}
		head -= r.back
		r, err = n.index(c, head)
		if err != nil {
			return nil, err
		}
	}
	start := head*c.logical + r.offset
	end := n.size
	for next := head + 1; next < c.count; next++ {
		if (next-head)*c.logical > 12<<20 {
			return nil, fmt.Errorf("decoded physical cluster exceeds limit")
		}
		following, err := n.index(c, next)
		if err != nil {
			return nil, err
		}
		if following.kind != 2 {
			end = min(end, next*c.logical+following.offset)
			break
		}
	}
	if start > at || end <= at || end-start > 12<<20 {
		return nil, fmt.Errorf("invalid compressed extent range")
	}
	physical := c.logical
	if r.kind != 0 && c.advise&2 != 0 && head+1 < c.count {
		following, err := n.index(c, head+1)
		if err != nil {
			return nil, err
		}
		if following.kind == 2 {
			if following.blocks == 0 || following.back != 1 {
				return nil, fmt.Errorf("missing physical block count")
			}
			physical = following.blocks * n.fs.block
		}
	}
	if physical > 1<<20 || end-start > physical && r.kind == 0 {
		return nil, fmt.Errorf("invalid encoded cluster size")
	}
	b, err := n.fs.decoded.Get(bytecache.Key{Kind: 1, Source: n.nid, Offset: int64(start), Size: int64(physical), OriginalSize: int64(end - start)}, func() ([]byte, error) {
		encoded, err := n.fs.read(r.physical*n.fs.block, physical)
		if err != nil {
			return nil, err
		}
		length := int(end - start)
		if r.kind == 0 {
			if c.advise&16 == 0 {
				return encoded[:length], nil
			}
			rotation := int(start % n.fs.block)
			out := make([]byte, length)
			for i := range out {
				out[i] = encoded[(rotation+i)%len(encoded)]
			}
			return out, nil
		}
		if n.fs.incompat&1 != 0 {
			padding := 0
			for padding < len(encoded) && encoded[padding] == 0 {
				padding++
			}
			if padding >= int(n.fs.block) {
				return nil, fmt.Errorf("invalid LZ4 zero padding")
			}
			encoded = encoded[padding:]
		}
		return lz4Prefix(encoded, length)
	})
	if err != nil {
		return nil, err
	}
	return b[at-start:], nil
}

// lz4Prefix decodes a bounded prefix of a raw LZ4 block. EROFS may request a
// shorter logical tail than the block's original data; encoded padding is not
// an extra output stream. Back references must refer to bytes already decoded.
func lz4Prefix(input []byte, size int) ([]byte, error) {
	if size < 0 || size > 12<<20 {
		return nil, fmt.Errorf("invalid LZ4 output limit")
	}
	out := make([]byte, 0, size)
	at := 0
	length := func(base int) (int, error) {
		n := base
		if base == 15 {
			for {
				if at >= len(input) {
					return 0, fmt.Errorf("truncated LZ4 length")
				}
				v := int(input[at])
				at++
				n += v
				if n > 12<<20 {
					return 0, fmt.Errorf("oversized LZ4 sequence")
				}
				if v != 255 {
					break
				}
			}
		}
		return n, nil
	}
	for len(out) < size {
		if at >= len(input) {
			return nil, fmt.Errorf("truncated LZ4 token")
		}
		token := input[at]
		at++
		literal, err := length(int(token >> 4))
		if err != nil {
			return nil, err
		}
		if literal > len(input)-at {
			return nil, fmt.Errorf("truncated LZ4 literals")
		}
		take := min(literal, size-len(out))
		out = append(out, input[at:at+take]...)
		at += literal
		if len(out) == size {
			break
		}
		if len(input)-at < 2 {
			return nil, fmt.Errorf("truncated LZ4 match")
		}
		distance := int(le.Uint16(input[at:]))
		at += 2
		if distance == 0 || distance > len(out) {
			return nil, fmt.Errorf("invalid LZ4 match distance")
		}
		match, err := length(int(token & 15))
		if err != nil {
			return nil, err
		}
		match += 4
		match = min(match, size-len(out))
		for i := 0; i < match; i++ {
			out = append(out, out[len(out)-distance])
		}
	}
	return out, nil
}
