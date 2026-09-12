// Package arsenic decodes StuffIt method 15 fork payloads.
// Adapted from compcol's MIT-licensed Arsenic implementation, copyright
// 2026 Karpeles Lab Inc. See LICENSE. This Go implementation uses explicit
// output/block bounds and publishes bytes only after CRC validation.
package arsenic

import (
	"fmt"
	"hash/crc32"
)

type model struct {
	first, increment, limit, total int
	frequencies                    []int
}

func newModel(first, last, increment, limit int) *model {
	m := &model{first: first, increment: increment, limit: limit, total: (last - first + 1) * increment, frequencies: make([]int, last-first+1)}
	for i := range m.frequencies {
		m.frequencies[i] = increment
	}
	return m
}

type coder struct {
	input       []byte
	bit         int
	width, code int64
	err         error
}

func (c *coder) next() int64 {
	if c.bit >= len(c.input)*8 {
		c.err = fmt.Errorf("arsenic: truncated arithmetic stream")
		return 0
	}
	v := (c.input[c.bit/8] >> uint(7-c.bit%8)) & 1
	c.bit++
	return int64(v)
}
func (c *coder) symbol(m *model) int {
	if c.err != nil {
		return 0
	}
	unit := c.width / int64(m.total)
	if unit < 1 || c.code < 0 {
		c.err = fmt.Errorf("arsenic: invalid arithmetic interval")
		return 0
	}
	target := min(c.code/unit, int64(m.total-1))
	low, index := 0, 0
	for index < len(m.frequencies)-1 && target >= int64(low+m.frequencies[index]) {
		low += m.frequencies[index]
		index++
	}
	size := m.frequencies[index]
	c.code -= unit * int64(low)
	if low+size == m.total {
		c.width -= unit * int64(low)
	} else {
		c.width = unit * int64(size)
	}
	for c.width <= 1<<24 && c.err == nil {
		c.width *= 2
		c.code = c.code*2 + c.next()
	}
	m.frequencies[index] += m.increment
	m.total += m.increment
	if m.total > m.limit {
		m.total = 0
		for i, f := range m.frequencies {
			m.frequencies[i] = (f + 1) / 2
			m.total += m.frequencies[i]
		}
	}
	return m.first + index
}
func (c *coder) bits(m *model, n int) uint32 {
	var v uint32
	for i := 0; i < n && c.err == nil; i++ {
		v |= uint32(c.symbol(m)) << uint(i)
	}
	return v
}

// Decode validates one self-terminating stream. maximum limits logical
// output bytes; maximumBlock limits intermediate BWT bytes per block.
func Decode(input []byte, maximum, maximumBlock int) ([]byte, error) {
	if maximum < 0 || maximumBlock < 1 {
		return nil, fmt.Errorf("arsenic: invalid limits")
	}
	c := coder{input: input, width: 1 << 25}
	for i := 0; i < 26; i++ {
		c.code = c.code*2 + c.next()
	}
	initial := newModel(0, 1, 1, 256)
	sig1, sig2 := c.bits(initial, 8), c.bits(initial, 8)
	if c.err != nil {
		return nil, c.err
	}
	if sig1 != 'A' || sig2 != 's' {
		return nil, fmt.Errorf("arsenic: bad signature")
	}
	blockBits := int(c.bits(initial, 4)) + 9
	blockLimit := min(1<<blockBits, maximumBlock)
	var out []byte
	end := c.symbol(initial)
	for end == 0 && c.err == nil {
		randomized := c.symbol(initial) != 0
		primary := int(c.bits(initial, blockBits))
		selector := newModel(0, 10, 8, 1024)
		models := []*model{newModel(2, 3, 8, 1024), newModel(4, 7, 4, 1024), newModel(8, 15, 4, 1024), newModel(16, 31, 4, 1024), newModel(32, 63, 2, 1024), newModel(64, 127, 2, 1024), newModel(128, 255, 1, 1024)}
		var mtf [256]byte
		for i := range mtf {
			mtf[i] = byte(i)
		}
		var block []byte
		s := c.symbol(selector)
		for c.err == nil {
			if s < 2 {
				weight, count := 1, 0
				for s < 2 && c.err == nil {
					count += (s + 1) * weight
					if count > blockLimit-len(block) {
						return nil, fmt.Errorf("arsenic: zero run exceeds block limit")
					}
					weight *= 2
					s = c.symbol(selector)
				}
				for i := 0; i < count; i++ {
					block = append(block, mtf[0])
				}
			}
			if s == 10 {
				break
			}
			if c.err != nil {
				break
			}
			index := 1
			if s != 2 {
				if s < 3 || s > 9 {
					return nil, fmt.Errorf("arsenic: invalid selector")
				}
				index = c.symbol(models[s-3])
			}
			if len(block) >= blockLimit {
				return nil, fmt.Errorf("arsenic: block limit exceeded")
			}
			value := mtf[index]
			copy(mtf[1:index+1], mtf[:index])
			mtf[0] = value
			block = append(block, value)
			s = c.symbol(selector)
		}
		if c.err != nil {
			return nil, c.err
		}
		end = c.symbol(initial)
		var storedCRC uint32
		if end != 0 {
			storedCRC = c.bits(initial, 32)
		}
		if c.err != nil {
			return nil, c.err
		}
		if primary >= len(block) && (len(block) != 0 || primary != 0) {
			return nil, fmt.Errorf("arsenic: invalid BWT primary index")
		}
		var counts [256]int
		for _, v := range block {
			counts[v]++
		}
		total := 0
		for i, count := range counts {
			counts[i] = total
			total += count
		}
		transform := make([]int, len(block))
		for i, v := range block {
			transform[counts[v]] = i
			counts[v]++
		}
		index, randomIndex, nextRandom := primary, 0, randomTable[0]
		last, run := -1, 0
		for i := 0; i < len(block); i++ {
			index = transform[index]
			value := block[index]
			if randomized && i == nextRandom {
				value ^= 1
				randomIndex = (randomIndex + 1) % len(randomTable)
				nextRandom += randomTable[randomIndex]
			}
			if run == 4 {
				if int(value) > maximum-len(out) {
					return nil, fmt.Errorf("arsenic: decoded size limit")
				}
				for n := 0; n < int(value); n++ {
					out = append(out, byte(last))
				}
				run = 0
				continue
			}
			if len(out) >= maximum {
				return nil, fmt.Errorf("arsenic: decoded size limit")
			}
			out = append(out, value)
			if int(value) == last {
				run++
			} else {
				last = int(value)
				run = 1
			}
		}
		if run == 4 {
			return nil, fmt.Errorf("arsenic: missing final run length")
		}
		if end != 0 && crc32.ChecksumIEEE(out) != storedCRC {
			return nil, fmt.Errorf("arsenic: CRC mismatch")
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	return out, nil
}
