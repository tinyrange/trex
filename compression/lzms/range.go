package lzms

import (
	"encoding/binary"
	"fmt"
)

const initialProbabilityHistory = uint64(0x0000000055555555)

type rangeDecoder struct {
	data       []byte
	next       int
	rangeValue uint32
	code       uint32
}

func newRangeDecoder(data []byte) (*rangeDecoder, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("lzms: compressed block has %d bytes, need at least 4", len(data))
	}
	if len(data)&1 != 0 {
		return nil, fmt.Errorf("lzms: odd compressed size %d", len(data))
	}
	return &rangeDecoder{
		data:       data,
		next:       4,
		rangeValue: ^uint32(0),
		code: uint32(binary.LittleEndian.Uint16(data[0:2]))<<16 |
			uint32(binary.LittleEndian.Uint16(data[2:4])),
	}, nil
}

func (r *rangeDecoder) decodeBit(probability uint8) (uint8, error) {
	if r.rangeValue <= 0xffff {
		if r.next+2 > len(r.data) {
			return 0, fmt.Errorf("lzms: truncated forward range stream")
		}
		r.rangeValue <<= 16
		r.code = r.code<<16 | uint32(binary.LittleEndian.Uint16(r.data[r.next:r.next+2]))
		r.next += 2
	}
	p := uint32(probability)
	if p == 0 {
		p = 1
	} else if p >= 64 {
		p = 63
	}
	bound := (r.rangeValue >> 6) * p
	if r.code < bound {
		r.rangeValue = bound
		return 0, nil
	}
	r.code -= bound
	r.rangeValue -= bound
	return 1, nil
}

type probabilityEntry struct {
	history uint64
	zeros   uint8
}

func newProbabilityEntry() probabilityEntry {
	return probabilityEntry{history: initialProbabilityHistory, zeros: 48}
}

func (p *probabilityEntry) observe(bit uint8) {
	oldest := uint8(p.history >> 63)
	p.history = p.history<<1 | uint64(bit&1)
	if oldest == 0 {
		p.zeros--
	}
	if bit&1 == 0 {
		p.zeros++
	}
}

type contextModel struct {
	width   uint
	state   uint8
	entries []probabilityEntry
}

func newContextModel(width uint) (*contextModel, error) {
	if width == 0 || width > 6 {
		return nil, fmt.Errorf("lzms: invalid context width %d", width)
	}
	model := &contextModel{width: width, entries: make([]probabilityEntry, 1<<width)}
	for index := range model.entries {
		model.entries[index] = newProbabilityEntry()
	}
	return model, nil
}

func (m *contextModel) decode(r *rangeDecoder) (uint8, error) {
	entry := &m.entries[m.state]
	bit, err := r.decodeBit(entry.zeros)
	if err != nil {
		return 0, err
	}
	entry.observe(bit)
	m.state = ((m.state << 1) | bit) & uint8((1<<m.width)-1)
	return bit, nil
}
