package lzms

import "fmt"

type recentOffsets struct {
	queue   [4]uint32
	pending uint32
	current uint32
}

func newRecentOffsets() recentOffsets {
	return recentOffsets{queue: [4]uint32{1, 2, 3, 4}}
}

func (r *recentOffsets) beginItem() { r.current = 0 }

func (r *recentOffsets) explicit(value uint32) { r.current = value }

func (r *recentOffsets) repeat(index int) (uint32, error) {
	if index < 0 || index >= 3 {
		return 0, fmt.Errorf("lzms: recent offset index %d", index)
	}
	value := r.queue[index]
	copy(r.queue[index:], r.queue[index+1:])
	r.queue[3] = 0
	r.current = value
	return value, nil
}

func (r *recentOffsets) endItem() {
	if r.pending != 0 {
		copy(r.queue[1:], r.queue[:3])
		r.queue[0] = r.pending
	}
	r.pending = r.current
}

type deltaPair struct {
	power     uint8
	rawOffset uint32
}

type recentDeltaPairs struct {
	queue   [4]deltaPair
	pending deltaPair
	current deltaPair
}

func newRecentDeltaPairs() recentDeltaPairs {
	return recentDeltaPairs{queue: [4]deltaPair{{0, 1}, {0, 2}, {0, 3}, {0, 4}}}
}

func (r *recentDeltaPairs) beginItem() { r.current = deltaPair{} }

func (r *recentDeltaPairs) explicit(value deltaPair) { r.current = value }

func (r *recentDeltaPairs) repeat(index int) (deltaPair, error) {
	if index < 0 || index >= 3 {
		return deltaPair{}, fmt.Errorf("lzms: recent delta index %d", index)
	}
	value := r.queue[index]
	copy(r.queue[index:], r.queue[index+1:])
	r.queue[3] = deltaPair{}
	r.current = value
	return value, nil
}

func (r *recentDeltaPairs) endItem() {
	if r.pending.rawOffset != 0 {
		copy(r.queue[1:], r.queue[:3])
		r.queue[0] = r.pending
	}
	r.pending = r.current
}
