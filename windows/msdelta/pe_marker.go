package msdelta

// PE transforms use two ownership bits per source byte. Store 32 source bytes
// per word instead of retaining another full-sized buffer beside every source
// and target image. Range updates preserve the independent ownership bit.
type peMarker struct {
	words []uint64
	size  int
}

func newPEMarker(size int) peMarker {
	words := size / 32
	if size%32 != 0 {
		words++
	}
	return peMarker{words: make([]uint64, words), size: size}
}
func (m peMarker) get(index int) byte {
	return byte(m.words[index/32]>>(uint(index%32)*2)) & 3
}
func (m peMarker) set(index int, value byte) {
	shift := uint(index%32) * 2
	m.words[index/32] = m.words[index/32]&^(uint64(3)<<shift) | uint64(value&3)<<shift
}

// update applies (old &^ clearBits) | setBits in the clipped half-open range.
func (m peMarker) update(start, end int, setBits, clearBits byte) {
	start = max(0, start)
	end = min(m.size, end)
	if start >= end {
		return
	}
	const alternating = uint64(0x5555555555555555)
	setWord := uint64(setBits&3) * alternating
	clearWord := uint64(clearBits&3) * alternating
	first, last := start/32, (end-1)/32
	firstMask := ^uint64(0) << (uint(start%32) * 2)
	lastMask := ^uint64(0)
	if end%32 != 0 {
		lastMask = (uint64(1) << (uint(end%32) * 2)) - 1
	}
	if first == last {
		mask := firstMask & lastMask
		m.words[first] = m.words[first]&^(clearWord&mask) | setWord&mask
		return
	}
	m.words[first] = m.words[first]&^(clearWord&firstMask) | setWord&firstMask
	for i := first + 1; i < last; i++ {
		m.words[i] = m.words[i]&^clearWord | setWord
	}
	m.words[last] = m.words[last]&^(clearWord&lastMask) | setWord&lastMask
}
