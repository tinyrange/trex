package sevenzip

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	lzmaRangeTop          = uint32(1 << 24)
	lzmaProbabilityBits   = 11
	lzmaProbabilityTotal  = uint16(1 << lzmaProbabilityBits)
	lzmaProbabilityMove   = 5
	lzmaStateCount        = 12
	lzmaLiteralStateCount = 7
	lzmaPositionStates    = 16
	lzmaLiteralTreeSize   = 0x300
	lzmaLengthLowBits     = 3
	lzmaLengthMidBits     = 3
	lzmaLengthHighBits    = 8
	lzmaLengthLowCount    = 1 << lzmaLengthLowBits
	lzmaLengthMidCount    = 1 << lzmaLengthMidBits
	lzmaLengthHighCount   = 1 << lzmaLengthHighBits
	lzmaDistanceStates    = 4
	lzmaDistanceSlotBits  = 6
	lzmaDistanceSlotCount = 1 << lzmaDistanceSlotBits
	lzmaDistanceModelEnd  = 14
	lzmaFullDistances     = 1 << (lzmaDistanceModelEnd / 2)
	lzmaAlignBits         = 4
	lzmaAlignCount        = 1 << lzmaAlignBits
)

// lzmaReader decodes a raw LZMA1 stream. It is intentionally local to the
// 7z implementation: the five-byte coder properties and exact output size
// come from the containing folder, rather than a host path or process.
type lzmaReader struct {
	input *bufio.Reader

	rangeValue uint32
	code       uint32

	lc      uint32
	lpMask  uint64
	posMask uint64

	dictionary     []byte
	dictionarySize uint64
	dictionaryPos  uint64
	dictionaryFull uint64

	outputSize uint64
	produced   uint64
	state      uint32
	reps       [4]uint32
	pending    uint32
	err        error

	isMatch     [lzmaStateCount][lzmaPositionStates]uint16
	isRep       [lzmaStateCount]uint16
	isRep0      [lzmaStateCount]uint16
	isRep1      [lzmaStateCount]uint16
	isRep2      [lzmaStateCount]uint16
	isRep0Long  [lzmaStateCount][lzmaPositionStates]uint16
	distSlot    [lzmaDistanceStates][lzmaDistanceSlotCount]uint16
	distSpecial [lzmaFullDistances - lzmaDistanceModelEnd]uint16
	distAlign   [lzmaAlignCount]uint16
	matchLength lzmaLengthDecoder
	repLength   lzmaLengthDecoder
	literals    []uint16
}

type lzmaLengthDecoder struct {
	choice  uint16
	choice2 uint16
	low     [lzmaPositionStates][lzmaLengthLowCount]uint16
	mid     [lzmaPositionStates][lzmaLengthMidCount]uint16
	high    [lzmaLengthHighCount]uint16
}

func newLZMAReader(input io.Reader, properties []byte, outputSize uint64, maximumDictionary uint64) (*lzmaReader, error) {
	if len(properties) != 5 {
		return nil, fmt.Errorf("lzma: property size is %d, want 5", len(properties))
	}
	encoded := uint32(properties[0])
	if encoded >= 9*5*5 {
		return nil, fmt.Errorf("lzma: invalid lc/lp/pb property %d", encoded)
	}
	lc := encoded % 9
	encoded /= 9
	lp := encoded % 5
	pb := encoded / 5
	if lc+lp > 4 {
		return nil, fmt.Errorf("lzma: unsupported literal context lc=%d lp=%d", lc, lp)
	}
	dictionarySize := uint64(binary.LittleEndian.Uint32(properties[1:5]))
	if dictionarySize == 0 {
		dictionarySize = 1
	}
	if maximumDictionary == 0 || dictionarySize > maximumDictionary {
		return nil, fmt.Errorf("lzma: dictionary size %d exceeds maximum %d", dictionarySize, maximumDictionary)
	}
	allocation := dictionarySize
	if outputSize < allocation {
		allocation = outputSize
	}
	if allocation == 0 {
		allocation = 1
	}
	if allocation > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("lzma: dictionary size %d cannot be allocated", allocation)
	}
	r := &lzmaReader{
		input:          bufio.NewReaderSize(input, 64<<10),
		rangeValue:     ^uint32(0),
		lc:             lc,
		lpMask:         uint64(1<<lp) - 1,
		posMask:        uint64(1<<pb) - 1,
		dictionary:     make([]byte, int(allocation)),
		dictionarySize: dictionarySize,
		outputSize:     outputSize,
		literals:       make([]uint16, (1<<(lc+lp))*lzmaLiteralTreeSize),
	}
	r.resetProbabilities()
	for i := 0; i < 5; i++ {
		value, err := r.input.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("lzma: truncated range-coder initialization: %w", err)
		}
		r.code = r.code<<8 | uint32(value)
	}
	return r, nil
}

func (r *lzmaReader) resetProbabilities() {
	initial := lzmaProbabilityTotal / 2
	r.matchLength.choice = initial
	r.matchLength.choice2 = initial
	r.repLength.choice = initial
	r.repLength.choice2 = initial
	for _, probabilities := range [][]uint16{
		r.isRep[:], r.isRep0[:], r.isRep1[:], r.isRep2[:],
		r.distSpecial[:], r.distAlign[:], r.matchLength.high[:],
		r.repLength.high[:], r.literals,
	} {
		for i := range probabilities {
			probabilities[i] = initial
		}
	}
	for i := range r.isMatch {
		for j := range r.isMatch[i] {
			r.isMatch[i][j] = initial
			r.isRep0Long[i][j] = initial
		}
	}
	for i := range r.distSlot {
		for j := range r.distSlot[i] {
			r.distSlot[i][j] = initial
		}
	}
	for i := range r.matchLength.low {
		for j := range r.matchLength.low[i] {
			r.matchLength.low[i][j] = initial
			r.matchLength.mid[i][j] = initial
			r.repLength.low[i][j] = initial
			r.repLength.mid[i][j] = initial
		}
	}
}

func (r *lzmaReader) normalize() error {
	if r.rangeValue >= lzmaRangeTop {
		return nil
	}
	value, err := r.input.ReadByte()
	if err != nil {
		return fmt.Errorf("lzma: truncated range-coded data: %w", err)
	}
	r.rangeValue <<= 8
	r.code = r.code<<8 | uint32(value)
	return nil
}

func (r *lzmaReader) bit(probability *uint16) (uint32, error) {
	if err := r.normalize(); err != nil {
		return 0, err
	}
	bound := (r.rangeValue >> lzmaProbabilityBits) * uint32(*probability)
	if r.code < bound {
		r.rangeValue = bound
		*probability += (lzmaProbabilityTotal - *probability) >> lzmaProbabilityMove
		return 0, nil
	}
	r.rangeValue -= bound
	r.code -= bound
	*probability -= *probability >> lzmaProbabilityMove
	return 1, nil
}

func (r *lzmaReader) bitTree(probabilities []uint16, bits uint32) (uint32, error) {
	symbol := uint32(1)
	for i := uint32(0); i < bits; i++ {
		bit, err := r.bit(&probabilities[symbol])
		if err != nil {
			return 0, err
		}
		symbol = symbol<<1 | bit
	}
	return symbol - (1 << bits), nil
}

func (r *lzmaReader) reverseBitTree(probabilities []uint16, bits uint32) (uint32, error) {
	symbol := uint32(1)
	var value uint32
	for i := uint32(0); i < bits; i++ {
		bit, err := r.bit(&probabilities[symbol-1])
		if err != nil {
			return 0, err
		}
		symbol = symbol<<1 | bit
		value |= bit << i
	}
	return value, nil
}

func (r *lzmaReader) directBits(bits uint32) (uint32, error) {
	var value uint32
	for i := uint32(0); i < bits; i++ {
		if err := r.normalize(); err != nil {
			return 0, err
		}
		r.rangeValue >>= 1
		var bit uint32
		if r.code >= r.rangeValue {
			r.code -= r.rangeValue
			bit = 1
		}
		value = value<<1 | bit
	}
	return value, nil
}

func (r *lzmaReader) dictionaryByte(distance uint32) (byte, error) {
	if uint64(distance) >= r.dictionaryFull || uint64(distance) >= r.dictionarySize {
		return 0, fmt.Errorf("lzma: invalid match distance %d after %d of %d output bytes", uint64(distance)+1, r.produced, r.outputSize)
	}
	index := (r.dictionaryPos + uint64(len(r.dictionary)) - uint64(distance) - 1) % uint64(len(r.dictionary))
	return r.dictionary[index], nil
}

func (r *lzmaReader) put(value byte) {
	r.dictionary[r.dictionaryPos] = value
	r.dictionaryPos++
	if r.dictionaryPos == uint64(len(r.dictionary)) {
		r.dictionaryPos = 0
	}
	if r.dictionaryFull < uint64(len(r.dictionary)) {
		r.dictionaryFull++
	}
	r.produced++
}

func lzmaLiteralState(state uint32) uint32 {
	if state <= 3 {
		return 0
	}
	if state <= 9 {
		return state - 3
	}
	return state - 6
}

func lzmaMatchState(state uint32) uint32 {
	if state < lzmaLiteralStateCount {
		return 7
	}
	return 10
}

func lzmaLongRepState(state uint32) uint32 {
	if state < lzmaLiteralStateCount {
		return 8
	}
	return 11
}

func lzmaShortRepState(state uint32) uint32 {
	if state < lzmaLiteralStateCount {
		return 9
	}
	return 11
}

func (r *lzmaReader) decodeLiteral() (byte, error) {
	var previous byte
	if r.produced != 0 {
		value, err := r.dictionaryByte(0)
		if err != nil {
			return 0, err
		}
		previous = value
	}
	context := ((r.produced & r.lpMask) << r.lc) | uint64(previous>>(8-r.lc))
	probabilities := r.literals[context*lzmaLiteralTreeSize : (context+1)*lzmaLiteralTreeSize]
	symbol := uint32(1)
	if r.state < lzmaLiteralStateCount {
		for symbol < 0x100 {
			bit, err := r.bit(&probabilities[symbol])
			if err != nil {
				return 0, err
			}
			symbol = symbol<<1 | bit
		}
	} else {
		matched, err := r.dictionaryByte(r.reps[0])
		if err != nil {
			return 0, err
		}
		matchByte := uint32(matched)
		for symbol < 0x100 {
			matchBit := (matchByte >> 7) & 1
			matchByte <<= 1
			index := ((1 + matchBit) << 8) + symbol
			bit, err := r.bit(&probabilities[index])
			if err != nil {
				return 0, err
			}
			symbol = symbol<<1 | bit
			if bit != matchBit {
				for symbol < 0x100 {
					bit, err = r.bit(&probabilities[symbol])
					if err != nil {
						return 0, err
					}
					symbol = symbol<<1 | bit
				}
				break
			}
		}
	}
	r.state = lzmaLiteralState(r.state)
	return byte(symbol), nil
}

func (r *lzmaReader) decodeLength(decoder *lzmaLengthDecoder, positionState uint32) (uint32, error) {
	bit, err := r.bit(&decoder.choice)
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		value, err := r.bitTree(decoder.low[positionState][:], lzmaLengthLowBits)
		return value + 2, err
	}
	bit, err = r.bit(&decoder.choice2)
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		value, err := r.bitTree(decoder.mid[positionState][:], lzmaLengthMidBits)
		return value + 2 + lzmaLengthLowCount, err
	}
	value, err := r.bitTree(decoder.high[:], lzmaLengthHighBits)
	return value + 2 + lzmaLengthLowCount + lzmaLengthMidCount, err
}

func (r *lzmaReader) decodeMatch(positionState uint32) error {
	r.state = lzmaMatchState(r.state)
	r.reps[3] = r.reps[2]
	r.reps[2] = r.reps[1]
	r.reps[1] = r.reps[0]
	length, err := r.decodeLength(&r.matchLength, positionState)
	if err != nil {
		return err
	}
	distanceState := length - 2
	if distanceState >= lzmaDistanceStates {
		distanceState = lzmaDistanceStates - 1
	}
	slot, err := r.bitTree(r.distSlot[distanceState][:], lzmaDistanceSlotBits)
	if err != nil {
		return err
	}
	if slot < 4 {
		r.reps[0] = slot
	} else {
		directCount := slot>>1 - 1
		base := uint32(2 | slot&1)
		if slot < lzmaDistanceModelEnd {
			base <<= directCount
			offset := base - slot
			extra, err := r.reverseBitTree(r.distSpecial[offset:], directCount)
			if err != nil {
				return err
			}
			r.reps[0] = base + extra
		} else {
			high, err := r.directBits(directCount - lzmaAlignBits)
			if err != nil {
				return err
			}
			low, err := r.reverseBitTree(r.distAlign[1:], lzmaAlignBits)
			if err != nil {
				return err
			}
			r.reps[0] = ((base<<(directCount-lzmaAlignBits))|high)<<lzmaAlignBits | low
		}
	}
	if r.reps[0] == ^uint32(0) {
		return fmt.Errorf("lzma: end marker before declared output size %d", r.outputSize)
	}
	r.pending = length
	return nil
}

func (r *lzmaReader) decodeRep(positionState uint32) error {
	bit, err := r.bit(&r.isRep0[r.state])
	if err != nil {
		return err
	}
	if bit == 0 {
		bit, err = r.bit(&r.isRep0Long[r.state][positionState])
		if err != nil {
			return err
		}
		if bit == 0 {
			r.state = lzmaShortRepState(r.state)
			r.pending = 1
			return nil
		}
	} else {
		var distance uint32
		bit, err = r.bit(&r.isRep1[r.state])
		if err != nil {
			return err
		}
		if bit == 0 {
			distance = r.reps[1]
		} else {
			bit, err = r.bit(&r.isRep2[r.state])
			if err != nil {
				return err
			}
			if bit == 0 {
				distance = r.reps[2]
			} else {
				distance = r.reps[3]
				r.reps[3] = r.reps[2]
			}
			r.reps[2] = r.reps[1]
		}
		r.reps[1] = r.reps[0]
		r.reps[0] = distance
	}
	r.state = lzmaLongRepState(r.state)
	length, err := r.decodeLength(&r.repLength, positionState)
	if err != nil {
		return err
	}
	r.pending = length
	return nil
}

func (r *lzmaReader) decodeSymbol() (byte, bool, error) {
	positionState := uint32(r.produced & r.posMask)
	bit, err := r.bit(&r.isMatch[r.state][positionState])
	if err != nil {
		return 0, false, err
	}
	if bit == 0 {
		value, err := r.decodeLiteral()
		return value, true, err
	}
	bit, err = r.bit(&r.isRep[r.state])
	if err != nil {
		return 0, false, err
	}
	if bit == 0 {
		err = r.decodeMatch(positionState)
	} else {
		err = r.decodeRep(positionState)
	}
	return 0, false, err
}

func (r *lzmaReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.produced == r.outputSize {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.produced < r.outputSize {
		if r.pending != 0 {
			value, err := r.dictionaryByte(r.reps[0])
			if err != nil {
				r.err = err
				return n, err
			}
			r.put(value)
			p[n] = value
			n++
			r.pending--
			continue
		}
		value, literal, err := r.decodeSymbol()
		if err != nil {
			r.err = err
			return n, err
		}
		if literal {
			r.put(value)
			p[n] = value
			n++
		}
	}
	if r.produced == r.outputSize {
		if r.pending != 0 {
			r.err = fmt.Errorf("lzma: match extends beyond declared output size %d", r.outputSize)
			return n, r.err
		}
		if n < len(p) {
			return n, io.EOF
		}
	}
	return n, nil
}
