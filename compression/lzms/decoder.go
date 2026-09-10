package lzms

import "fmt"

const maximumOutputSize = int64(1<<31 - 2)

var (
	positionSlots, positionSlotsError = generateSlotTable(positionSlotRuns[:], 0x7fffffff)
	lengthSlots, lengthSlotsError     = generateSlotTable(lengthSlotRuns[:], 0x400108ab)
)

type decoder struct {
	rangeStream    *rangeDecoder
	backwardStream *backwardBitReader

	literalMatch *contextModel
	matchType    *contextModel
	lzMode       *contextModel
	lzRepeat     [2]*contextModel
	deltaMode    *contextModel
	deltaRepeat  [2]*contextModel

	literals     *adaptiveHuffman
	lzOffsets    *adaptiveHuffman
	deltaOffsets *adaptiveHuffman
	lengths      *adaptiveHuffman
	deltaPowers  *adaptiveHuffman

	recentLZ    recentOffsets
	recentDelta recentDeltaPairs
	output      []byte
	want        int
}

// Decompress expands one raw LZMS block to exactly outputSize bytes and then
// applies the mandatory LZMS x86 address restoration transform.
func Decompress(data []byte, outputSize int) ([]byte, error) {
	output, err := decompressIntermediate(data, outputSize)
	if err != nil {
		return nil, err
	}
	restoreX86Addresses(output)
	return output, nil
}

func decompressIntermediate(data []byte, outputSize int) ([]byte, error) {
	if outputSize < 0 || int64(outputSize) > maximumOutputSize {
		return nil, fmt.Errorf("lzms: invalid output size %d", outputSize)
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("lzms: compressed block has %d bytes, need at least 4", len(data))
	}
	if len(data)&1 != 0 {
		return nil, fmt.Errorf("lzms: odd compressed size %d", len(data))
	}
	if positionSlotsError != nil {
		return nil, positionSlotsError
	}
	if lengthSlotsError != nil {
		return nil, lengthSlotsError
	}
	if outputSize == 0 {
		return []byte{}, nil
	}
	positionSymbols, err := positionSlots.symbolsForOutputSize(outputSize)
	if err != nil {
		return nil, err
	}
	d, err := newDecoder(data, outputSize, positionSymbols)
	if err != nil {
		return nil, err
	}
	if err := d.decodeItems(); err != nil {
		return nil, err
	}
	return d.output, nil
}

func newDecoder(data []byte, outputSize, positionSymbols int) (*decoder, error) {
	rangeStream, err := newRangeDecoder(data)
	if err != nil {
		return nil, err
	}
	backwardStream, err := newBackwardBitReader(data)
	if err != nil {
		return nil, err
	}
	context := func(width uint) (*contextModel, error) { return newContextModel(width) }
	literalMatch, err := context(4)
	if err != nil {
		return nil, err
	}
	matchType, err := context(5)
	if err != nil {
		return nil, err
	}
	lzMode, err := context(6)
	if err != nil {
		return nil, err
	}
	lzRepeat0, err := context(6)
	if err != nil {
		return nil, err
	}
	lzRepeat1, err := context(6)
	if err != nil {
		return nil, err
	}
	deltaMode, err := context(6)
	if err != nil {
		return nil, err
	}
	deltaRepeat0, err := context(6)
	if err != nil {
		return nil, err
	}
	deltaRepeat1, err := context(6)
	if err != nil {
		return nil, err
	}
	literals, err := newAdaptiveHuffman(256, 1024)
	if err != nil {
		return nil, err
	}
	lzOffsets, err := newAdaptiveHuffman(positionSymbols, 1024)
	if err != nil {
		return nil, err
	}
	deltaOffsets, err := newAdaptiveHuffman(positionSymbols, 1024)
	if err != nil {
		return nil, err
	}
	lengths, err := newAdaptiveHuffman(54, 512)
	if err != nil {
		return nil, err
	}
	deltaPowers, err := newAdaptiveHuffman(8, 512)
	if err != nil {
		return nil, err
	}
	return &decoder{
		rangeStream: rangeStream, backwardStream: backwardStream,
		literalMatch: literalMatch, matchType: matchType,
		lzMode: lzMode, lzRepeat: [2]*contextModel{lzRepeat0, lzRepeat1},
		deltaMode: deltaMode, deltaRepeat: [2]*contextModel{deltaRepeat0, deltaRepeat1},
		literals: literals, lzOffsets: lzOffsets, deltaOffsets: deltaOffsets,
		lengths: lengths, deltaPowers: deltaPowers,
		recentLZ: newRecentOffsets(), recentDelta: newRecentDeltaPairs(),
		output: make([]byte, 0, outputSize), want: outputSize,
	}, nil
}

func (d *decoder) decodeItems() error {
	for len(d.output) < d.want {
		d.recentLZ.beginItem()
		d.recentDelta.beginItem()
		isMatch, err := d.literalMatch.decode(d.rangeStream)
		if err != nil {
			return err
		}
		if isMatch == 0 {
			symbol, err := d.literals.decode(d.backwardStream)
			if err != nil {
				return err
			}
			d.output = append(d.output, byte(symbol))
		} else {
			isDelta, err := d.matchType.decode(d.rangeStream)
			if err != nil {
				return err
			}
			if isDelta == 0 {
				if err := d.decodeLZMatch(); err != nil {
					return err
				}
			} else if err := d.decodeDeltaMatch(); err != nil {
				return err
			}
		}
		d.recentLZ.endItem()
		d.recentDelta.endItem()
	}
	return nil
}

func (d *decoder) decodeLZMatch() error {
	repeat, err := d.lzMode.decode(d.rangeStream)
	if err != nil {
		return err
	}
	var offset uint32
	if repeat == 0 {
		symbol, err := d.lzOffsets.decode(d.backwardStream)
		if err != nil {
			return err
		}
		offset, err = positionSlots.decode(symbol, d.backwardStream)
		if err != nil {
			return err
		}
		d.recentLZ.explicit(offset)
	} else {
		index, err := d.decodeRepeatIndex(d.lzRepeat)
		if err != nil {
			return err
		}
		offset, err = d.recentLZ.repeat(index)
		if err != nil {
			return err
		}
	}
	length, err := d.decodeLength()
	if err != nil {
		return err
	}
	return d.copyLZ(offset, length)
}

func (d *decoder) decodeDeltaMatch() error {
	repeat, err := d.deltaMode.decode(d.rangeStream)
	if err != nil {
		return err
	}
	var pair deltaPair
	if repeat == 0 {
		power, err := d.deltaPowers.decode(d.backwardStream)
		if err != nil {
			return err
		}
		symbol, err := d.deltaOffsets.decode(d.backwardStream)
		if err != nil {
			return err
		}
		rawOffset, err := positionSlots.decode(symbol, d.backwardStream)
		if err != nil {
			return err
		}
		pair = deltaPair{power: uint8(power), rawOffset: rawOffset}
		d.recentDelta.explicit(pair)
	} else {
		index, err := d.decodeRepeatIndex(d.deltaRepeat)
		if err != nil {
			return err
		}
		pair, err = d.recentDelta.repeat(index)
		if err != nil {
			return err
		}
	}
	length, err := d.decodeLength()
	if err != nil {
		return err
	}
	return d.copyDelta(pair, length)
}

func (d *decoder) decodeRepeatIndex(models [2]*contextModel) (int, error) {
	continueBit, err := models[0].decode(d.rangeStream)
	if err != nil || continueBit == 0 {
		return 0, err
	}
	lastBit, err := models[1].decode(d.rangeStream)
	if err != nil {
		return 0, err
	}
	return int(lastBit) + 1, nil
}

func (d *decoder) decodeLength() (uint32, error) {
	symbol, err := d.lengths.decode(d.backwardStream)
	if err != nil {
		return 0, err
	}
	return lengthSlots.decode(symbol, d.backwardStream)
}

func (d *decoder) copyLZ(offset, length uint32) error {
	position := uint32(len(d.output))
	if offset == 0 || offset > position {
		return fmt.Errorf("lzms: match offset %d exceeds output position %d", offset, position)
	}
	if uint64(length) > uint64(d.want-len(d.output)) {
		return fmt.Errorf("lzms: match length %d exceeds remaining output %d", length, d.want-len(d.output))
	}
	source := len(d.output) - int(offset)
	remaining := int(length)
	for remaining > 0 {
		count := len(d.output) - source
		if count > remaining {
			count = remaining
		}
		d.output = append(d.output, d.output[source:source+count]...)
		remaining -= count
	}
	return nil
}

func (d *decoder) copyDelta(pair deltaPair, length uint32) error {
	a := uint64(1) << pair.power
	b := uint64(pair.rawOffset) << pair.power
	distance := a + b
	position := uint64(len(d.output))
	if pair.rawOffset == 0 || distance > position {
		return fmt.Errorf("lzms: delta distance %d exceeds output position %d", distance, position)
	}
	if uint64(length) > uint64(d.want-len(d.output)) {
		return fmt.Errorf("lzms: delta length %d exceeds remaining output %d", length, d.want-len(d.output))
	}
	for range length {
		q := uint64(len(d.output))
		value := int(d.output[q-a]) + int(d.output[q-b]) - int(d.output[q-distance])
		d.output = append(d.output, byte(value))
	}
	return nil
}
