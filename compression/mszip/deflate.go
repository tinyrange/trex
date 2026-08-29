package mszip

import "fmt"

const deflateMaxCodeBits = 15

type deflateBitReader struct {
	data   []byte
	byteAt int
	bits   uint64
	count  uint
}

func (r *deflateBitReader) read(count uint) (uint32, error) {
	if count > 32 {
		return 0, fmt.Errorf("deflate: invalid %d-bit field", count)
	}
	for r.count < count {
		if r.byteAt >= len(r.data) {
			return 0, fmt.Errorf("deflate: truncated input at byte %d", r.byteAt)
		}
		r.bits |= uint64(r.data[r.byteAt]) << r.count
		r.byteAt++
		r.count += 8
	}
	mask := uint64(1<<count) - 1
	value := uint32(r.bits & mask)
	r.bits >>= count
	r.count -= count
	return value, nil
}

func (r *deflateBitReader) alignByte() {
	r.bits = 0
	r.count = 0
}

type deflateCode struct {
	byLength [deflateMaxCodeBits + 1]map[uint32]int
	maximum  int
}

func newDeflateCode(lengths []uint8) (deflateCode, error) {
	var counts [deflateMaxCodeBits + 1]uint32
	maximum := 0
	for _, length := range lengths {
		if int(length) > deflateMaxCodeBits {
			return deflateCode{}, fmt.Errorf("deflate: code length %d exceeds %d", length, deflateMaxCodeBits)
		}
		if length != 0 {
			counts[length]++
			if int(length) > maximum {
				maximum = int(length)
			}
		}
	}
	if maximum == 0 {
		return deflateCode{}, fmt.Errorf("deflate: empty Huffman code")
	}
	left := int32(1)
	for length := 1; length <= deflateMaxCodeBits; length++ {
		left = left*2 - int32(counts[length])
		if left < 0 {
			return deflateCode{}, fmt.Errorf("deflate: oversubscribed Huffman code")
		}
	}
	var next [deflateMaxCodeBits + 1]uint32
	var code uint32
	for length := 1; length <= deflateMaxCodeBits; length++ {
		code = (code + counts[length-1]) << 1
		next[length] = code
	}
	output := deflateCode{maximum: maximum}
	for symbol, lengthValue := range lengths {
		length := int(lengthValue)
		if length == 0 {
			continue
		}
		if output.byLength[length] == nil {
			output.byLength[length] = make(map[uint32]int)
		}
		wire := next[length]
		if _, exists := output.byLength[length][wire]; exists {
			return deflateCode{}, fmt.Errorf("deflate: duplicate Huffman code")
		}
		output.byLength[length][wire] = symbol
		next[length]++
	}
	return output, nil
}

func (c deflateCode) decode(reader *deflateBitReader) (int, error) {
	var wire uint32
	for length := 1; length <= c.maximum; length++ {
		bit, err := reader.read(1)
		if err != nil {
			return 0, err
		}
		wire = wire<<1 | bit
		if symbols := c.byLength[length]; symbols != nil {
			if symbol, ok := symbols[wire]; ok {
				return symbol, nil
			}
		}
	}
	return 0, fmt.Errorf("deflate: invalid Huffman code at byte %d", reader.byteAt)
}

var deflateCodeLengthOrder = [...]int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

var deflateLengthBase = [...]int{
	3, 4, 5, 6, 7, 8, 9, 10,
	11, 13, 15, 17, 19, 23, 27, 31,
	35, 43, 51, 59, 67, 83, 99, 115,
	131, 163, 195, 227, 258,
}

var deflateLengthExtra = [...]uint{
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4,
	5, 5, 5, 5, 0,
}

var deflateDistanceBase = [...]int{
	1, 2, 3, 4, 5, 7, 9, 13,
	17, 25, 33, 49, 65, 97, 129, 193,
	257, 385, 513, 769, 1025, 1537, 2049, 3073,
	4097, 6145, 8193, 12289, 16385, 24577,
}

var deflateDistanceExtra = [...]uint{
	0, 0, 0, 0, 1, 1, 2, 2,
	3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10,
	11, 11, 12, 12, 13, 13,
}

func fixedDeflateCodes() (deflateCode, deflateCode, error) {
	literalLengths := make([]uint8, 288)
	for index := range literalLengths {
		switch {
		case index <= 143:
			literalLengths[index] = 8
		case index <= 255:
			literalLengths[index] = 9
		case index <= 279:
			literalLengths[index] = 7
		default:
			literalLengths[index] = 8
		}
	}
	distanceLengths := make([]uint8, 32)
	for index := range distanceLengths {
		distanceLengths[index] = 5
	}
	literals, err := newDeflateCode(literalLengths)
	if err != nil {
		return deflateCode{}, deflateCode{}, err
	}
	distances, err := newDeflateCode(distanceLengths)
	return literals, distances, err
}

func dynamicDeflateCodes(reader *deflateBitReader) (deflateCode, deflateCode, error) {
	hlit, err := reader.read(5)
	if err != nil {
		return deflateCode{}, deflateCode{}, err
	}
	hdist, err := reader.read(5)
	if err != nil {
		return deflateCode{}, deflateCode{}, err
	}
	hclen, err := reader.read(4)
	if err != nil {
		return deflateCode{}, deflateCode{}, err
	}
	literalCount := int(hlit) + 257
	distanceCount := int(hdist) + 1
	codeLengthCount := int(hclen) + 4
	codeLengths := make([]uint8, 19)
	for index := 0; index < codeLengthCount; index++ {
		length, err := reader.read(3)
		if err != nil {
			return deflateCode{}, deflateCode{}, err
		}
		codeLengths[deflateCodeLengthOrder[index]] = uint8(length)
	}
	codeLengthCode, err := newDeflateCode(codeLengths)
	if err != nil {
		return deflateCode{}, deflateCode{}, err
	}
	lengths := make([]uint8, 0, literalCount+distanceCount)
	for len(lengths) < cap(lengths) {
		symbol, err := codeLengthCode.decode(reader)
		if err != nil {
			return deflateCode{}, deflateCode{}, err
		}
		switch {
		case symbol <= 15:
			lengths = append(lengths, uint8(symbol))
		case symbol == 16:
			if len(lengths) == 0 {
				return deflateCode{}, deflateCode{}, fmt.Errorf("deflate: repeat code has no previous length")
			}
			extra, err := reader.read(2)
			if err != nil {
				return deflateCode{}, deflateCode{}, err
			}
			for count := int(extra) + 3; count > 0; count-- {
				lengths = append(lengths, lengths[len(lengths)-1])
			}
		case symbol == 17:
			extra, err := reader.read(3)
			if err != nil {
				return deflateCode{}, deflateCode{}, err
			}
			lengths = append(lengths, make([]uint8, int(extra)+3)...)
		case symbol == 18:
			extra, err := reader.read(7)
			if err != nil {
				return deflateCode{}, deflateCode{}, err
			}
			lengths = append(lengths, make([]uint8, int(extra)+11)...)
		default:
			return deflateCode{}, deflateCode{}, fmt.Errorf("deflate: invalid code-length symbol %d", symbol)
		}
		if len(lengths) > cap(lengths) {
			return deflateCode{}, deflateCode{}, fmt.Errorf("deflate: code-length run exceeds alphabet")
		}
	}
	literals, err := newDeflateCode(lengths[:literalCount])
	if err != nil {
		return deflateCode{}, deflateCode{}, err
	}
	if lengths[256] == 0 {
		return deflateCode{}, deflateCode{}, fmt.Errorf("deflate: literal code omits end-of-block")
	}
	distances, err := newDeflateCode(lengths[literalCount:])
	return literals, distances, err
}

func inflateCompressedBlock(reader *deflateBitReader, output *[]byte, history []byte, limit int, literals, distances deflateCode) error {
	for {
		symbol, err := literals.decode(reader)
		if err != nil {
			return err
		}
		if symbol < 256 {
			if len(*output) >= limit {
				return fmt.Errorf("deflate: output exceeds %d bytes", limit)
			}
			*output = append(*output, byte(symbol))
			continue
		}
		if symbol == 256 {
			return nil
		}
		lengthIndex := symbol - 257
		if lengthIndex < 0 || lengthIndex >= len(deflateLengthBase) {
			return fmt.Errorf("deflate: invalid length symbol %d", symbol)
		}
		length := deflateLengthBase[lengthIndex]
		extra, err := reader.read(deflateLengthExtra[lengthIndex])
		if err != nil {
			return err
		}
		length += int(extra)
		distanceSymbol, err := distances.decode(reader)
		if err != nil {
			return err
		}
		if distanceSymbol < 0 || distanceSymbol >= len(deflateDistanceBase) {
			return fmt.Errorf("deflate: invalid distance symbol %d", distanceSymbol)
		}
		distance := deflateDistanceBase[distanceSymbol]
		extra, err = reader.read(deflateDistanceExtra[distanceSymbol])
		if err != nil {
			return err
		}
		distance += int(extra)
		if distance > len(history)+len(*output) {
			return fmt.Errorf("deflate: distance %d exceeds %d bytes of history", distance, len(history)+len(*output))
		}
		if length > limit-len(*output) {
			return fmt.Errorf("deflate: match exceeds %d-byte output", limit)
		}
		for count := 0; count < length; count++ {
			source := len(*output) - distance
			if source >= 0 {
				*output = append(*output, (*output)[source])
			} else {
				*output = append(*output, history[len(history)+source])
			}
		}
	}
}

// Inflate decodes MSZIP deflate with compatibility for early encoders.
func Inflate(data, dictionary []byte, expected int) ([]byte, error) {
	if expected < 0 {
		return nil, fmt.Errorf("deflate: negative output size")
	}
	if len(dictionary) > 1<<15 {
		dictionary = dictionary[len(dictionary)-(1<<15):]
	}
	reader := &deflateBitReader{data: data}
	output := make([]byte, 0, expected)
	final := false
	for !final {
		finalBit, err := reader.read(1)
		if err != nil {
			return nil, err
		}
		final = finalBit != 0
		blockType, err := reader.read(2)
		if err != nil {
			return nil, err
		}
		switch blockType {
		case 0:
			reader.alignByte()
			length, err := reader.read(16)
			if err != nil {
				return nil, err
			}
			inverse, err := reader.read(16)
			if err != nil {
				return nil, err
			}
			if int(length) > expected-len(output) {
				return nil, fmt.Errorf("deflate: stored block exceeds %d-byte output", expected)
			}
			start := 0
			if uint16(length)^uint16(inverse) != 0xffff {
				// Some NT 3.x MSZIP streams omit NLEN and begin the stored
				// payload immediately after LEN. Restrict this compatibility
				// form to an exact enclosing CFDATA output boundary.
				if int(length) != expected-len(output) || length < 2 {
					return nil, fmt.Errorf("deflate: invalid stored-block length %#x/%#x at byte %d after %d output bytes", length, inverse, reader.byteAt, len(output))
				}
				output = append(output, byte(inverse), byte(inverse>>8))
				start = 2
			}
			for count := start; count < int(length); count++ {
				value, err := reader.read(8)
				if err != nil {
					return nil, err
				}
				output = append(output, byte(value))
			}
		case 1:
			literals, distances, err := fixedDeflateCodes()
			if err != nil {
				return nil, err
			}
			if err := inflateCompressedBlock(reader, &output, dictionary, expected, literals, distances); err != nil {
				return nil, fmt.Errorf("deflate: fixed block after %d output bytes: %w", len(output), err)
			}
		case 2:
			literals, distances, err := dynamicDeflateCodes(reader)
			if err != nil {
				return nil, err
			}
			if err := inflateCompressedBlock(reader, &output, dictionary, expected, literals, distances); err != nil {
				return nil, fmt.Errorf("deflate: dynamic block after %d output bytes: %w", len(output), err)
			}
		default:
			return nil, fmt.Errorf("deflate: reserved block type")
		}
		// Early MSZIP encoders can use the enclosing CFDATA byte count as the
		// stream delimiter and leave BFINAL clear after a complete block. The
		// caller supplies that authenticated output size, so accept only an
		// exact boundary rather than interpreting padding as another block.
		if len(output) == expected {
			return output, nil
		}
	}
	if len(output) != expected {
		return nil, fmt.Errorf("deflate: decoded %d bytes, want %d", len(output), expected)
	}
	return output, nil
}
