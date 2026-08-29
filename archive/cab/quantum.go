package cab

import "fmt"

const quantumFrameSize = 32768

type quantumBitReader struct {
	data []byte
	bit  int
}

func (r *quantumBitReader) read(count int) (uint32, error) {
	if count < 0 || count > 24 || count > len(r.data)*8-r.bit {
		return 0, fmt.Errorf("cab: truncated Quantum bitstream")
	}
	var value uint32
	for ; count > 0; count-- {
		value = value<<1 | uint32((r.data[r.bit/8]>>(7-(r.bit&7)))&1)
		r.bit++
	}
	return value, nil
}

func (r *quantumBitReader) alignByte() {
	r.bit = (r.bit + 7) &^ 7
}

type quantumSymbol struct {
	value      int
	cumulative uint32
}

type quantumModel struct {
	symbols    []quantumSymbol
	shiftsLeft int
}

func newQuantumModel(first, count int) quantumModel {
	symbols := make([]quantumSymbol, count+1)
	for index := range symbols {
		symbols[index] = quantumSymbol{value: first + index, cumulative: uint32(count - index)}
	}
	return quantumModel{symbols: symbols, shiftsLeft: 4}
}

func (m *quantumModel) update() {
	m.shiftsLeft--
	entries := len(m.symbols) - 1
	if m.shiftsLeft != 0 {
		for index := entries - 1; index >= 0; index-- {
			m.symbols[index].cumulative >>= 1
			if m.symbols[index].cumulative <= m.symbols[index+1].cumulative {
				m.symbols[index].cumulative = m.symbols[index+1].cumulative + 1
			}
		}
		return
	}

	m.shiftsLeft = 50
	for index := 0; index < entries; index++ {
		m.symbols[index].cumulative = (m.symbols[index].cumulative - m.symbols[index+1].cumulative + 1) >> 1
	}
	for left := 0; left < entries-1; left++ {
		for right := left + 1; right < entries; right++ {
			if m.symbols[left].cumulative < m.symbols[right].cumulative {
				m.symbols[left], m.symbols[right] = m.symbols[right], m.symbols[left]
			}
		}
	}
	for index := entries - 1; index >= 0; index-- {
		m.symbols[index].cumulative += m.symbols[index+1].cumulative
	}
}

type quantumDecoder struct {
	bits *quantumBitReader
	low  uint16
	high uint16
	code uint16
}

func (d *quantumDecoder) startFrame() error {
	value, err := d.bits.read(16)
	if err != nil {
		return err
	}
	d.low = 0
	d.high = 0xffff
	d.code = uint16(value)
	return nil
}

func (d *quantumDecoder) symbol(model *quantumModel) (int, error) {
	total := model.symbols[0].cumulative
	interval := uint32(d.high-d.low) + 1
	position := ((uint32(d.code-d.low+1)*total - 1) / interval) & 0xffff

	boundary := 1
	for boundary < len(model.symbols)-1 && model.symbols[boundary].cumulative > position {
		boundary++
	}
	selected := boundary - 1
	value := model.symbols[selected].value
	interval = uint32(d.high-d.low) + 1
	d.high = d.low + uint16((model.symbols[selected].cumulative*interval)/total-1)
	d.low += uint16((model.symbols[boundary].cumulative * interval) / total)

	for index := selected; index >= 0; index-- {
		model.symbols[index].cumulative += 8
	}
	if model.symbols[0].cumulative > 3800 {
		model.update()
	}

	for {
		if d.low&0x8000 != d.high&0x8000 {
			if d.low&0x4000 != 0 && d.high&0x4000 == 0 {
				d.code ^= 0x4000
				d.low &= 0x3fff
				d.high |= 0x4000
			} else {
				break
			}
		}
		bit, err := d.bits.read(1)
		if err != nil {
			return 0, err
		}
		d.low <<= 1
		d.high = d.high<<1 | 1
		d.code = d.code<<1 | uint16(bit)
	}
	return value, nil
}

func quantumCABPayload(blocks []dataBlock) ([]byte, int, error) {
	blocks, err := mergeSplitCABDataBlocks(blocks)
	if err != nil {
		return nil, 0, err
	}
	totalCompressed := len(blocks)
	totalOutput := 0
	for _, block := range blocks {
		totalCompressed += len(block.compressed)
		totalOutput += block.uncompressed
	}
	payload := make([]byte, 0, totalCompressed)
	for _, block := range blocks {
		payload = append(payload, block.compressed...)
		// A sentinel distinguishes the controller-injected boundary from the
		// format's optional zero padding after a complete 32 KiB frame.
		payload = append(payload, 0xff)
	}
	return payload, totalOutput, nil
}

func quantumDecompressCAB(blocks []dataBlock, windowBits int) ([]byte, error) {
	if windowBits < 10 || windowBits > 21 {
		return nil, fmt.Errorf("cab: invalid Quantum window size %d", windowBits)
	}
	input, expected, err := quantumCABPayload(blocks)
	if err != nil {
		return nil, err
	}
	reader := &quantumBitReader{data: input}
	decoder := quantumDecoder{bits: reader}

	models := []quantumModel{
		newQuantumModel(0, 64), newQuantumModel(64, 64),
		newQuantumModel(128, 64), newQuantumModel(192, 64),
		newQuantumModel(0, min(windowBits*2, 24)),
		newQuantumModel(0, min(windowBits*2, 36)),
		newQuantumModel(0, windowBits*2),
		newQuantumModel(0, 27),
		newQuantumModel(0, 7),
	}

	positionBase := make([]int, 42)
	positionExtra := make([]int, 42)
	for slot, base := 0, 0; slot < len(positionBase); slot++ {
		extra := 0
		if slot >= 2 {
			extra = (slot - 2) >> 1
		}
		positionBase[slot], positionExtra[slot] = base, extra
		base += 1 << extra
	}
	lengthBase := make([]int, 27)
	lengthExtra := make([]int, 27)
	for slot, base := 0, 0; slot < 26; slot++ {
		extra := 0
		if slot >= 2 {
			extra = (slot - 2) >> 2
		}
		lengthBase[slot], lengthExtra[slot] = base, extra
		base += 1 << extra
	}
	lengthBase[26] = 254

	output := make([]byte, 0, expected)
	windowSize := 1 << windowBits
	for len(output) < expected {
		if err := decoder.startFrame(); err != nil {
			return nil, err
		}
		frameOutput := min(quantumFrameSize, expected-len(output))
		frameEnd := len(output) + frameOutput
		for len(output) < frameEnd {
			selector, err := decoder.symbol(&models[8])
			if err != nil {
				return nil, err
			}
			if selector < 4 {
				literal, err := decoder.symbol(&models[selector])
				if err != nil {
					return nil, err
				}
				output = append(output, byte(literal))
				continue
			}

			matchLength := 0
			positionSlot := 0
			switch selector {
			case 4:
				matchLength = 3
				positionSlot, err = decoder.symbol(&models[4])
			case 5:
				matchLength = 4
				positionSlot, err = decoder.symbol(&models[5])
			case 6:
				var lengthSlot int
				lengthSlot, err = decoder.symbol(&models[7])
				if err == nil {
					var extra uint32
					extra, err = reader.read(lengthExtra[lengthSlot])
					matchLength = lengthBase[lengthSlot] + int(extra) + 5
				}
				if err == nil {
					positionSlot, err = decoder.symbol(&models[6])
				}
			default:
				err = fmt.Errorf("cab: invalid Quantum selector %d", selector)
			}
			if err != nil {
				return nil, err
			}
			extra, err := reader.read(positionExtra[positionSlot])
			if err != nil {
				return nil, err
			}
			offset := positionBase[positionSlot] + int(extra) + 1
			if offset > windowSize || offset > len(output) {
				return nil, fmt.Errorf("cab: invalid Quantum match offset %d at output %d", offset, len(output))
			}
			if len(output)+matchLength > frameEnd {
				return nil, fmt.Errorf("cab: Quantum match crosses frame boundary")
			}
			for count := 0; count < matchLength; count++ {
				output = append(output, output[len(output)-offset])
			}
		}

		if frameOutput == quantumFrameSize && len(output) < expected {
			reader.alignByte()
			for {
				marker, err := reader.read(8)
				if err != nil {
					return nil, err
				}
				if marker == 0xff {
					break
				}
				if marker != 0 {
					return nil, fmt.Errorf("cab: invalid Quantum frame padding 0x%02x", marker)
				}
			}
		}
	}
	return output, nil
}
