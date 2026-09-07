package sevenzip

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// LZMA2 chunk framing follows Lasse Collin's format description:
// https://sourceforge.net/p/sevenzip/discussion/45797/thread/09814bb2/
// The range decoder and dictionary are the native LZMA implementation here.
type lzma2Reader struct {
	input                          *bufio.Reader
	model                          *lzmaReader
	size, produced                 uint64
	chunk                          []byte
	needDictionary, needProperties bool
	done                           bool
	err                            error
}

func newLZMA2Reader(input io.Reader, properties []byte, size, maximumDictionary uint64) (*lzma2Reader, error) {
	if len(properties) != 1 || properties[0] > 40 {
		return nil, fmt.Errorf("lzma2: invalid dictionary properties %x", properties)
	}
	p := properties[0]
	dictionary := uint64(0xffffffff)
	if p < 40 {
		dictionary = uint64(2|(p&1)) << (p/2 + 11)
	}
	if dictionary > maximumDictionary {
		return nil, fmt.Errorf("lzma2: dictionary %d exceeds maximum %d", dictionary, maximumDictionary)
	}
	props := []byte{0x5d, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(props[1:], uint32(dictionary))
	model, err := newLZMAReader(bytes.NewReader(make([]byte, 5)), props, size, maximumDictionary)
	if err != nil {
		return nil, err
	}
	return &lzma2Reader{input: bufio.NewReader(input), model: model, size: size, needDictionary: true, needProperties: true}, nil
}

func (r *lzma2Reader) readSize() (uint64, error) {
	var b [2]byte
	_, err := io.ReadFull(r.input, b[:])
	return uint64(binary.BigEndian.Uint16(b[:])) + 1, err
}

func (r *lzma2Reader) next() error {
	control, err := r.input.ReadByte()
	if err != nil {
		return fmt.Errorf("lzma2: missing chunk control: %w", err)
	}
	if control == 0 {
		if r.produced != r.size {
			return fmt.Errorf("lzma2: ended at %d bytes, want %d", r.produced, r.size)
		}
		r.done = true
		return nil
	}
	if control != 1 && control != 2 && control < 0x80 {
		return fmt.Errorf("lzma2: invalid control %#x", control)
	}
	m := r.model
	if control == 1 || control >= 0xe0 {
		m.dictionaryPos, m.dictionaryFull, m.produced = 0, 0, 0
		r.needDictionary = false
		r.needProperties = true
	}
	if r.needDictionary {
		return fmt.Errorf("lzma2: first chunk must reset dictionary")
	}
	unpacked, err := r.readSize()
	if err != nil {
		return fmt.Errorf("lzma2: truncated chunk size: %w", err)
	}
	if control >= 0x80 {
		unpacked += uint64(control&0x1f) << 16
	}
	if unpacked > r.size-r.produced {
		return fmt.Errorf("lzma2: chunk exceeds declared output size")
	}
	r.chunk = make([]byte, int(unpacked))
	if control < 0x80 {
		// Plain chunks update the dictionary, not the probability/state model.
		// A later compressed control byte decides which model state to reset.
		if _, err := io.ReadFull(r.input, r.chunk); err != nil {
			return fmt.Errorf("lzma2: truncated plain chunk: %w", err)
		}
		for _, b := range r.chunk {
			m.put(b)
		}
	} else {
		packed, err := r.readSize()
		if err != nil {
			return fmt.Errorf("lzma2: truncated packed size: %w", err)
		}
		if control >= 0xc0 {
			property, err := r.input.ReadByte()
			if err != nil {
				return fmt.Errorf("lzma2: missing LZMA properties: %w", err)
			}
			lc, lp, pb := uint32(property)%9, uint32(property)/9%5, uint32(property)/45
			if property >= 225 || lc+lp > 4 {
				return fmt.Errorf("lzma2: invalid LZMA properties %#x", property)
			}
			m.lc, m.lpMask, m.posMask = lc, uint64(1<<lp)-1, uint64(1<<pb)-1
			m.literals = make([]uint16, (1<<(lc+lp))*lzmaLiteralTreeSize)
			r.needProperties = false
		}
		if r.needProperties {
			return fmt.Errorf("lzma2: compressed chunk needs properties")
		}
		if control >= 0xa0 {
			m.state, m.pending, m.reps = 0, 0, [4]uint32{}
			m.resetProbabilities()
		}
		data := make([]byte, int(packed))
		if _, err := io.ReadFull(r.input, data); err != nil {
			return fmt.Errorf("lzma2: truncated compressed chunk: %w", err)
		}
		if len(data) < 5 || data[0] != 0 {
			return fmt.Errorf("lzma2: invalid range initialization")
		}
		compressed := bytes.NewReader(data[5:])
		m.input = bufio.NewReader(compressed)
		m.rangeValue, m.code = ^uint32(0), binary.BigEndian.Uint32(data[1:5])
		m.outputSize, m.err = m.produced+unpacked, nil
		if _, err := io.ReadFull(m, r.chunk); err != nil {
			return fmt.Errorf("lzma2: decode chunk: %w", err)
		}
		if err := m.normalize(); err != nil {
			return err
		}
		if m.pending != 0 || m.code != 0 || compressed.Len()+m.input.Buffered() != 0 {
			return fmt.Errorf("lzma2: compressed chunk does not end at declared boundary")
		}
	}
	r.produced += unpacked
	if r.produced == r.size {
		end, err := r.input.ReadByte()
		if err != nil || end != 0 {
			return fmt.Errorf("lzma2: missing end marker after declared output")
		}
		r.done = true
	}
	return nil
}

func (r *lzma2Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if len(r.chunk) == 0 && !r.done {
		if err := r.next(); err != nil {
			r.err = err
			return 0, err
		}
	}
	if len(r.chunk) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunk)
	r.chunk = r.chunk[n:]
	return n, nil
}
