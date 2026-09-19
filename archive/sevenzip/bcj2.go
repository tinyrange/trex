package sevenzip

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// BCJ2 restores x86 branch operands from main, call, jump and range-coded
// decision streams. Format reference: Igor Pavlov's public-domain Bcj2.c,
// https://github.com/ip7z/7zip/blob/main/C/Bcj2.c . All streams stay bounded
// readers; neither the folder nor any intermediate is materialized.
type bcj2Reader struct {
	input                  [4]*bufio.Reader
	remaining              [4]uint64
	left, position         uint64
	code, rangeValue       uint32
	probs                  [258]uint32
	previous               byte
	pending                [4]byte
	pendingPos, pendingEnd int
	err                    error
	done                   bool
}

func newBCJ2Reader(inputs []io.Reader, sizes []uint64, size uint64) (*bcj2Reader, error) {
	if len(inputs) != 4 || len(sizes) != 4 || sizes[1]%4 != 0 || sizes[2]%4 != 0 || sizes[3] < 5 {
		return nil, fmt.Errorf("bcj2: invalid input sizes")
	}
	left := size
	for _, n := range sizes[:3] {
		if n > left {
			return nil, fmt.Errorf("bcj2: stream sizes exceed output")
		}
		left -= n
	}
	if left != 0 {
		return nil, fmt.Errorf("bcj2: stream sizes do not match output")
	}
	r := &bcj2Reader{left: size, rangeValue: ^uint32(0)}
	for i := range r.input {
		r.input[i] = bufio.NewReader(inputs[i])
		r.remaining[i] = sizes[i]
	}
	for i := range r.probs {
		r.probs[i] = 1024
	}
	for i := 0; i < 5; i++ {
		b, err := r.byte(3)
		if err != nil {
			return nil, err
		}
		if i == 0 && b != 0 {
			return nil, fmt.Errorf("bcj2: invalid range prefix")
		}
		r.code = r.code<<8 | uint32(b)
	}
	if r.code == ^uint32(0) {
		return nil, fmt.Errorf("bcj2: invalid range code")
	}
	return r, nil
}

func (r *bcj2Reader) byte(stream int) (byte, error) {
	if r.remaining[stream] == 0 {
		return 0, fmt.Errorf("bcj2: truncated stream %d", stream)
	}
	b, err := r.input[stream].ReadByte()
	if err != nil {
		return 0, fmt.Errorf("bcj2: stream %d: %w", stream, err)
	}
	r.remaining[stream]--
	return b, nil
}

func (r *bcj2Reader) normalize() error {
	if r.rangeValue < 1<<24 {
		b, err := r.byte(3)
		if err != nil {
			return err
		}
		r.rangeValue <<= 8
		r.code = r.code<<8 | uint32(b)
	}
	return nil
}

func (r *bcj2Reader) next() (byte, error) {
	if r.pendingPos < r.pendingEnd {
		b := r.pending[r.pendingPos]
		r.pendingPos++
		r.previous = b
		return b, nil
	}
	if err := r.normalize(); err != nil {
		return 0, err
	}
	b, err := r.byte(0)
	if err != nil {
		return 0, err
	}
	previous := r.previous
	r.previous = b
	if b != 0xe8 && b != 0xe9 && !(previous == 0x0f && b&0xf0 == 0x80) {
		return b, nil
	}
	index := 0
	if b == 0xe8 {
		index = int(previous) + 2
	} else if b == 0xe9 {
		index = 1
	}
	p := r.probs[index]
	bound := (r.rangeValue >> 11) * p
	if r.code < bound {
		r.rangeValue = bound
		r.probs[index] += (2048 - p) >> 5
		return b, nil
	}
	r.rangeValue -= bound
	r.code -= bound
	r.probs[index] -= p >> 5
	if r.left < 5 {
		return 0, fmt.Errorf("bcj2: branch exceeds output")
	}
	stream := 2
	if b == 0xe8 {
		stream = 1
	}
	var absolute uint32
	for i := 0; i < 4; i++ {
		v, err := r.byte(stream)
		if err != nil {
			return 0, err
		}
		absolute = absolute<<8 | uint32(v)
	}
	binary.LittleEndian.PutUint32(r.pending[:], absolute-uint32(r.position+5))
	r.pendingPos, r.pendingEnd = 0, 4
	return b, nil
}

func (r *bcj2Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.done {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.left > 0 {
		b, err := r.next()
		if err != nil {
			r.err = err
			return n, err
		}
		p[n] = b
		n++
		r.position++
		r.left--
	}
	if r.left == 0 {
		if err := r.normalize(); err != nil {
			r.err = err
			return n, err
		}
		if r.remaining != [4]uint64{} || r.code != 0 {
			r.err = fmt.Errorf("bcj2: trailing stream data or unfinished range code")
			return n, r.err
		}
		r.done = true
	}
	return n, nil
}
