package ibmiimd

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Packed is the observed LIC framed bitstream. Expanded bytes are exposed lazily;
// neither relocation nor execution is performed. The grammar was recovered from
// a0b00700 at file offsets 0x29a4 (frame) and 0x2bcc (bit advance).
type Packed struct {
	StoredBytes   uint32         `json:"stored_bytes"`
	ExpandedBytes uint32         `json:"expanded_bytes"`
	Frames        []Frame        `json:"frames"`
	Data          storage.Reader `json:"-"`
}
type Frame struct {
	Offset       int64  `json:"offset"`
	Stored       uint32 `json:"stored_bytes"`
	Expanded     uint32 `json:"expanded_bytes"`
	OutputOffset int64  `json:"output_offset"`
}

// OpenPacked validates all framing and budgets before exposing any output.
func OpenPacked(source storage.Reader, maximumFrames int, maximumBytes int64) (*Packed, error) {
	var h [16]byte
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	p := &Packed{StoredBytes: be.Uint32(h[:]), ExpandedBytes: be.Uint32(h[4:])}
	count := be.Uint32(h[8:])
	if maximumFrames < 1 || maximumBytes < 0 || count == 0 || uint64(count) > uint64(maximumFrames) || p.StoredBytes < 32 || int64(p.StoredBytes) > source.Size() || p.ExpandedBytes == 0 || int64(p.ExpandedBytes) > maximumBytes || be.Uint32(h[12:]) != 0 {
		return nil, fmt.Errorf("ibmi packed: invalid header or budget")
	}
	pos, out := int64(16), int64(0)
	for i := uint32(0); i < count; i++ {
		if int64(p.StoredBytes)-pos < 16 {
			return nil, fmt.Errorf("ibmi packed: truncated frame header")
		}
		if _, err := starfile.ReadFullAt(source, h[:], pos); err != nil {
			return nil, err
		}
		stored, expanded := be.Uint32(h[4:]), be.Uint32(h[8:])
		if be.Uint32(h[:]) != 0x03000080 || stored < 16 || stored > 65536 || int64(stored) > int64(p.StoredBytes)-pos || expanded == 0 || expanded > 32768 || int64(expanded) > int64(p.ExpandedBytes)-out {
			return nil, fmt.Errorf("ibmi packed: invalid frame %d", i)
		}
		p.Frames = append(p.Frames, Frame{pos, stored, expanded, out})
		pos += int64(stored)
		out += int64(expanded)
	}
	if pos != int64(p.StoredBytes) || out != int64(p.ExpandedBytes) {
		return nil, fmt.Errorf("ibmi packed: aggregate length mismatch")
	}
	p.Data = &packedReader{source: source, frames: append([]Frame(nil), p.Frames...), size: out, cachedIndex: -1}
	return p, nil
}

type bitReader struct {
	data []byte
	bit  int
}

func (r *bitReader) read(n int) (uint32, error) {
	if n < 0 || n > 11 || n > len(r.data)*8-r.bit {
		return 0, io.ErrUnexpectedEOF
	}
	var v uint32
	for i := 0; i < n; i++ {
		v = v<<1 | uint32((r.data[r.bit/8]>>uint(7-r.bit%8))&1)
		r.bit++
	}
	return v, nil
}

// DecodeFrame expands one bounded 03000080 frame with fresh history. References
// copy forwards (including overlap), and cannot refer outside this frame.
func DecodeFrame(frame []byte) ([]byte, error) {
	out, info, err := DecodeFrameWithInfo(frame)
	if err == nil && !info.TerminationVerified {
		return nil, fmt.Errorf("ibmi packed: invalid end control or stop-bit padding")
	}
	return out, err
}

// FrameDecodeInfo distinguishes exact output from control/padding integrity.
// Bit counts are relative to the bitstream at frame offset 12. The first tail
// byte may also contain consumed bits; TailFirstBit disambiguates that overlap.
type FrameDecodeInfo struct {
	OutputConsumedBits  int  `json:"output_consumed_bits"`
	RemainingBits       int  `json:"remaining_bits"`
	TailByteOffset      int  `json:"tail_byte_offset"`
	TailFirstBit        int  `json:"tail_first_bit"`
	EndControlBits      int  `json:"end_control_bits"`
	PaddingBits         int  `json:"padding_bits"`
	PaddingZero         bool `json:"padding_zero"`
	StopBit             bool `json:"stop_bit"`
	PostStopZero        bool `json:"post_stop_zero"`
	TerminationVerified bool `json:"termination_verified"`
}

func DecodeFrameWithInfo(frame []byte) ([]byte, FrameDecodeInfo, error) {
	if len(frame) < 16 || len(frame) > 65536 || binary.BigEndian.Uint32(frame) != 0x03000080 || uint64(binary.BigEndian.Uint32(frame[4:])) != uint64(len(frame)) {
		return nil, FrameDecodeInfo{}, fmt.Errorf("ibmi packed: malformed frame")
	}
	want := int(binary.BigEndian.Uint32(frame[8:]))
	if want < 1 || want > 32768 {
		return nil, FrameDecodeInfo{}, fmt.Errorf("ibmi packed: frame output budget")
	}
	r := bitReader{data: frame[12:]}
	out := make([]byte, 0, want)
	for len(out) < want {
		tag, err := r.read(1)
		if err != nil {
			return nil, FrameDecodeInfo{}, err
		}
		if tag == 0 {
			v, err := r.read(8)
			if err != nil {
				return nil, FrameDecodeInfo{}, err
			}
			out = append(out, byte(v))
			continue
		}
		width := 2
		for width < 8 {
			if r.bit >= len(r.data)*8 {
				return nil, FrameDecodeInfo{}, io.ErrUnexpectedEOF
			}
			if (r.data[r.bit/8]>>uint(7-r.bit%8))&1 != 0 {
				break
			}
			r.bit++
			width++
		}
		length, err := r.read(width)
		if err != nil {
			return nil, FrameDecodeInfo{}, err
		}
		if length == 255 {
			return nil, FrameDecodeInfo{}, fmt.Errorf("ibmi packed: premature end marker at output %d", len(out))
		}
		near, err := r.read(1)
		if err != nil {
			return nil, FrameDecodeInfo{}, err
		}
		width = 11
		if near != 0 {
			width = 7
		}
		distance, err := r.read(width)
		if err != nil {
			return nil, FrameDecodeInfo{}, err
		}
		if distance == 0 || int(distance) > len(out) || length == 0 || int(length) > want-len(out) {
			return nil, FrameDecodeInfo{}, fmt.Errorf("ibmi packed: invalid reference at bit %d, length %d distance %d output %d", r.bit, length, distance, len(out))
		}
		for i := uint32(0); i < length; i++ {
			out = append(out, out[len(out)-int(distance)])
		}
	}
	info := FrameDecodeInfo{OutputConsumedBits: r.bit, RemainingBits: len(r.data)*8 - r.bit, TailByteOffset: 12 + r.bit/8, TailFirstBit: r.bit % 8}
	tail := r
	tag, err := tail.read(1)
	if err == nil && tag == 1 {
		width := 2
		for width < 8 && tail.bit < len(tail.data)*8 && (tail.data[tail.bit/8]>>uint(7-tail.bit%8))&1 == 0 {
			tail.bit++
			width++
		}
		length, err := tail.read(width)
		if err == nil && length == 255 {
			info.EndControlBits = tail.bit - r.bit
		}
	}
	padding := r.bit + info.EndControlBits
	info.PaddingBits = len(r.data)*8 - padding
	info.PaddingZero = true
	for pos := padding; pos < len(r.data)*8; pos++ {
		if (r.data[pos/8]>>uint(7-pos%8))&1 != 0 {
			info.PaddingZero = false
			break
		}
	}
	if info.PaddingBits >= 1 && info.PaddingBits <= 32 {
		info.StopBit = (r.data[padding/8]>>uint(7-padding%8))&1 != 0
		info.PostStopZero = true
		for pos := padding + 1; pos < len(r.data)*8; pos++ {
			if (r.data[pos/8]>>uint(7-pos%8))&1 != 0 {
				info.PostStopZero = false
				break
			}
		}
	}
	info.TerminationVerified = info.EndControlBits == 15 && len(frame)%4 == 0 && info.PaddingBits >= 1 && info.PaddingBits <= 32 && info.StopBit && info.PostStopZero
	return out, info, nil
}

type packedReader struct {
	source      storage.Reader
	frames      []Frame
	size        int64
	mu          sync.Mutex
	cachedIndex int
	cached      []byte
}

func (r *packedReader) Size() int64 { return r.size }
func (r *packedReader) ReadAt(dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ibmi packed: negative offset")
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for len(dst) > 0 && off < r.size {
		i := sort.Search(len(r.frames), func(i int) bool { return r.frames[i].OutputOffset+int64(r.frames[i].Expanded) > off })
		f := r.frames[i]
		if r.cachedIndex != i {
			raw := make([]byte, int(f.Stored))
			if _, err := starfile.ReadFullAt(r.source, raw, f.Offset); err != nil {
				return n, err
			}
			decoded, err := DecodeFrame(raw)
			if err != nil {
				return n, fmt.Errorf("ibmi packed frame %d: %w", i, err)
			}
			r.cached = decoded
			r.cachedIndex = i
		}
		copied := copy(dst, r.cached[off-f.OutputOffset:])
		n += copied
		off += int64(copied)
		dst = dst[copied:]
	}
	if len(dst) > 0 {
		return n, io.EOF
	}
	return n, nil
}

// InspectFrame decodes one frame and returns exact consumption diagnostics.
// It does not force expansion of any other frame.
func (p *Packed) InspectFrame(index int) (FrameDecodeInfo, storage.Reader, error) {
	if index < 0 {
		return FrameDecodeInfo{}, nil, fmt.Errorf("ibmi packed: frame index")
	}
	r, ok := p.Data.(*packedReader)
	if !ok || index >= len(r.frames) {
		return FrameDecodeInfo{}, nil, fmt.Errorf("ibmi packed: invalid reader or frame index")
	}
	// Use the reader's private validated frame table, not mutable exported metadata.
	f := r.frames[index]
	raw := make([]byte, int(f.Stored))
	if _, err := starfile.ReadFullAt(r.source, raw, f.Offset); err != nil {
		return FrameDecodeInfo{}, nil, err
	}
	_, info, err := DecodeFrameWithInfo(raw)
	if err != nil {
		return FrameDecodeInfo{}, nil, err
	}
	return info, io.NewSectionReader(r.source, f.Offset+int64(info.TailByteOffset), int64(f.Stored)-int64(info.TailByteOffset)), nil
}
