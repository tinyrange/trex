package sevenzip

import (
	"encoding/binary"
	"fmt"
	"io"
)

// The x86 filter below is adapted from the explicitly public-domain
// dec_bcj.go in github.com/therootcompany/xz v1.0.1 (CC0).
// Authors: Lasse Collin, Igor Pavlov; Go translation: Michael Cross.
// The streaming adapter keeps only one block plus four lookahead bytes.
type bcjReader struct {
	source         io.Reader
	remaining      uint64
	pos, mask      uint32
	pending, ready []byte
}

func newBCJReader(source io.Reader, size uint64, properties []byte) (io.Reader, error) {
	r := &bcjReader{source: source, remaining: size}
	if len(properties) == 4 {
		r.pos = binary.LittleEndian.Uint32(properties)
	} else if len(properties) != 0 {
		return nil, fmt.Errorf("7z: invalid BCJ properties")
	}
	return r, nil
}
func (r *bcjReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.ready) == 0 {
		if r.remaining == 0 && len(r.pending) == 0 {
			return 0, io.EOF
		}
		count := int(min(r.remaining, 64<<10))
		buf := make([]byte, len(r.pending)+count)
		copy(buf, r.pending)
		if _, e := io.ReadFull(r.source, buf[len(r.pending):]); e != nil {
			return 0, fmt.Errorf("7z: truncated BCJ input: %w", e)
		}
		r.remaining -= uint64(count)
		converted := bcjX86Filter(r, buf)
		r.pos += uint32(converted)
		if r.remaining == 0 {
			converted = len(buf)
		}
		r.ready = buf[:converted]
		r.pending = buf[converted:]
	}
	n := copy(p, r.ready)
	r.ready = r.ready[n:]
	return n, nil
}

func bcjX86TestMSByte(b byte) bool {
	return b == 0x00 || b == 0xff
}

func bcjX86Filter(s *bcjReader, buf []byte) int {
	var maskToAllowedStatus = []bool{
		true, true, true, false, true, false, false, false,
	}
	var maskToBitNum = []byte{0, 1, 2, 2, 3, 3, 3, 3}
	var i int
	var prevPos int = -1
	var prevMask uint32 = s.mask
	var src uint32
	var dest uint32
	var j uint32
	var b byte
	if len(buf) <= 4 {
		return 0
	}
	for i = 0; i < len(buf)-4; i++ {
		if buf[i]&0xfe != 0xe8 {
			continue
		}
		prevPos = i - prevPos
		if prevPos > 3 {
			prevMask = 0
		} else {
			prevMask = (prevMask << (uint(prevPos) - 1)) & 7
			if prevMask != 0 {
				b = buf[i+4-int(maskToBitNum[prevMask])]
				if !maskToAllowedStatus[prevMask] || bcjX86TestMSByte(b) {
					prevPos = i
					prevMask = prevMask<<1 | 1
					continue
				}
			}
		}
		prevPos = i
		if bcjX86TestMSByte(buf[i+4]) {
			src = binary.LittleEndian.Uint32(buf[i+1:])
			for {
				dest = src - (s.pos + uint32(i) + 5)
				if prevMask == 0 {
					break
				}
				j = uint32(maskToBitNum[prevMask]) * 8
				b = byte(dest >> (24 - j))
				if !bcjX86TestMSByte(b) {
					break
				}
				src = dest ^ (1<<(32-j) - 1)
			}
			dest &= 0x01FFFFFF
			dest |= 0 - dest&0x01000000
			binary.LittleEndian.PutUint32(buf[i+1:], dest)
			i += 4
		} else {
			prevMask = prevMask<<1 | 1
		}
	}
	prevPos = i - prevPos
	if prevPos > 3 {
		s.mask = 0
	} else {
		s.mask = prevMask << (uint(prevPos) - 1)
	}
	return i
}
