// Package lzvn decodes Apple LZVN token streams; see NOTICE for provenance.
package lzvn

import (
	"encoding/binary"
	"fmt"
)

// LZVN tokens encode literal/match lengths and an explicit or reused distance.
// End tokens occupy eight bytes; undefined opcodes never become empty output.
// Decode requires the exact decoded size and optional preceding block history.
// The caller must bound size before calling; no partial output is returned on error.
func Decode(src []byte, size int, history []byte) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("lzvn: negative decoded size")
	}
	out := make([]byte, 0, size)
	distance := 0
	pos := 0
	for pos < len(src) {
		op := int(src[pos])
		n, l, m := 1, 0, 0
		switch {
		case op == 6:
			if pos+8 != len(src) || len(out) != size {
				return nil, fmt.Errorf("lzvn: LZVN end/size mismatch")
			}
			return out, nil
		case op == 14 || op == 22:
			pos++
			continue
		case op >= 0xe0 && op <= 0xef:
			l = op & 15
			if op == 0xe0 {
				n = 2
				if pos+2 > len(src) {
					return nil, fmt.Errorf("lzvn: truncated LZVN token")
				}
				l = int(src[pos+1]) + 16
			}
		case op >= 0xf0:
			m = op & 15
			if op == 0xf0 {
				n = 2
				if pos+2 > len(src) {
					return nil, fmt.Errorf("lzvn: truncated LZVN token")
				}
				m = int(src[pos+1]) + 16
			}
		case op >= 0xa0 && op <= 0xbf:
			n = 3
			l = (op >> 3) & 3
			if pos+3 > len(src) {
				return nil, fmt.Errorf("lzvn: truncated LZVN token")
			}
			v := int(binary.LittleEndian.Uint16(src[pos+1:]))
			m = ((op&7)<<2 | v&3) + 3
			distance = v >> 2
		case op >= 0x70 && op <= 0x7f || op >= 0xd0 && op <= 0xdf || op&7 == 6 && op < 0x40:
			return nil, fmt.Errorf("lzvn: undefined LZVN opcode")
		default:
			l = op >> 6
			m = ((op >> 3) & 7) + 3
			if op&7 == 7 {
				n = 3
				if pos+3 > len(src) {
					return nil, fmt.Errorf("lzvn: truncated LZVN token")
				}
				distance = int(binary.LittleEndian.Uint16(src[pos+1:]))
			} else if op&7 != 6 {
				n = 2
				if pos+2 > len(src) {
					return nil, fmt.Errorf("lzvn: truncated LZVN token")
				}
				distance = (op&7)<<8 | int(src[pos+1])
			}
		}
		pos += n
		if l > len(src)-pos || l+m > size-len(out) {
			return nil, fmt.Errorf("lzvn: LZVN literal/output overflow")
		}
		out = append(out, src[pos:pos+l]...)
		pos += l
		if m > 0 && (distance <= 0 || distance > len(history)+len(out)) {
			return nil, fmt.Errorf("lzvn: invalid LZVN distance")
		}
		for j := 0; j < m; j++ {
			index := len(out) - distance
			if index < 0 {
				out = append(out, history[len(history)+index])
			} else {
				out = append(out, out[index])
			}
		}
	}
	return nil, fmt.Errorf("lzvn: missing LZVN end")
}
