package ibmisave

import (
	"encoding/binary"
	"fmt"
)

// TerseInfo describes consumption without treating output length as proof of
// termination. Codec 02 is not the variable-width LIC codec 03.
type TerseInfo struct {
	Codes               int    `json:"codes"`
	ConsumedBits        int    `json:"consumed_bits"`
	RemainingBits       int    `json:"remaining_bits"`
	DictionaryFull      bool   `json:"dictionary_full"`
	TailHex             string `json:"tail_hex"`
	TerminationVerified bool   `json:"termination_verified"`
}

// DecodeTerseWithInfo decodes an inspected fixed-12-bit 02000080 frame
// with prefix-chain LRU replacement. The caller must inspect
// TerminationVerified before accepting
// the result as a complete record. Storage is bounded by the 16-bit LD_TRS
// record lengths; prefix chains avoid quadratic dictionary allocations.
func DecodeTerseWithInfo(frame []byte) ([]byte, TerseInfo, error) {
	var info TerseInfo
	bad := func(s string) ([]byte, TerseInfo, error) { return nil, info, fmt.Errorf("ibmi_terse: %s", s) }
	if len(frame) < 12 || len(frame) > 65535 || binary.BigEndian.Uint32(frame) != 0x02000080 || int(binary.BigEndian.Uint32(frame[4:])) != len(frame) {
		return bad("invalid frame header")
	}
	want := int(binary.BigEndian.Uint32(frame[8:]))
	if want < 1 || want > 65535 {
		return bad("invalid expanded size")
	}
	// Every tree node starts as a blank-run extension. The least recently used
	// node is recycled, and every node in the referenced prefix chain is touched.
	// This is not a frozen or implicitly reset LZW dictionary.
	var parent, forward, backward [4096]uint16
	var suffix [4096]byte
	prev := uint16(65)
	for i := 258; i < 4096; i++ {
		parent[i] = prev
		suffix[i] = 0x40
		prev = uint16(i)
		backward[i] = uint16(i - 1)
		forward[i] = uint16(i + 1)
	}
	forward[0] = 258
	backward[0] = 4095
	backward[258] = 0
	forward[4095] = 0
	data := frame[12:]
	previous := uint16(0)
	out := make([]byte, 0, want)
	var path [4096]uint16
	for len(out) < want {
		bit := info.Codes * 12
		if bit+12 > len(data)*8 {
			return bad("truncated code stream")
		}
		off := bit / 8
		code := uint16(binary.BigEndian.Uint16(data[off : off+2]))
		if bit%8 == 0 {
			code >>= 4
		} else {
			code &= 4095
		}
		info.Codes++
		info.ConsumedBits = info.Codes * 12
		if code == 0 || code == 257 {
			return bad("reserved/end code before declared output")
		}
		selected := backward[0]
		if selected == 0 {
			return bad("empty replacement list")
		}
		before := backward[selected]
		backward[0] = before
		forward[before] = 0
		head := selected
		depth := 0
		cur := code
		for cur > 257 {
			if depth == len(path) || cur == selected {
				return bad("invalid dictionary chain")
			}
			path[depth] = cur
			depth++
			f, b := forward[cur], backward[cur]
			forward[b] = f
			backward[f] = b
			forward[cur] = head
			backward[head] = cur
			head = cur
			cur = parent[cur]
		}
		if cur == 0 || cur > 256 {
			return bad("invalid literal")
		}
		if depth+1 > want-len(out) {
			return bad(fmt.Sprintf("phrase exceeds output at %d/%d code %d", len(out), want, code))
		}
		first := byte(cur - 1)
		suffix[previous] = first
		out = append(out, first)
		for j := depth - 1; j >= 0; j-- {
			out = append(out, suffix[path[j]])
		}
		front := forward[0]
		forward[selected] = front
		backward[front] = selected
		forward[0] = head
		backward[head] = 0
		parent[selected] = code
		previous = selected
	}
	info.DictionaryFull = info.Codes > 3838
	info.RemainingBits = len(data)*8 - info.ConsumedBits
	info.TailHex = fmt.Sprintf("%x", data[info.ConsumedBits/8:])
	// One zero 12-bit end code, then zero fill to a byte boundary.
	info.TerminationVerified = info.RemainingBits == 12 || info.RemainingBits == 16
	if info.TerminationVerified {
		for bit := info.ConsumedBits; bit < len(data)*8; bit++ {
			if data[bit/8]&(1<<uint(7-bit%8)) != 0 {
				info.TerminationVerified = false
				break
			}
		}
	}
	return out, info, nil
}
