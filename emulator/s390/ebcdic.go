package s390

import "golang.org/x/text/encoding/charmap"

var ebcdicToRune [256]rune
var asciiToEBCDIC [256]byte

func init() {
	for i := 0; i < 256; i++ {
		ebcdicToRune[i] = charmap.CodePage037.DecodeByte(byte(i))
		asciiToEBCDIC[i] = 0x6f // '?'
	}
	for i := 0; i < 256; i++ {
		r := ebcdicToRune[i]
		if r < 256 {
			asciiToEBCDIC[r] = byte(i)
		}
	}
}

// EBCDICString decodes code page 037 text, mapping controls to spaces.
func EBCDICString(b []byte) string {
	out := make([]rune, len(b))
	for i, x := range b {
		r := ebcdicToRune[x]
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = ' '
		}
		out[i] = r
	}
	return string(out)
}

// EncodeEBCDIC encodes text in code page 037.
func EncodeEBCDIC(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 256 {
			out = append(out, asciiToEBCDIC[r])
		} else {
			out = append(out, 0x6f)
		}
	}
	return out
}

// Code page 500 (international) differs from 037 in seven positions; the
// Linux for S/390 console drivers use it.
var cp500 = map[byte]rune{0x4a: '[', 0x4f: '!', 0x5a: ']', 0x5f: '^', 0xb0: '¢', 0xba: '¬', 0xbb: '|'}

// EBCDIC500String decodes code page 500 text, mapping controls to spaces.
func EBCDIC500String(b []byte) string {
	out := []rune(EBCDICString(b))
	for i, x := range b {
		if r, ok := cp500[x]; ok {
			out[i] = r
		}
	}
	return string(out)
}

// EncodeEBCDIC500 encodes text in code page 500.
func EncodeEBCDIC500(s string) []byte {
	out := EncodeEBCDIC(s)
	rs := []rune(s)
	for e, r := range cp500 {
		for i := range rs {
			if rs[i] == r {
				out[i] = e
			}
		}
	}
	return out
}
