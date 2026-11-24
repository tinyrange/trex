package s390

import (
	"math/bits"
	"slices"
)

// Seven-track 2803 mode modifiers (A22-6866-4, figure 14).
const (
	tapeConvert       = 0x10
	tapeEven          = 0x20
	tapeEvenTranslate = 0x28
	tapeOdd           = 0x30
	tapeOddTranslate  = 0x38
)

func (t *Tape2401) frameRate() int64 {
	return int64(t.density()) * 75 // inches per second, Model 2
}

func (t *Tape2401) density() int {
	if t.sevenTrack {
		switch t.sevenMode & 0xc0 {
		case 0x00:
			return 200
		case 0x40:
			return 556
		}
	}
	return 800
}

func (t *Tape2401) writeRecord(data []byte) {
	if t.sevenTrack {
		data = encodeSevenTrack(data, t.sevenMode)
	}
	t.Tape3420.writeRecord(data)
	if t.sevenTrack {
		t.blocks[t.pos-1].density = t.density()
	}
}

// eraseSevenTrackGap overwrites about 3.5 inches starting at the current
// record boundary. Surviving frames stay readable as the next block.
func (t *Tape2401) eraseSevenTrackGap() error {
	const eraseMils = 3500
	const gapMils = 750
	t.motion(eraseMils * t.density() / 1000)
	remaining := eraseMils
	for remaining > 0 && t.pos < len(t.blocks) {
		block := &t.blocks[t.pos]
		density := block.density
		if density == 0 {
			density = t.density()
		}
		frames := remaining * density / 1000
		if frames < block.n {
			data, err := block.bytes()
			if err != nil {
				return err
			}
			*block = tapeBlock{data: slices.Clone(data[frames:]), n: len(data) - frames, bad: block.bad, density: density}
			break
		}
		remaining -= (block.n*1000+density-1)/density + gapMils
		t.blocks = slices.Delete(t.blocks, t.pos, t.pos+1)
	}
	return nil
}

// encodeSevenTrack produces one physical frame per byte with the parity
// track in bit 6. With conversion, each group of three bytes spans four
// frames; the final frame is right-padded with zero bits.
func encodeSevenTrack(data []byte, mode byte) []byte {
	mode &= 0x38
	odd := mode != tapeEven && mode != tapeEvenTranslate
	if mode == tapeConvert {
		frames := make([]byte, 0, (len(data)*8+5)/6)
		var word uint16
		var count int
		for _, b := range data {
			word = word<<8 | uint16(b)
			count += 8
			for count >= 6 {
				count -= 6
				frames = append(frames, frameParity(byte(word>>count)&0x3f, odd))
			}
		}
		if count != 0 {
			frames = append(frames, frameParity(byte(word<<(6-count))&0x3f, odd))
		}
		return frames
	}
	frames := make([]byte, len(data))
	for i, b := range data {
		code := b & 0x3f
		if mode == tapeEvenTranslate || mode == tapeOddTranslate {
			code = ebcdicToTapeBCD(b)
		}
		if !odd && code == 0 {
			code = 0x10 // substitute blank supplies a recorded transition
		}
		frames[i] = frameParity(code, odd)
	}
	return frames
}

func frameParity(code byte, odd bool) byte {
	if (bits.OnesCount8(code)&1 != 0) != odd {
		code |= 0x40
	}
	return code
}

func (t *Tape2401) readSevenTrack(frames []byte, backward bool) []byte {
	mode := t.sevenMode & 0x38
	odd := mode != tapeEven && mode != tapeEvenTranslate
	out := make([]byte, 0, len(frames))
	var word uint16
	var count int
	for _, frame := range frames {
		code := frame & 0x3f
		if frame&0x7f != frameParity(code, odd) {
			t.sense[0] |= senseDataCheck
			t.sense[3] |= 0x80 // read/write vertical redundancy check
		}
		switch {
		case mode == tapeConvert && !backward:
			word = word<<6 | uint16(code)
			count += 6
			if count >= 8 {
				count -= 8
				out = append(out, byte(word>>count))
			}
		case mode == tapeEvenTranslate || mode == tapeOddTranslate:
			if !odd && code == 0x10 {
				code = 0 // substitute blank
			}
			out = append(out, tapeBCDToEBCDIC(code))
		default:
			out = append(out, code)
		}
	}
	if count == 6 || word&((1<<count)-1) != 0 {
		// A lone frame or nonzero bits where padding should be reports a
		// converter check and supplies the remaining bits with zero fill.
		t.sense[0] |= 0x01
		out = append(out, byte(word<<(8-count)))
	}
	return out
}

// BCDIC zone translation and the space and zero exceptions (A22-6866-4,
// figures 18 and 19). The zone codes for digits differ from those for
// alphabetic and punctuation characters.
func ebcdicToTapeBCD(b byte) byte {
	code := b & 0x3f
	// The high EBCDIC zone bit exchanges the zero and special-character
	// positions in each of the three nondigit zones.
	if b&0x80 != 0 && code < 0x30 && (code&0xf == 0 || code&0xf == 0xa) {
		code ^= 0xa
	}
	switch code {
	case 0x00:
		return 0
	case 0x10:
		return 0x30
	case 0x20:
		return 0x20
	case 0x30:
		return 0x0a
	case 0x3a:
		return 0x10
	default:
		return code ^ 0x30
	}
}

func tapeBCDToEBCDIC(code byte) byte {
	switch {
	case code == 0:
		return 0x40
	case code <= 0x09:
		return 0xf0 | code
	case code == 0x0a:
		return 0xf0
	case code == 0x10:
		return 0x7a
	case code == 0x20:
		return 0x60
	case code == 0x30:
		return 0x50
	case code == 0x1a || code == 0x2a || code == 0x3a:
		return 0xc0 | (code ^ 0x3a)
	case code >= 0x11 && code <= 0x19 || code >= 0x21 && code <= 0x29 ||
		code >= 0x31 && code <= 0x39:
		if code == 0x11 {
			return 0x61
		}
		return 0xc0 | (code ^ 0x30)
	}
	// Punctuation includes the unassigned characters in the same zones.
	return 0x40 | (code ^ 0x30)
}
