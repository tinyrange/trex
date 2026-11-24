package s390

import (
	"strings"
	"time"
)

// 1403 printer behind a 2821 control unit with the Universal Character Set
// feature (IBM 2821 Control Unit, GA24-3312-9).

// printBuffer is the size of the 2821's print-line buffer: a write or
// diagnostic write takes at most this many bytes.
const printBuffer = 132

// Printer sense bits.
const (
	sensePrtEquip    = 0x10 // equipment check: hammer check
	sensePrtData     = 0x08 // data check: a character not in the UCS storage
	sensePrtChannel9 = 0x01 // channel 9 sensed during a carriage space
)

// Check-read plane bits for each print position.
const (
	planeLineComplete = 0x04
	planePrintCheck   = 0x02
)

// formLength is the number of lines on a form when no carriage tape is
// given.
const formLength = 66

// printer holds the 2821/1403 state.
type printer struct {
	// Carriage: the carriage tape holds, for each line from line 1, the
	// channels punched in it (bit n-1 for channel n), and line is the
	// current line (0-based).
	tape []uint16
	line int
	// skipMoves reports whether a skip-immediate moves the carriage when
	// it is already at the channel (only after a write without spacing or a
	// UCS load).
	skipMoves bool

	ucs        [240]byte // the 240-character storage
	ucsLoaded  bool      // loaded since power on (otherwise every code prints)
	ucsGated   bool      // a UCS gate in this chain allows a UCS load
	fold       bool      // the storage was loaded with folding
	blockCheck bool      // block-data-check is in force
	plane      [printBuffer]byte
}

// SetCarriageTape installs a carriage tape: holes lists, for each line from
// line 1, the channels (1-12) punched in that line. The carriage is
// restored to channel 1.
func (u *UnitRecord) SetCarriageTape(holes [][]int) {
	u.pr.tape = make([]uint16, len(holes))
	for i, chs := range holes {
		for _, c := range chs {
			if c >= 1 && c <= 12 {
				u.pr.tape[i] |= 1 << (c - 1)
			}
		}
	}
	u.restoreCarriage()
}

func (u *UnitRecord) carriage() []uint16 {
	if u.pr.tape == nil {
		u.pr.tape = make([]uint16, formLength)
		u.pr.tape[0] = 1 // channel 1 at the first line
	}
	return u.pr.tape
}

// restoreCarriage positions the carriage at channel 1, as the restore key does.
func (u *UnitRecord) restoreCarriage() {
	t := u.carriage()
	for i, h := range t {
		if h&1 != 0 {
			u.pr.line = i
			return
		}
	}
	u.pr.line = 0
}

// space moves the carriage n lines and returns the device status bits the
// channels sensed in the lines reached: unit check for channel 9 (with the
// sense bit) and unit exception for channel 12.
func (u *UnitRecord) space(n int) byte {
	t := u.carriage()
	var st byte
	for i := 0; i < n; i++ {
		u.pr.line = (u.pr.line + 1) % len(t)
		if t[u.pr.line]&(1<<8) != 0 {
			u.sense |= sensePrtChannel9
			st |= usUnitCheck
		}
		if t[u.pr.line]&(1<<11) != 0 {
			st |= usUnitExcept
		}
	}
	return st
}

// skip moves the carriage to the next line punched in channel c.
func (u *UnitRecord) skip(c int) {
	t := u.carriage()
	bit := uint16(1) << (c - 1)
	if t[u.pr.line]&bit != 0 && !u.pr.skipMoves {
		return
	}
	for i := 1; i <= len(t); i++ {
		l := (u.pr.line + i) % len(t)
		if t[l]&bit != 0 {
			u.pr.line = l
			return
		}
	}
}

// carriageAfter moves the carriage as a write or control command's modifier
// bits specify and returns the status from channels 9 and 12.
func (u *UnitRecord) carriageAfter(mod byte) byte {
	switch {
	case mod&0x10 != 0:
		u.skip(int(mod & 0xf))
		u.pr.skipMoves = false
		return 0
	case mod != 0:
		u.pr.skipMoves = false
		return u.space(int(mod))
	}
	u.pr.skipMoves = true
	return 0
}

// load fills the print buffer from channel data. It returns the bytes
// taken, and the length the control unit asks for (the whole buffer), which
// the channel compares with the count for incorrect length.
func (u *UnitRecord) load(data []byte) (int, int) {
	n := min(len(data), printBuffer)
	u.buffer = append(u.buffer[:0], data[:n]...)
	return n, printBuffer
}

// printScan compares the print buffer with the UCS storage as the chain
// passes, setting each position's check planes; print reports whether
// hammers fire (a write, not a diagnostic write) and gated whether the
// write follows a UCS gate in its chain. A position completes (the
// print-line-complete plane) when its character prints or is a blank or
// null, which never print. A character not in the storage leaves the
// position incomplete and, when printing, is a data check unless blocked.
// While gated, the storage addressing is not synchronized with the chain
// and a blank or null that the storage holds is selected for printing: a
// print (hammer) check, an equipment check. With folding, the quadrant bits
// are not compared.
func (u *UnitRecord) printScan(print, gated bool) byte {
	for i := range u.pr.plane {
		u.pr.plane[i] = planeLineComplete
	}
	if !u.pr.ucsLoaded {
		return 0
	}
	key := func(b byte) byte {
		if u.pr.fold {
			return b | 0xc0
		}
		return b
	}
	var loaded [256]bool
	for _, x := range u.pr.ucs {
		loaded[key(x)] = true
	}
	var st byte
	for i := 0; i < printBuffer; i++ {
		b := byte(0x40)
		if i < len(u.buffer) {
			b = key(u.buffer[i])
		}
		blank := b == 0x00 || b == 0x40 || u.pr.fold && b == 0xc0
		switch {
		case !loaded[b] && blank:
		case !loaded[b]:
			u.pr.plane[i] = 0
			if print && !u.pr.blockCheck {
				u.sense |= sensePrtData
				st |= usUnitCheck
			}
		case blank && print && gated:
			u.pr.plane[i] |= planePrintCheck
			u.sense |= sensePrtEquip
			st |= usUnitCheck
		}
	}
	return st
}

// printerExec executes a 1403 command. first reports whether the command is
// the first of its chain and prev is the command before it in the chain.
func (u *UnitRecord) printerExec(cmd byte, data []byte, first bool, prev byte) ([]byte, int, byte) {
	mod := cmd >> 3
	validMod := mod <= 3 || mod&0x10 != 0 && mod&0xf >= 1 && mod&0xf <= 12
	// Any command other than the gate and the data-check controls ends the
	// gating; a print scan of this command still sees it.
	gated := u.pr.ucsGated
	if cmd != 0xeb && cmd != 0x73 && cmd != 0x7b {
		u.pr.ucsGated = false
	}
	switch {
	case cmd == 0xeb: // UCS gate: first in a chain, or reissued while gated
		if !first && !gated {
			return u.reject()
		}
		u.pr.ucsGated = true
		return nil, 0, usCE | usDE
	case cmd == 0x73 || cmd == 0x7b: // block / reset block data check
		// Alone, first in a chain, or after a UCS gate with no write,
		// carriage or UCS load command between.
		if !first && !gated {
			return u.reject()
		}
		u.pr.blockCheck = cmd == 0x73
		return nil, 0, usCE | usDE
	case cmd == 0xfb || cmd == 0xf3: // UCS storage load (no folding, folding)
		if !gated {
			return u.reject()
		}
		u.pr.skipMoves = true
		u.pr.fold = cmd == 0xf3
		n := min(len(data), len(u.pr.ucs))
		copy(u.pr.ucs[:], data[:n])
		u.pr.ucsLoaded = true
		u.chanT, u.devT = urControlXfr+time.Duration(n)*urByte, spaceTime
		return nil, len(u.pr.ucs), usCE | usDE
	case cmd&7 == 1 && validMod: // write, with spacing or skipping after
		n, want := u.load(data)
		u.Output = append(u.Output, strings.TrimRight(EBCDICString(data[:n]), " "))
		if len(u.Output) > 20000 {
			u.dropped += 10000
			u.Output = append(u.Output[:0], u.Output[10000:]...)
		}
		u.version++
		st := u.printScan(true, gated) | u.carriageAfter(mod)
		u.chanT, u.devT = urControlXfr+time.Duration(n)*urByte, printCycle
		return nil, want, usCE | usDE | st
	case cmd&7 == 5 && validMod: // diagnostic write: load the buffer, one print scan
		// No printing takes place, so an uncomparable character leaves
		// its position incomplete without a data check.
		n, want := u.load(data)
		st := u.printScan(false, gated)
		u.chanT, u.devT = urControlXfr+time.Duration(n)*urByte, printCycle
		return nil, want, usCE | usDE | st
	case cmd == 0x02: // diagnostic data read of the print buffer
		out := make([]byte, printBuffer)
		copy(out, u.buffer)
		u.chanT = urControlXfr + printBuffer*urByte
		return out, 0, usCE | usDE
	case cmd == 0x06: // diagnostic check read of the check planes
		u.chanT = urControlXfr + printBuffer*urByte
		return append([]byte(nil), u.pr.plane[:]...), 0, usCE | usDE | u.planeStatus()
	case cmd&7 == 3 && validMod && mod != 0: // space or skip immediately
		st := u.carriageAfter(mod)
		u.devT = spaceTime
		return nil, 0, usCE | usDE | st
	}
	return u.reject()
}

// planeStatus is the status of a check read: a position with a print check,
// or one the last print scan left incomplete, is an equipment check.
func (u *UnitRecord) planeStatus() byte {
	for _, p := range u.pr.plane {
		if p&planePrintCheck != 0 || p&planeLineComplete == 0 {
			u.sense |= sensePrtEquip
			return usUnitCheck
		}
	}
	return 0
}
