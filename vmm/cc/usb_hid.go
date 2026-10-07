package cc

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// USB 1.1 low-speed HID devices. Descriptor/control handling is independent of
// the host-controller transport. Identities name synthetic trex devices.
type usbHID struct {
	pointer                                bool
	address, configuration, protocol, idle byte
	pendingAddress                         byte
	addressPending                         bool
	request                                [8]byte
	reply                                  []byte
	replyOffset                            int
	output                                 []byte
	stalled                                bool
	report                                 []byte
	pending                                [][]byte
	controls, reports                      uint64
	trace                                  []any
}

func newUSBHID(pointer bool) *usbHID {
	d := &usbHID{pointer: pointer, protocol: 1}
	d.report = make([]byte, 8)
	if pointer {
		d.report = make([]byte, 6)
	}
	return d
}

// Standard boot keyboard and an absolute pointing device with wheel. The
// pointer uses generic report protocol, not a misleading boot-mouse protocol.
var usbKeyboardDescriptor = []byte{
	0x05, 1, 0x09, 6, 0xa1, 1, 0x05, 7, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0, 0x25, 1,
	0x75, 1, 0x95, 8, 0x81, 2, 0x95, 1, 0x75, 8, 0x81, 1,
	0x95, 5, 0x75, 1, 0x05, 8, 0x19, 1, 0x29, 5, 0x91, 2,
	0x95, 1, 0x75, 3, 0x91, 1, 0x95, 6, 0x75, 8, 0x15, 0, 0x25, 0x65,
	0x05, 7, 0x19, 0, 0x29, 0x65, 0x81, 0, 0xc0,
}
var usbPointerDescriptor = []byte{
	0x05, 1, 0x09, 2, 0xa1, 1, 0x09, 1, 0xa1, 0,
	0x05, 9, 0x19, 1, 0x29, 3, 0x15, 0, 0x25, 1, 0x95, 3, 0x75, 1, 0x81, 2,
	0x95, 1, 0x75, 5, 0x81, 1, 0x05, 1, 0x09, 0x30, 0x09, 0x31,
	0x15, 0, 0x26, 0xff, 0x7f, 0x75, 16, 0x95, 2, 0x81, 2,
	0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 8, 0x95, 1, 0x81, 6, 0xc0, 0xc0,
}

func (d *usbHID) reportDescriptor() []byte {
	if d.pointer {
		return usbPointerDescriptor
	}
	return usbKeyboardDescriptor
}
func usbString(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := []byte{byte(2 + len(units)*2), 3}
	for _, v := range units {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}
func (d *usbHID) descriptor(kind, index byte) []byte {
	hid := []byte{9, 0x21, 0x11, 1, 0, 1, 0x22, byte(len(d.reportDescriptor())), 0}
	switch kind {
	case 1:
		product := byte(0x10)
		if d.pointer {
			product = 0x11
		}
		return []byte{18, 1, 0x10, 1, 0, 0, 0, 8, 0x34, 0x12, product, 0xcc, 0, 1, 1, 2, 0, 1}
	case 2:
		sub, proto := byte(1), byte(1)
		if d.pointer {
			sub, proto = 0, 0
		}
		out := []byte{9, 2, 34, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, sub, proto, 0}
		out = append(out, hid...)
		return append(out, 7, 5, 0x81, 3, byte(len(d.report)), 0, 10)
	case 3:
		switch index {
		case 0:
			return []byte{4, 3, 9, 4}
		case 1:
			return usbString("TinyRangeX")
		case 2:
			if d.pointer {
				return usbString("trex absolute pointer")
			}
			return usbString("trex USB keyboard")
		}
	case 0x21:
		return hid
	case 0x22:
		return d.reportDescriptor()
	}
	return nil
}

func (d *usbHID) setup(data []byte) bool {
	if len(data) != 8 {
		return false
	}
	copy(d.request[:], data)
	d.reply = nil
	d.replyOffset = 0
	d.output = nil
	d.stalled = false
	d.addressPending = false
	typ, request := data[0], data[1]
	value, index, length := binary.LittleEndian.Uint16(data[2:]), binary.LittleEndian.Uint16(data[4:]), binary.LittleEndian.Uint16(data[6:])
	d.controls++
	row := map[string]any{"type": int(typ), "request": int(request), "value": int(value), "index": int(index), "length": int(length)}
	if len(d.trace) == 32 {
		d.trace = d.trace[1:]
	}
	d.trace = append(d.trace, row)
	switch typ & 0x60 {
	case 0:
		switch request {
		case 6:
			if typ&0x80 == 0 {
				d.stalled = true
				break
			}
			d.reply = d.descriptor(byte(value>>8), byte(value))
			d.stalled = d.reply == nil
		case 5:
			if typ != 0 || value > 127 || index != 0 || length != 0 {
				d.stalled = true
				break
			}
			d.pendingAddress = byte(value)
			d.addressPending = true
		case 9:
			if typ != 0 || value > 1 || index != 0 || length != 0 {
				d.stalled = true
				break
			}
			d.configuration = byte(value)
			d.pending = nil
			if value != 0 {
				d.pending = append(d.pending, append([]byte(nil), d.report...))
			}
		case 8:
			d.reply = []byte{d.configuration}
		case 0:
			d.reply = []byte{0, 0}
		case 1: // Endpoint CLEAR_FEATURE(HALT).
			d.stalled = typ != 2 || value != 0
		case 10:
			d.reply = []byte{0} // GET_INTERFACE
		case 11:
			d.stalled = value != 0 || index != 0 // SET_INTERFACE
		default:
			d.stalled = true
		}
	case 0x20:
		if index != 0 {
			d.stalled = true
			break
		}
		switch request {
		case 1:
			d.reply = append([]byte(nil), d.report...) // GET_REPORT
		case 2:
			d.reply = []byte{d.idle}
		case 3:
			d.reply = []byte{d.protocol}
		case 9:
			d.stalled = length > 8 // SET_REPORT (keyboard LEDs).
		case 10:
			d.idle = byte(value >> 8)
		case 11:
			if value > 1 {
				d.stalled = true
			} else {
				d.protocol = byte(value)
			}
		default:
			d.stalled = true
		}
	default:
		d.stalled = true
	}
	if len(d.reply) > int(length) {
		d.reply = d.reply[:length]
	}
	return !d.stalled
}

// transaction returns USB ACK/NAK/STALL as 0/1/2. Control status applies the
// pending address only after successful completion, so address zero remains
// valid throughout SET_ADDRESS. Interrupt queues preserve every transition.
func (d *usbHID) transaction(pid byte, endpoint byte, data []byte) (int, int) {
	if pid == 0x2d {
		if endpoint == 0 && d.setup(data) {
			return len(data), 0
		}
		return 0, 2
	}
	if endpoint == 1 && pid == 0x69 {
		if d.configuration == 0 || len(d.pending) == 0 {
			return 0, 1
		}
		if len(data) < len(d.pending[0]) {
			return 0, 2
		}
		n := copy(data, d.pending[0])
		d.pending = d.pending[1:]
		d.reports++
		return n, 0
	}
	if endpoint != 0 || d.stalled {
		return 0, 2
	}
	input := d.request[0]&0x80 != 0
	length := int(binary.LittleEndian.Uint16(d.request[6:]))
	if pid == 0x69 && (input && length != 0) {
		n := copy(data, d.reply[d.replyOffset:])
		d.replyOffset += n
		return n, 0
	}
	if pid == 0xe1 && !input && length != 0 {
		if len(d.output)+len(data) > length || len(d.output)+len(data) > 8 {
			return 0, 2
		}
		d.output = append(d.output, data...)
		return len(data), 0
	}
	if (pid == 0x69 && !input) || (pid == 0xe1 && input && len(data) == 0) {
		if d.addressPending {
			d.address = d.pendingAddress
			d.addressPending = false
		}
		return 0, 0
	}
	return 0, 2
}
func (d *usbHID) enqueue(report []byte) error {
	if d.configuration == 0 {
		return fmt.Errorf("USB HID device is not configured")
	}
	if len(d.pending) >= 1024 {
		return fmt.Errorf("USB HID report queue full")
	}
	d.report = append(d.report[:0], report...)
	d.pending = append(d.pending, append([]byte(nil), report...))
	return nil
}

var usbKeys = map[string]byte{
	"enter": 40, "ret": 40, "esc": 41, "escape": 41, "backspace": 42, "tab": 43, "space": 44, "spc": 44,
	"minus": 45, "equal": 46, "bracket_left": 47, "bracket_right": 48, "backslash": 49,
	"semicolon": 51, "apostrophe": 52, "grave_accent": 53, "comma": 54, "dot": 55, "slash": 56, "caps_lock": 57,
	"insert": 73, "home": 74, "pgup": 75, "delete": 76, "end": 77, "pgdn": 78, "right": 79, "left": 80, "down": 81, "up": 82,
	"ctrl": 224, "control": 224, "shift": 225, "alt": 226, "meta_l": 227, "ctrl_r": 228, "shift_r": 229, "alt_r": 230, "meta_r": 231,
}

func usbKey(name string) (byte, bool) {
	name = strings.ToLower(name)
	if len(name) == 1 && name[0] >= 'a' && name[0] <= 'z' {
		return name[0] - 'a' + 4, true
	}
	if len(name) == 1 && name[0] >= '1' && name[0] <= '9' {
		return name[0] - '1' + 30, true
	}
	if name == "0" {
		return 39, true
	}
	for n := 1; n <= 12; n++ {
		if name == fmt.Sprintf("f%d", n) {
			return byte(57 + n), true
		}
	}
	v, ok := usbKeys[name]
	return v, ok
}
func (d *usbHID) key(name string, down bool) error {
	code, ok := usbKey(name)
	if !ok {
		return fmt.Errorf("unknown USB keyboard key %q", name)
	}
	r := append([]byte(nil), d.report...)
	if code >= 224 {
		bit := byte(1 << (code - 224))
		if down {
			r[0] |= bit
		} else {
			r[0] &^= bit
		}
	} else {
		found := false
		for i := 2; i < 8; i++ {
			if r[i] == code {
				found = true
				if !down {
					r[i] = 0
				}
			}
		}
		if down && !found {
			inserted := false
			for i := 2; i < 8; i++ {
				if r[i] == 0 {
					r[i] = code
					inserted = true
					break
				}
			}
			if !inserted {
				return fmt.Errorf("USB boot keyboard supports six simultaneous keys")
			}
		}
	}
	return d.enqueue(r)
}
func (d *usbHID) point(x, y uint16, buttons byte, wheel int) error {
	r := []byte{buttons, byte(x), byte(x >> 8), byte(y), byte(y >> 8), byte(wheel)}
	return d.enqueue(r)
}
