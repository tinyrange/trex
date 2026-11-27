package r3000

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/channel"
)

var scanKeys = map[string][2]byte{
	"a": {0x1c, 0x1e}, "b": {0x32, 0x30}, "c": {0x21, 0x2e}, "d": {0x23, 0x20}, "e": {0x24, 0x12}, "f": {0x2b, 0x21},
	"g": {0x34, 0x22}, "h": {0x33, 0x23}, "i": {0x43, 0x17}, "j": {0x3b, 0x24}, "k": {0x42, 0x25}, "l": {0x4b, 0x26},
	"m": {0x3a, 0x32}, "n": {0x31, 0x31}, "o": {0x44, 0x18}, "p": {0x4d, 0x19}, "q": {0x15, 0x10}, "r": {0x2d, 0x13},
	"s": {0x1b, 0x1f}, "t": {0x2c, 0x14}, "u": {0x3c, 0x16}, "v": {0x2a, 0x2f}, "w": {0x1d, 0x11}, "x": {0x22, 0x2d},
	"y": {0x35, 0x15}, "z": {0x1a, 0x2c}, "1": {0x16, 0x02}, "2": {0x1e, 0x03}, "3": {0x26, 0x04}, "4": {0x25, 0x05},
	"5": {0x2e, 0x06}, "6": {0x36, 0x07}, "7": {0x3d, 0x08}, "8": {0x3e, 0x09}, "9": {0x46, 0x0a}, "0": {0x45, 0x0b},
	"-": {0x4e, 0x0c}, "=": {0x55, 0x0d}, "[": {0x54, 0x1a}, "]": {0x5b, 0x1b}, "\\": {0x5d, 0x2b},
	";": {0x4c, 0x27}, "'": {0x52, 0x28}, ",": {0x41, 0x33}, ".": {0x49, 0x34}, "/": {0x4a, 0x35}, "\x60": {0x0e, 0x29},
	" ": {0x29, 0x39}, "enter": {0x5a, 0x1c}, "tab": {0x0d, 0x0f}, "escape": {0x76, 0x01}, "backspace": {0x66, 0x0e},
	"shift": {0x12, 0x2a}, "control": {0x14, 0x1d}, "alt": {0x11, 0x38},
	"shift_r": {0x59, 0x36}, "caps_lock": {0x58, 0x3a},
	"f1": {0x05, 0x3b}, "f2": {0x06, 0x3c}, "f3": {0x04, 0x3d}, "f4": {0x0c, 0x3e},
	"f5": {0x03, 0x3f}, "f6": {0x0b, 0x40}, "f7": {0x83, 0x41}, "f8": {0x0a, 0x42},
	"f9": {0x01, 0x43}, "f10": {0x09, 0x44}, "f11": {0x78, 0x57}, "f12": {0x07, 0x58},
}

var extendedScanKeys = map[string][2]byte{
	"left": {0x6b, 0x4b}, "right": {0x74, 0x4d}, "up": {0x75, 0x48}, "down": {0x72, 0x50},
	"home": {0x6c, 0x47}, "end": {0x69, 0x4f}, "pgup": {0x7d, 0x49}, "pgdn": {0x7a, 0x51},
	"insert": {0x70, 0x52}, "delete": {0x71, 0x53}, "ctrl_r": {0x14, 0x1d}, "alt_r": {0x11, 0x38},
	"meta_l": {0x1f, 0x5b}, "meta_r": {0x27, 0x5c}, "kp_enter": {0x5a, 0x1c},
}

func (m *Machine) Key(key string, down bool) error {
	return m.keyboard.key(m.cycles, key, down)
}

func (k *keyboard) key(cycles uint64, key string, down bool) error {
	key = strings.ToLower(key)
	code, normal := scanKeys[key]
	extended := !normal
	if extended {
		code, normal = extendedScanKeys[key]
	}
	if !normal {
		return fmt.Errorf("r3000: unknown key %q", key)
	}
	if k.command&0x10 != 0 {
		return fmt.Errorf("r3000: keyboard interface disabled")
	}
	var packet [3]byte
	sequence := packet[:0]
	if extended {
		sequence = append(sequence, 0xe0)
	}
	setOne := k.scanSet == 1 || k.command&0x40 != 0
	if setOne {
		if !down {
			code[1] |= 0x80
		}
		sequence = append(sequence, code[1])
	} else {
		if !down {
			sequence = append(sequence, 0xf0)
		}
		sequence = append(sequence, code[0])
	}
	if k.length+len(sequence) > len(k.queue) {
		return fmt.Errorf("r3000: keyboard queue full: %w", channel.ErrWouldBlock)
	}
	k.queueBytes(cycles, false, true, sequence...)
	return nil
}

func (m *Machine) TypeText(text string) error {
	before := m.keyboard
	for _, r := range text {
		key := string(r)
		shift := r >= 'A' && r <= 'Z'
		const shifted = "~!@#$%^&*()_+{}|:\"<>?"
		const base = "\x601234567890-=[]\\;',./"
		if i := strings.IndexRune(shifted, r); i >= 0 {
			key = base[i : i+1]
			shift = true
		}
		switch r {
		case '\n', '\r':
			key = "enter"
		case '\t':
			key = "tab"
		}
		if err := m.typeKey(key, shift); err != nil {
			m.keyboard = before
			return err
		}
	}
	return nil
}

func (m *Machine) typeKey(key string, shift bool) error {
	if shift {
		if err := m.Key("shift", true); err != nil {
			return err
		}
	}
	if err := m.Key(key, true); err != nil {
		return err
	}
	if err := m.Key(key, false); err != nil {
		return err
	}
	if shift {
		return m.Key("shift", false)
	}
	return nil
}

const ps2FrameCycles = cyclesPerSecond * 11 * 60 / 1_000_000

type ps2Byte struct {
	value      byte
	mouse, irq bool
}

type keyboard struct {
	command, controllerPending, keyPending, mousePending, port, scanSet byte
	keyLast                                                             byte
	keyLastValid, lastCommand, system, reporting                        bool
	mouseEnabled, mouseRemote, mouseWrap, mouseScaling                  bool
	mouseResolution, mouseRate                                          byte
	queue                                                               [64]ps2Byte
	length                                                              int
	output                                                              ps2Byte
	full                                                                bool
	deadline                                                            uint64
	frameCycles                                                         uint64
}

func (k *keyboard) init() {
	*k = keyboard{port: 1, scanSet: 2, reporting: true, mouseResolution: 2, mouseRate: 100, frameCycles: ps2FrameCycles}
}

func (k *keyboard) schedule(cycles uint64) {
	if !k.full && k.length > 0 && k.deadline == 0 {
		k.deadline = cycles + k.frameCycles
	}
}

func (k *keyboard) tick(cycles uint64) {
	if k.deadline == 0 || cycles < k.deadline {
		return
	}
	k.deadline = 0
	if k.full || k.length == 0 {
		return
	}
	k.output, k.full = k.queue[0], true
	k.length--
	copy(k.queue[:], k.queue[1:k.length+1])
}

func (k *keyboard) setOutput(value byte, mouse, irq bool) {
	k.output, k.full = ps2Byte{value, mouse, irq}, true
	k.deadline = 0
}

func (k *keyboard) queueBytes(cycles uint64, mouse, irq bool, values ...byte) {
	for _, value := range values {
		if k.length == len(k.queue) {
			break
		}
		k.queue[k.length] = ps2Byte{value, mouse, irq}
		k.length++
	}
	k.schedule(cycles)
}

func (k *keyboard) reply(cycles uint64, irq bool, values ...byte) {
	k.keyLast, k.keyLastValid = values[len(values)-1], true
	k.queueBytes(cycles, false, irq, values...)
}

func (k *keyboard) irq(mouse bool) bool {
	if !k.full || !k.output.irq || k.output.mouse != mouse {
		return false
	}
	mask := byte(1)
	if mouse {
		mask = 2
	}
	return k.command&mask != 0
}

func (k *keyboard) access(cycles uint64, reg uint32, data byte, write bool) byte {
	if !write {
		if reg == 1 {
			status := byte(0x10)
			if k.lastCommand {
				status |= 8
			}
			if k.system || k.command&4 != 0 {
				status |= 4
			}
			if k.full {
				status |= 1
				if k.output.mouse {
					status |= 0x20
				}
			}
			return status
		}
		if !k.full {
			return 0
		}
		value := k.output.value
		k.full = false
		k.schedule(cycles)
		return value
	}
	k.lastCommand = reg == 1
	if k.lastCommand {
		switch data {
		case 0x20:
			k.setOutput(k.command, false, false)
		case 0x60, 0xd1, 0xd2, 0xd3, 0xd4:
			k.controllerPending = data
		case 0xa7:
			k.command |= 0x20
		case 0xa8:
			k.command &^= 0x20
		case 0xaa:
			k.system = true
			k.setOutput(0x55, false, false)
		case 0xa9, 0xab, 0xc0, 0xe0:
			k.setOutput(0, false, false)
		case 0xad:
			k.command |= 0x10
		case 0xae:
			k.command &^= 0x10
		case 0xd0:
			k.setOutput(k.port, false, false)
		}
		return 0
	}
	pending := k.controllerPending
	k.controllerPending = 0
	switch pending {
	case 0x60:
		k.command, k.system = data, data&4 != 0
	case 0xd1:
		k.port = data
	case 0xd2:
		k.setOutput(data, false, true)
	case 0xd3:
		k.setOutput(data, true, true)
	case 0xd4:
		k.mouseCommand(cycles, data)
	default:
		k.keyCommand(cycles, data)
	}
	return 0
}

func (k *keyboard) clearKeyboardQueue() {
	kept := 0
	for _, queued := range k.queue[:k.length] {
		if queued.mouse {
			k.queue[kept] = queued
			kept++
		}
	}
	k.length = kept
}

func (k *keyboard) keyCommand(cycles uint64, data byte) {
	if k.keyPending != 0 {
		command := k.keyPending
		if command < 0xfb || command > 0xfd || data >= 0xf0 {
			k.keyPending = 0
		}
		if command < 0xfb || command > 0xfd || data < 0xf0 {
			if command == 0xf0 && data == 0 {
				k.reply(cycles, false, 0xfa, k.scanSet)
			} else {
				if command == 0xf0 && data <= 3 {
					k.scanSet = data
				}
				k.reply(cycles, command == 0xed, 0xfa)
			}
			return
		}
	}
	if data == 0xf0 || data >= 0xf4 && data <= 0xfd || data == 0xff {
		k.clearKeyboardQueue()
	}
	switch data {
	case 0xee:
		k.reply(cycles, false, 0xee)
	case 0xef, 0xf1:
		k.reply(cycles, false, 0xfe)
	case 0xfe:
		if k.keyLastValid {
			k.queueBytes(cycles, false, false, k.keyLast)
		} else {
			k.queueBytes(cycles, false, false, 0xfe)
		}
	case 0xff:
		k.scanSet, k.reporting = 2, true
		k.reply(cycles, false, 0xfa, 0xaa)
	case 0xf2:
		k.reply(cycles, false, 0xfa, 0xab, 0x83)
	case 0xf4, 0xf6:
		k.reporting = true
		k.reply(cycles, false, 0xfa)
	case 0xf5:
		k.scanSet, k.reporting = 2, false
		k.reply(cycles, false, 0xfa)
	case 0xed, 0xf0, 0xf3, 0xfb, 0xfc, 0xfd:
		k.keyPending = data
		k.reply(cycles, data == 0xed, 0xfa)
	default:
		k.reply(cycles, false, 0xfa)
	}
}

func (k *keyboard) mouseCommand(cycles uint64, data byte) {
	if k.mouseWrap && data != 0xec && data != 0xff {
		k.queueBytes(cycles, true, false, data)
		return
	}
	if k.mousePending != 0 {
		switch k.mousePending {
		case 0xf3:
			if data > 0 {
				k.mouseRate = data
			}
		case 0xe8:
			if data <= 3 {
				k.mouseResolution = data
			}
		}
		k.mousePending = 0
		k.queueBytes(cycles, true, false, 0xfa)
		return
	}
	k.queueBytes(cycles, true, false, 0xfa)
	switch data {
	case 0xff, 0xf6:
		k.mouseResolution, k.mouseRate = 2, 100
		k.mouseEnabled, k.mouseRemote, k.mouseWrap, k.mouseScaling = false, false, false, false
		if data == 0xff {
			k.queueBytes(cycles, true, false, 0xaa, 0)
		}
	case 0xf2:
		k.queueBytes(cycles, true, false, 0)
	case 0xf3, 0xe8:
		k.mousePending = data
	case 0xe9:
		flags := byte(truth(k.mouseEnabled)<<5 | truth(k.mouseRemote)<<6 | truth(k.mouseScaling)<<4)
		k.queueBytes(cycles, true, false, flags, k.mouseResolution, k.mouseRate)
	case 0xeb:
		k.queueBytes(cycles, true, false, 8, 0, 0)
	case 0xf0:
		k.mouseRemote = true
	case 0xea:
		k.mouseRemote = false
	case 0xee:
		k.mouseWrap = true
	case 0xec:
		k.mouseWrap = false
	case 0xe7:
		k.mouseScaling = true
	case 0xe6:
		k.mouseScaling = false
	case 0xf4:
		k.mouseEnabled = true
	case 0xf5:
		k.mouseEnabled = false
	}
}
