package cc

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

type ps2byte struct {
	value byte
	mouse bool
}

func (d *driver) AbsolutePointer(ctx context.Context) (bool, error) {
	var active bool
	err := d.call(ctx, func() error { active = d.pc.input.active(); return nil })
	return active, err
}

type keyboard struct {
	queue                                        []ps2byte
	command, output, pending, parameter, scanSet byte
	enabled                                      bool
	mouseEnabled, mouseRemote, mouseScaling      bool
	mouseParameter, mouseRate, mouseResolution   byte
	mouseButtons                                 byte
	irq                                          func(uint32, bool) error
}

func newKeyboard(irq func(uint32, bool) error) *keyboard {
	return &keyboard{command: 0x45, output: 3, enabled: true, scanSet: 2, irq: irq}
}
func (k *keyboard) updateIRQ() error {
	var key, mouse bool
	if len(k.queue) != 0 {
		if k.queue[0].mouse {
			mouse = k.command&2 != 0
		} else {
			key = k.command&1 != 0
		}
	}
	if err := k.irq(1, key); err != nil {
		return err
	}
	return k.irq(12, mouse)
}
func (k *keyboard) enqueue(mouse bool, values ...byte) error {
	if len(k.queue)+len(values) > 1024 {
		return fmt.Errorf("PS/2 output queue is full")
	}
	for _, v := range values {
		k.queue = append(k.queue, ps2byte{v, mouse})
	}
	return k.updateIRQ()
}
func (k *keyboard) io(ex hypervisor.X86Exit) error {
	if ex.Size != 1 {
		return fmt.Errorf("i8042 requires byte IO")
	}
	for i := range ex.Data {
		if !ex.Write {
			if ex.Port == 0x64 {
				ex.Data[i] = 4
				if len(k.queue) != 0 {
					ex.Data[i] |= 1
					if k.queue[0].mouse {
						ex.Data[i] |= 0x20
					}
				}
			} else {
				ex.Data[i] = 0
				if len(k.queue) != 0 {
					ex.Data[i] = k.queue[0].value
					k.queue = k.queue[1:]
				}
				// Reading the output buffer deasserts its IRQ. A following
				// queued byte produces a new edge even inside the ISR.
				if err := k.irq(1, false); err != nil {
					return err
				}
				if err := k.irq(12, false); err != nil {
					return err
				}
				if err := k.updateIRQ(); err != nil {
					return err
				}
			}
			continue
		}
		v := ex.Data[i]
		if ex.Port == 0x64 {
			switch v {
			case 0x20:
				if err := k.enqueue(false, k.command); err != nil {
					return err
				}
			case 0x60, 0xd1, 0xd4:
				k.pending = v
			case 0xaa:
				if err := k.enqueue(false, 0x55); err != nil {
					return err
				}
			case 0xab, 0xa9:
				if err := k.enqueue(false, 0); err != nil {
					return err
				}
			case 0xad:
				k.command |= 0x10
			case 0xae:
				k.command &^= 0x10
			case 0xa7:
				k.command |= 0x20
			case 0xa8:
				k.command &^= 0x20
			case 0xd0:
				if err := k.enqueue(false, k.output); err != nil {
					return err
				}
			}
			continue
		}
		switch k.pending {
		case 0x60:
			k.command = v
			k.pending = 0
			if err := k.updateIRQ(); err != nil {
				return err
			}
			continue
		case 0xd1:
			k.output = v
			k.pending = 0
			continue
		case 0xd4:
			k.pending = 0
			if err := k.mouseCommand(v); err != nil {
				return err
			}
			continue
		}
		if k.parameter != 0 {
			command := k.parameter
			k.parameter = 0
			if command == 0xf0 {
				if v == 0 {
					if err := k.enqueue(false, 0xfa, k.scanSet); err != nil {
						return err
					}
					continue
				}
				if v != 1 && v != 2 {
					return fmt.Errorf("unsupported PS/2 scan set %d", v)
				}
				k.scanSet = v
			}
			if err := k.enqueue(false, 0xfa); err != nil {
				return err
			}
			continue
		}
		switch v {
		case 0xff:
			k.enabled = true
			k.scanSet = 2
			if err := k.enqueue(false, 0xfa, 0xaa); err != nil {
				return err
			}
		case 0xf2:
			if err := k.enqueue(false, 0xfa, 0xab, 0x83); err != nil {
				return err
			}
		case 0xed, 0xf3, 0xf0:
			k.parameter = v
			if err := k.enqueue(false, 0xfa); err != nil {
				return err
			}
		case 0xf4:
			k.enabled = true
			if err := k.enqueue(false, 0xfa); err != nil {
				return err
			}
		case 0xf5:
			k.enabled = false
			if err := k.enqueue(false, 0xfa); err != nil {
				return err
			}
		case 0xf6:
			k.enabled = true
			k.scanSet = 2
			if err := k.enqueue(false, 0xfa); err != nil {
				return err
			}
		default:
			if err := k.enqueue(false, 0xfe); err != nil {
				return err
			}
		}
	}
	return nil
}

var scanCodes = map[string]uint16{
	"ctrl_r": 0xe01d, "alt_r": 0xe038, "meta_l": 0xe05b, "meta_r": 0xe05c,
	"esc": 1, "escape": 1, "1": 2, "2": 3, "3": 4, "4": 5, "5": 6, "6": 7, "7": 8, "8": 9, "9": 10, "0": 11, "minus": 12, "equal": 13, "backspace": 14, "tab": 15,
	"q": 16, "w": 17, "e": 18, "r": 19, "t": 20, "y": 21, "u": 22, "i": 23, "o": 24, "p": 25, "bracket_left": 26, "bracket_right": 27, "ret": 28, "enter": 28, "ctrl": 29, "control": 29,
	"a": 30, "s": 31, "d": 32, "f": 33, "g": 34, "h": 35, "j": 36, "k": 37, "l": 38, "semicolon": 39, "apostrophe": 40, "grave_accent": 41, "shift": 42, "backslash": 43,
	"z": 44, "x": 45, "c": 46, "v": 47, "b": 48, "n": 49, "m": 50, "comma": 51, "dot": 52, "slash": 53, "shift_r": 54, "alt": 56, "spc": 57, "space": 57, "caps_lock": 58,
	"f1": 59, "f2": 60, "f3": 61, "f4": 62, "f5": 63, "f6": 64, "f7": 65, "f8": 66, "f9": 67, "f10": 68, "f11": 87, "f12": 88,
	"delete": 0xe053, "home": 0xe047, "end": 0xe04f, "up": 0xe048, "down": 0xe050, "left": 0xe04b, "right": 0xe04d, "pgup": 0xe049, "pgdn": 0xe051, "insert": 0xe052,
}

func (k *keyboard) key(name string, down bool) error {
	code, ok := scanCodes[strings.ToLower(name)]
	if !ok {
		return &vmm.Error{Code: vmm.ErrorInvalid, Message: "unknown keyboard key " + name}
	}
	if !k.enabled || k.command&0x10 != 0 {
		return &vmm.Error{Code: vmm.ErrorState, Message: "guest keyboard is disabled"}
	}
	if k.command&0x40 == 0 && k.scanSet != 1 {
		return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "keyboard input requires translated scan set 1"}
	}
	data := []byte{}
	if code>>8 != 0 {
		data = append(data, byte(code>>8))
	}
	value := byte(code)
	if !down {
		value |= 0x80
	}
	data = append(data, value)
	return k.enqueue(false, data...)
}
func (d *driver) Input(ctx context.Context, input vmm.Input) error {
	if input.Kind == "pointer" {
		if math.IsNaN(input.X) || math.IsNaN(input.Y) || math.IsInf(input.X, 0) || math.IsInf(input.Y, 0) || input.Wheel < -127 || input.Wheel > 127 {
			return &vmm.Error{Code: vmm.ErrorInvalid, Message: "invalid pointer coordinates or wheel delta"}
		}
		if input.Absolute {
			if input.X < 0 || input.X > 32767 || input.Y < 0 || input.Y > 32767 {
				return &vmm.Error{Code: vmm.ErrorInvalid, Message: "absolute pointer coordinates must be in 0..32767"}
			}
			var buttons byte
			for _, name := range input.Buttons {
				switch name {
				case "left":
					buttons |= 1
				case "right":
					buttons |= 2
				case "middle":
					buttons |= 4
				default:
					return &vmm.Error{Code: vmm.ErrorInvalid, Message: "unknown mouse button"}
				}
			}
			return d.call(ctx, func() error {
				return d.pc.input.pointer(uint32(input.X*65535/32767), uint32(input.Y*65535/32767), buttons, int32(input.Wheel))
			})
		}
		if input.Absolute || input.Wheel != 0 {
			return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "cc PS/2 mouse requires relative motion without a wheel"}
		}
		if input.X < -4096 || input.X > 4096 || input.Y < -4096 || input.Y > 4096 {
			return &vmm.Error{Code: vmm.ErrorInvalid, Message: "mouse delta exceeds limit"}
		}
		var buttons byte
		for _, name := range input.Buttons {
			switch name {
			case "left":
				buttons |= 1
			case "right":
				buttons |= 2
			case "middle":
				buttons |= 4
			default:
				return &vmm.Error{Code: vmm.ErrorInvalid, Message: "unknown mouse button"}
			}
		}
		return d.call(ctx, func() error { return d.pc.keyboard.mouseMove(int(input.X), -int(input.Y), buttons) })
	}
	if input.Kind == "key" {
		return d.call(ctx, func() error { return d.pc.keyboard.key(input.Key, input.Down) })
	}
	if input.Kind != "keys" {
		return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "cc input supports key transitions and key chords"}
	}
	for _, key := range input.Keys {
		if _, ok := scanCodes[strings.ToLower(key)]; !ok {
			return &vmm.Error{Code: vmm.ErrorInvalid, Message: "unknown keyboard key " + key}
		}
	}
	if err := d.call(ctx, func() error {
		for _, key := range input.Keys {
			if err := d.pc.keyboard.key(key, true); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	timer := time.NewTimer(50 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
	case <-timer.C:
	}
	// Both attempts execute on the serialized device loop. Track progress
	// there so cancellation racing a completed release cannot duplicate it.
	remaining := len(input.Keys)
	releaseKeys := func() error {
		for remaining > 0 {
			if err := d.pc.keyboard.key(input.Keys[remaining-1], false); err != nil {
				return err
			}
			remaining--
		}
		return nil
	}
	// Cold guest reads may keep the device loop busy for more than a second.
	// Preserve the live caller's deadline; only cancellation starts cleanup.
	err := ctx.Err()
	if err == nil {
		err = d.call(ctx, releaseKeys)
	}
	if ctx.Err() != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = d.call(cleanup, releaseKeys)
		return ctx.Err()
	}
	return err
}
