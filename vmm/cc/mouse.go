package cc

// Standard three-button PS/2 mouse attached to the i8042 auxiliary port.
func (k *keyboard) mouseCommand(v byte) error {
	if k.mouseParameter != 0 {
		if k.mouseParameter == 0xf3 {
			k.mouseRate = v
		} else {
			k.mouseResolution = v & 3
		}
		k.mouseParameter = 0
		return k.enqueue(true, 0xfa)
	}
	switch v {
	case 0xff:
		k.mouseEnabled = false
		k.mouseRemote = false
		k.mouseScaling = false
		k.mouseRate = 100
		k.mouseResolution = 2
		k.mouseButtons = 0
		return k.enqueue(true, 0xfa, 0xaa, 0)
	case 0xf6:
		k.mouseEnabled = false
		k.mouseRemote = false
		k.mouseScaling = false
		k.mouseRate = 100
		k.mouseResolution = 2
	case 0xf5:
		k.mouseEnabled = false
	case 0xf4:
		k.mouseEnabled = true
	case 0xf3, 0xe8:
		k.mouseParameter = v
	case 0xf2:
		return k.enqueue(true, 0xfa, 0)
	case 0xf0:
		k.mouseRemote = true
	case 0xea:
		k.mouseRemote = false
	case 0xe6:
		k.mouseScaling = false
	case 0xe7:
		k.mouseScaling = true
	case 0xe9:
		status := (k.mouseButtons&1)<<2 | (k.mouseButtons&2)>>1 | (k.mouseButtons&4)>>1
		if k.mouseEnabled {
			status |= 0x20
		}
		if k.mouseRemote {
			status |= 0x40
		}
		if k.mouseScaling {
			status |= 0x10
		}
		return k.enqueue(true, 0xfa, status, k.mouseResolution, k.mouseRate)
	case 0xeb:
		return k.enqueue(true, 0xfa, 8|k.mouseButtons, 0, 0)
	default:
		return k.enqueue(true, 0xfe)
	}
	return k.enqueue(true, 0xfa)
}
func (k *keyboard) mouseMove(dx, dy int, buttons byte) error {
	changed := buttons != k.mouseButtons
	k.mouseButtons = buttons
	if !k.mouseEnabled || k.mouseRemote || k.command&0x20 != 0 {
		return nil
	}
	for dx != 0 || dy != 0 || changed {
		x, y := max(-255, min(255, dx)), max(-255, min(255, dy))
		flags := byte(8) | buttons
		if x < 0 {
			flags |= 0x10
		}
		if y < 0 {
			flags |= 0x20
		}
		if err := k.enqueue(true, flags, byte(x), byte(y)); err != nil {
			return err
		}
		dx -= x
		dy -= y
		changed = false
	}
	return nil
}
