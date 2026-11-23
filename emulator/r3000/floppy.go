package r3000

// floppyController models the 82077 with no media inserted. The Jazz ROM and
// NT still reset and probe the controller when booting from Ethernet/SCSI.
type floppyController struct {
	dor, resetStatus, seekStatus byte
	irq                          bool
	deadline                     uint64
	cylinder                     [4]byte
	command                      [9]byte
	commandLength, expected      int
	result                       [7]byte
	readAt, resultLength         int
}

func (f *floppyController) reset(cycles uint64) {
	dor := f.dor
	*f = floppyController{dor: dor, deadline: cycles + cyclesPerSecond/4}
}

func (f *floppyController) tick(cycles uint64) {
	if f.deadline != 0 && cycles >= f.deadline {
		f.deadline = 0
		f.resetStatus = 4
		f.irq = f.dor&8 != 0
	}
}

func (f *floppyController) access(cycles uint64, reg uint32, value byte, write bool) byte {
	if !write {
		switch reg {
		case 2:
			return f.dor
		case 4:
			if f.readAt < f.resultLength {
				return 0xd0
			}
			if f.commandLength != 0 {
				return 0x90
			}
			return 0x80
		case 5:
			if f.readAt >= f.resultLength {
				return 0xff
			}
			out := f.result[f.readAt]
			f.readAt++
			f.irq = false
			return out
		case 7:
			return 0x80
		default:
			return 0
		}
	}
	switch reg {
	case 2:
		if (f.dor^value)&4 != 0 {
			f.reset(cycles)
			if value&4 == 0 {
				f.deadline = 0
			}
		}
		f.dor = value
	case 4:
		if value&0x80 != 0 {
			f.reset(cycles)
		}
	case 5:
		if f.commandLength == 0 {
			switch value & 31 {
			case 3, 0x0f:
				f.expected = 3
			case 4, 7, 0x0a:
				f.expected = 2
			case 5, 6:
				f.expected = 9
			case 0x0d:
				f.expected = 6
			case 0x13:
				f.expected = 4
			default:
				f.expected = 1
			}
		}
		f.command[f.commandLength] = value
		f.commandLength++
		if f.commandLength == f.expected {
			f.execute()
		}
	}
	return 0
}

func (f *floppyController) setResult(values ...byte) {
	f.readAt = 0
	f.resultLength = copy(f.result[:], values)
}

func (f *floppyController) execute() {
	f.commandLength = 0
	unit := f.command[1] & 3
	switch f.command[0] & 31 {
	case 3, 0x13:
	case 4:
		state := f.command[1]&7 | 4
		if f.cylinder[unit] == 0 {
			state |= 0x10
		}
		f.setResult(state)
	case 5, 6, 0x0a, 0x0d:
		f.setResult(0x40|f.command[1]&7, 4, 0, f.cylinder[unit], 0, 1, 2)
		f.irq = f.dor&8 != 0
	case 7, 0x0f:
		f.cylinder[unit] = 0
		if f.command[0]&31 == 0x0f {
			f.cylinder[unit] = f.command[2]
		}
		f.resetStatus = 0
		f.seekStatus = 0x20 | unit
		f.irq = f.dor&8 != 0
	case 8:
		if f.resetStatus != 0 {
			unit = 4 - f.resetStatus
			f.resetStatus--
			f.setResult(0xc0|unit, f.cylinder[unit])
		} else if f.seekStatus != 0 {
			f.setResult(f.seekStatus, f.cylinder[f.seekStatus&3])
			f.seekStatus = 0
		} else {
			f.setResult(0x80)
		}
		f.irq = false
	case 0x10:
		f.setResult(0x90)
	default:
		f.setResult(0x80)
	}
}
