package main

func inputWord(data []byte, at int) uint16 { return uint16(data[at]) | uint16(data[at+1])<<8 }

// Validate the whole gesture before installing a global hook. Windows 1.x
// enters modal tracking on a button press, so down/moves/up must be queued
// together, not split into synchronous serial calls that would deadlock.
func validInputEvents(data []byte, width, height uint16) bool {
	n := len(data)
	var keys [256]byte
	if n == 0 || n > 240 || n%6 != 0 {
		return false
	}
	for i := 0; i < len(keys); i++ {
		keys[i] = 0
	}
	buttons := uint16(0)
	held := 0
	for i := 0; i < n; i += 6 {
		message, low, high := inputWord(data, i), inputWord(data, i+2), inputWord(data, i+4)
		if message >= 0x200 && message <= 0x205 && message != 0x203 {
			if low >= width || high >= height {
				return false
			}
			bit := uint16(1)
			if message >= 0x204 {
				bit = 2
			}
			if message == 0x201 || message == 0x204 {
				if buttons&bit != 0 {
					return false
				}
				buttons |= bit
			}
			if message == 0x202 || message == 0x205 {
				if buttons&bit == 0 {
					return false
				}
				buttons &^= bit
			}
		} else if message == 0x100 || message == 0x101 {
			if low == 0 || low > 255 || high > 255 {
				return false
			}
			if message == 0x100 {
				if keys[low] != 0 {
					return false
				}
				keys[low] = 1
				held++
			} else {
				if keys[low] == 0 {
					return false
				}
				keys[low] = 0
				held--
			}
		} else {
			return false
		}
	}
	return buttons == 0 && held == 0
}
