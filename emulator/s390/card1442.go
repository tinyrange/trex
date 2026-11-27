package s390

import "time"

// A 1442 has one feed path through a read and a punch station.
func (u *UnitRecord) exec1442(cmd byte, data []byte) ([]byte, int, byte) {
	switch cmd &^ 0x20 {
	case 0x01, 0x02, 0x03, 0x81, 0x83:
	default:
		return u.reject()
	}
	const ok = usCE | usDE
	if cmd == 0x23 {
		return nil, 0, ok
	}
	if u.punchStopped || cmd&3 != 1 && len(u.cards) == 0 {
		u.sense = senseIntReq
		return nil, 0, usUnitCheck
	}
	u.sense = 0
	var out []byte
	var n int
	status := byte(ok)
	switch cmd & 3 {
	case 1:
		if u.card1442 == nil {
			return nil, 0, ok
		}
		n = min(len(data), 80-u.column1442)
		for _, symbol := range data[:n] {
			punch := ebcdicPunch[symbol]
			off := 2 * u.column1442
			u.card1442[off] |= byte(punch >> 6)
			u.card1442[off+1] |= byte(punch & 0x3f)
			u.column1442++
		}
		u.chanT = urControlXfr + time.Duration(n)*6250*time.Microsecond
		if cmd&0x80 == 0 {
			u.version++
			return nil, n, ok
		}
	case 2:
		out = u.cards[0]
		if len(out) == 160 {
			out, u.sense = readCardColumns(out, false)
			if u.sense != 0 {
				status |= usUnitCheck
			}
		}
		u.chanT = urControlXfr + time.Duration(len(out))*urByte
	}
	u.stack1442((cmd >> 5) & 1)
	if len(u.cards) != 0 {
		card := u.cards[0]
		if len(card) == 160 {
			u.card1442 = append([]byte(nil), card...)
		} else {
			u.card1442 = make([]byte, 160)
			for i, symbol := range card {
				rows := ebcdicPunch[symbol]
				u.card1442[2*i], u.card1442[2*i+1] = byte(rows>>6), byte(rows&0x3f)
			}
		}
		u.cards = u.cards[1:]
		if len(u.cards) == 0 && u.eof {
			u.eof = false
			status |= usUnitExcept
		}
	}
	u.version++
	u.devT = 150*time.Millisecond - 80*urByte // 400 cards per minute
	return out, n, status
}

func (u *UnitRecord) stack1442(stacker byte) {
	if u.card1442 == nil {
		return
	}
	u.readStackers[stacker]++
	u.column1442, u.card1442 = 0, nil
}
