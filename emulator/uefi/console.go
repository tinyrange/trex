package uefi

import "encoding/binary"

// The text console is an event sink with EFI-visible mode and cursor state.
// Consumers may render these events independently of the interpreter backend.
func (m *Machine) textCall(name string, a [8]uint64) uint64 {
	console := m.ramBase + 0xd00
	if a[0] != console {
		return invalidParameter
	}
	mode := console + 80
	read32 := func(offset uint64) uint32 {
		b := m.get(mode+offset, 4)
		if len(b) != 4 {
			return 0
		}
		return binary.LittleEndian.Uint32(b)
	}
	clear := func() { m.u32(mode+12, 0); m.u32(mode+16, 0); m.emit(Event{Kind: "console", Name: "clear"}) }
	switch name {
	case "Text.Reset":
		m.u32(mode+4, 0)
		m.u32(mode+8, 7)
		m.u32(mode+20, 1)
		clear()
	case "Text.SetMode":
		if a[1] != 0 {
			return unsupported
		}
		m.u32(mode+4, 0)
		clear()
	case "Text.SetAttribute":
		if a[1] > 127 {
			return unsupported
		}
		m.u32(mode+8, uint32(a[1]))
	case "Text.ClearScreen":
		clear()
	case "Text.SetCursorPosition":
		if a[1] >= 80 || a[2] >= 25 {
			return unsupported
		}
		m.u32(mode+12, uint32(a[1]))
		m.u32(mode+16, uint32(a[2]))
	case "Text.EnableCursor":
		if a[1] > 1 {
			return invalidParameter
		}
		m.u32(mode+20, uint32(a[1]))
	case "Text.QueryMode":
		if a[1] != 0 {
			return unsupported
		}
		if a[2] == 0 || a[3] == 0 {
			return invalidParameter
		}
		m.u64(a[2], 80)
		m.u64(a[3], 25)
	case "Text.TestString":
		m.text(a[1])
	case "Text.OutputString":
		text := m.text(a[1])
		column, row := read32(12), read32(16)
		for _, r := range text {
			switch r {
			case '\r':
				column = 0
			case '\n':
				row++
			case '\b':
				if column > 0 {
					column--
				}
			default:
				column++
				if column >= 80 {
					column = 0
					row++
				}
			}
			if row >= 25 {
				row = 24
			}
		}
		m.u32(mode+12, column)
		m.u32(mode+16, row)
		m.emit(Event{Kind: "console", Name: "output", Text: text})
	}
	return 0
}
