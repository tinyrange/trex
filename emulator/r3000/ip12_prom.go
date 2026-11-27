package r3000

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	ip12PROMPrintf   = 0xbfc00080
	ip12PROMEaddr    = 0xbfc001a8
	ip12PROMNVRAMTab = 0xbfc001d0
)

var ip12EthernetAddress = [6]byte{0x08, 0x00, 0x69, 0x00, 0x00, 0x01}

func (m *IP12) promRAM(address, size uint32, write bool) []byte {
	if size == 0 || uint64(address)+uint64(size) > 1<<32 {
		return nil
	}
	x := instruction{exception: -1}
	physical, _ := m.cpu.translate(address, write, &x)
	if x.exception >= 0 {
		return nil
	}
	last := address + size - 1
	if address>>12 != last>>12 {
		end, _ := m.cpu.translate(last, write, &x)
		if x.exception >= 0 || end != physical+size-1 {
			return nil
		}
	}
	return m.pic.memory(physical, size)
}

func (m *IP12) promWrite(address uint32, data []byte) bool {
	if m.promRAM(address, uint32(len(data)), true) == nil {
		return false
	}
	x := instruction{exception: -1}
	for i, b := range data {
		m.cpu.access(m, address+uint32(i), 1, true, false, uint32(b), &x)
		if x.exception >= 0 {
			return false
		}
	}
	return true
}

func (m *IP12) promString(address uint32) (string, error) {
	var out strings.Builder
	for i := uint32(0); i < 4096; i++ {
		b := m.promRAM(address+i, 1, false)
		if b == nil {
			return "", fmt.Errorf("ip12 PROM: invalid string at %#x", address)
		}
		if b[0] == 0 {
			return out.String(), nil
		}
		out.WriteByte(b[0])
	}
	return "", fmt.Errorf("ip12 PROM: unterminated string at %#x", address)
}

func (m *IP12) promPrintf() (uint32, error) {
	format, err := m.promString(m.cpu.gpr[4])
	if err != nil {
		return 0, err
	}
	var out strings.Builder
	arg := uint32(1)
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			out.WriteByte(format[i])
			continue
		}
		i++
		if i < len(format) && format[i] == '%' {
			out.WriteByte('%')
			continue
		}
		start := i
		for i < len(format) && (format[i] == '-' || format[i] == ' ' || format[i] == '+' || format[i] == '#') {
			i++
		}
		width := i
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
		if i > width {
			if n, err := strconv.Atoi(format[width:i]); err != nil || n > 256 {
				return 0, fmt.Errorf("ip12 PROM: oversized printf field")
			}
		}
		end := i
		if i < len(format) && format[i] == 'l' {
			i++ // o32 long is a word.
		}
		if i == len(format) {
			return 0, fmt.Errorf("ip12 PROM: incomplete printf conversion")
		}
		var word uint32
		if arg < 4 {
			word = m.cpu.gpr[4+arg]
		} else {
			buf := m.promRAM(m.cpu.gpr[29]+4*arg, 4, false)
			if buf == nil {
				return 0, fmt.Errorf("ip12 PROM: printf argument outside RAM")
			}
			word = binary.BigEndian.Uint32(buf)
		}
		arg++
		verb := format[i]
		var value any
		switch verb {
		case 'd', 'i':
			verb, value = 'd', int32(word)
		case 'u':
			verb, value = 'd', word
		case 'x', 'X', 'o', 'c':
			value = word
		case 'p':
			out.WriteString("0x")
			verb, value = 'x', word
		case 's':
			value, err = m.promString(word)
			if err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("ip12 PROM: unsupported printf conversion %%%c", verb)
		}
		fmt.Fprintf(&out, "%"+format[start:end]+string(verb), value)
		if out.Len() > 1<<16 {
			return 0, fmt.Errorf("ip12 PROM: printf output exceeds 64 KiB")
		}
	}
	n, err := m.scc[1].ports[1].stream.WriteAvailable([]byte(out.String()))
	return uint32(n), err
}

// promCall handles pre-ARCS services supplied when a standalone executable
// is loaded directly. A caller-supplied PROM always executes as guest code.
func (m *IP12) promCall() (bool, error) {
	var result uint32
	switch m.cpu.pc {
	case ip12PROMPrintf:
		var err error
		result, err = m.promPrintf()
		if err != nil {
			return false, err
		}
	case ip12PROMEaddr:
		dst := m.cpu.gpr[4]
		if !m.promWrite(dst, ip12EthernetAddress[:]) {
			return false, fmt.Errorf("ip12 PROM: Ethernet address destination %#x is not mapped RAM", dst)
		}
		result = dst
	case ip12PROMNVRAMTab:
		dst, size := m.cpu.gpr[4], m.cpu.gpr[5]
		if size == 0 || size > 4096 {
			result = ^uint32(0)
			break
		}
		// A table terminated at its first entry has no exported variables.
		if !m.promWrite(dst, make([]byte, size)) {
			return false, fmt.Errorf("ip12 PROM: NVRAM table destination %#x is not mapped RAM", dst)
		}
	default:
		return false, nil
	}
	m.cpu.gpr[2] = result
	m.cpu.pc, m.cpu.next, m.cpu.delaySlot = m.cpu.gpr[31], m.cpu.gpr[31]+4, false
	return true, nil
}
