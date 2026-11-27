package r3000

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"math/bits"
	"time"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/vmm/ethernet"
)

const cyclesPerSecond = 25_000_000
const romSize = 128 << 10

// Config supplies immutable firmware files and the virtual clock epoch.
// Devices advance in guest cycles, independently of host scheduling.
type Config struct {
	Memory                int
	ROM, NVRAM, StationID storage.Reader
	Start                 time.Time
}

type Stop struct {
	Kind                               string
	PC, Instruction, Address, Physical uint32
	Value                              uint32
	Exception                          int
	Store                              bool
	Cycles                             uint64
}

type writeWatch struct {
	address uint32
	end     uint64
	nonzero bool
}

type Machine struct {
	cpu                                 cpu
	ram, rom, video                     []byte
	nvram                               [0x2000]byte
	station                             [0x1000]byte
	paletteWritten                      [256]bool
	g300, cursor                        [0x1000]byte
	board                               [0x48]uint32
	ioCache                             [8]ioCacheBlock
	ioPending                           byte
	irqEnable                           uint16
	led                                 byte
	timerPeriod, timerNext, retraceNext uint64
	timerIRQ, videoIRQ                  bool
	uart                                [2]serialPort
	keyboard                            keyboard
	sound                               soundController
	floppy                              floppyController
	parallelData, parallelControl       byte
	rtc                                 rtc
	sonic                               sonic
	scsi                                scsiController
	net                                 ethernet.Endpoint
	serverPort                          ethernet.Endpoint
	epoch                               time.Time
	mop                                 *mopServer
	breaks                              map[uint32]bool
	watch                               *writeWatch
	watchHit                            Stop
	cycles                              uint64
	fault                               error
	closed                              bool
}

func NewMachine(config Config) (*Machine, error) {
	if config.Memory == 0 {
		config.Memory = 64 << 20
	}
	if config.Memory < 1<<20 || config.Memory > 256<<20 || config.Memory&4095 != 0 {
		return nil, fmt.Errorf("r3000: memory must be 1–256 MiB in 4 KiB pages")
	}
	m := &Machine{cpu: newCPU(), ram: make([]byte, config.Memory), video: make([]byte, 2<<20), breaks: make(map[uint32]bool)}
	m.rom = bytes.Repeat([]byte{0xff}, romSize)
	if err := readSeed(m.rom, config.ROM, false); err != nil {
		return nil, fmt.Errorf("r3000 ROM: %w", err)
	}
	copy(m.nvram[:], bytes.Repeat([]byte{0xff}, len(m.nvram)))
	copy(m.station[:], bytes.Repeat([]byte{0xff}, len(m.station)))
	copy(m.station[:], []byte{2, 0, 0x4a, 0x41, 0x5a, 0x5a, 0, 0xbd})
	if err := readSeed(m.nvram[:], config.NVRAM, true); err != nil {
		return nil, fmt.Errorf("r3000 system NVRAM: %w", err)
	}
	if err := readSeed(m.station[:], config.StationID, true); err != nil {
		return nil, fmt.Errorf("r3000 station NVRAM: %w", err)
	}
	m.board[0], m.board[1], m.board[0x210/8], m.board[0x220/8] = 0x104, 0xf0000000, 0x18186, 7
	for offset := 0x70; offset < 0xf0; offset += 8 {
		m.board[offset/8] = 7
	}
	for i := range m.uart {
		guest, host, err := channel.NewMemoryPair(1 << 20)
		if err != nil {
			return nil, err
		}
		m.uart[i] = serialPort{guest: guest, host: host, txIRQ: true}
	}
	m.sonic.reset()
	m.scsi.reg[8] = 7
	m.scsi.reset()
	if config.Start.IsZero() {
		config.Start = time.Date(1991, 4, 1, 0, 0, 0, 0, time.UTC)
	}
	m.epoch = config.Start
	m.rtc.init(config.Start)
	m.keyboard.init()
	return m, nil
}

func readSeed(dst []byte, source storage.Reader, exact bool) error {
	if source == nil {
		return nil
	}
	size := source.Size()
	if size <= 0 || size > int64(len(dst)) || exact && size != int64(len(dst)) {
		return fmt.Errorf("invalid seed size %d for %d-byte device", size, len(dst))
	}
	_, err := block.ReadFullAt(source, dst[:size], 0)
	return err
}

func (m *Machine) Close() error {
	if !m.closed {
		m.closed = true
		for i := range m.uart {
			_ = m.uart[i].guest.Close()
			_ = m.uart[i].host.Close()
		}
		if m.net != nil {
			_ = m.serverPort.Close()
			return m.net.Close()
		}
	}
	return nil
}

func (m *Machine) Serial(port int) (channel.ByteChannel, error) {
	if port < 1 || port > len(m.uart) || m.closed {
		return nil, fmt.Errorf("r3000: COM%d unavailable", port)
	}
	return m.uart[port-1].host, nil
}

func (m *Machine) BreakAt(address uint32) error {
	if address&3 != 0 {
		return fmt.Errorf("r3000: unaligned breakpoint %#x", address)
	}
	m.breaks[address] = true
	return nil
}

// WatchWrite stops after the next committed CPU write in the physical range.
func (m *Machine) WatchWrite(address, size uint32, nonzero bool) error {
	end := uint64(address) + uint64(size)
	if size == 0 || end > 1<<32 {
		return fmt.Errorf("r3000: invalid write watch range")
	}
	m.watch = &writeWatch{address: address, end: end, nonzero: nonzero}
	m.watchHit = Stop{}
	return nil
}

func (m *Machine) ClearWatch() {
	m.watch = nil
	m.watchHit = Stop{}
}

func (m *Machine) recordWrite(address, size, value uint32) {
	watch := m.watch
	if watch == nil || uint64(address) >= watch.end || uint64(address)+uint64(size) <= uint64(watch.address) {
		return
	}
	value &= uint32(0xffffffff) >> (32 - size*8)
	if watch.nonzero {
		first := max(uint64(address), uint64(watch.address)) - uint64(address)
		end := min(uint64(address)+uint64(size), watch.end) - uint64(address)
		mask := uint32(0xffffffff) >> (32 - (end-first)*8)
		if value>>(first*8)&mask == 0 {
			return
		}
	}
	m.watchHit = Stop{Kind: "write_watch", PC: m.cpu.pc, Physical: address, Value: value, Store: true}
	m.watch = nil
}

func (m *Machine) Run(ctx context.Context, budget uint64, stopOnException bool) (Stop, error) {
	if m.closed {
		return Stop{}, fmt.Errorf("r3000: machine closed")
	}
	start := m.cycles
	for i := uint64(0); i < budget; i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return Stop{}, err
			}
		}
		if m.breaks[m.cpu.pc] {
			return Stop{Kind: "breakpoint", PC: m.cpu.pc, Cycles: m.cycles - start}, nil
		}
		stop := m.step()
		if m.watchHit.Kind != "" {
			hit := m.watchHit
			m.watchHit = Stop{}
			hit.Instruction, hit.Cycles = stop.Instruction, m.cycles-start
			return hit, nil
		}
		if m.fault != nil {
			return stop, m.fault
		}
		if stop.Kind == "exception" && (stopOnException || stop.Exception == 6 || stop.Exception == 7 || stop.Exception == 10) {
			stop.Cycles = m.cycles - start
			return stop, nil
		}
	}
	return Stop{Kind: "budget", PC: m.cpu.pc, Cycles: m.cycles - start}, nil
}

// Read copies bytes from physical memory without triggering device effects.
func (m *Machine) Read(address uint32, out []byte) error {
	for _, region := range []struct {
		base uint32
		data []byte
	}{
		{0, m.ram},
		{0x1fc00000, m.rom},
		{0xfff00000, m.rom},
		{0x40000000, m.video},
		{0x60000000, m.g300[:]},
	} {
		if address >= region.base && uint64(address-region.base)+uint64(len(out)) <= uint64(len(region.data)) {
			copy(out, region.data[address-region.base:])
			return nil
		}
	}
	return fmt.Errorf("r3000: physical memory read outside mapped ranges at %#x", address)
}

// ReadEffective copies mapped memory through the current CPU translation without
// changing exception registers or invoking device read side effects.
func (m *Machine) ReadEffective(address uint32, out []byte) error {
	return m.cpu.readEffective(address, out, m.Read)
}

func loadLE(p []byte, size uint32) uint32 {
	switch size {
	case 1:
		return uint32(p[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(p))
	default:
		return binary.LittleEndian.Uint32(p)
	}
}

func storeLE(p []byte, size, value uint32) {
	switch size {
	case 1:
		p[0] = byte(value)
	case 2:
		binary.LittleEndian.PutUint16(p, uint16(value))
	default:
		binary.LittleEndian.PutUint32(p, value)
	}
}

func inRange(address, size, base, length uint32) bool {
	return address >= base && uint64(address-base)+uint64(size) <= uint64(length)
}

func (m *Machine) readBus(address, size uint32) (uint32, bool) {
	if inRange(address, size, 0, uint32(len(m.ram))) {
		if m.ioPending != 0 {
			m.flushIO(address, size)
		}
		return loadLE(m.ram[address:], size), true
	}
	for _, base := range [...]uint32{0x1fc00000, 0xfff00000} {
		if inRange(address, size, base, romSize) {
			return loadLE(m.rom[address-base:], size), true
		}
	}
	return m.mmio(address, size, 0, false)
}

func (m *Machine) writeBus(address, size, value uint32) bool {
	if inRange(address, size, 0, uint32(len(m.ram))) {
		if m.ioPending != 0 {
			m.flushIO(address, size)
		}
		storeLE(m.ram[address:], size, value)
		m.recordWrite(address, size, value)
		return true
	}
	_, ok := m.mmio(address, size, value, true)
	if ok {
		m.recordWrite(address, size, value)
	}
	return ok
}

func (m *Machine) step() Stop {
	m.updateInterrupts()
	result := m.cpu.step(m)
	m.cycles++
	return result
}

func (m *Machine) updateInterrupts() {
	if m.sound.registers[0]&1 != 0 {
		m.sound.tick(m)
	}
	if m.keyboard.deadline != 0 {
		m.keyboard.tick(m.cycles)
	}
	if m.floppy.deadline != 0 {
		m.floppy.tick(m.cycles)
	}
	if m.scsi.dmaWaiting {
		m.scsi.transferDMA(m)
	}
	if m.sonic.reg[sonicCommand]&0x20 != 0 {
		m.sonic.tick(m.cycles)
	}
	if m.cycles&63 == 0 {
		for i := range m.uart {
			if m.uart[i].ier&1 != 0 {
				m.uart[i].poll()
			}
		}
		m.mopTick()
		if m.net != nil {
			for frame := m.net.Receive(); frame != nil; frame = m.net.Receive() {
				m.sonic.receive(m, frame)
			}
		}
	}
	if m.timerPeriod != 0 && m.cycles >= m.timerNext {
		m.timerIRQ = true
		m.timerNext += m.timerPeriod
	}
	if m.retraceNext != 0 && m.cycles >= m.retraceNext {
		m.videoIRQ = true
		m.retraceNext += m.retracePeriod()
	}
	m.cpu.cp0[cause] &^= 1<<11 | 1<<14 | 1<<15
	if m.timerIRQ {
		m.cpu.cp0[cause] |= 1 << 14
	}
	if m.irqEnable != 0 && m.irqSource() != 0 {
		m.cpu.cp0[cause] |= 1 << 11
	}
	if m.cpu.fcsr>>12&m.cpu.fcsr>>7&31 != 0 {
		m.cpu.cp0[cause] |= 1 << 15
	}
}

func (m *Machine) irqSource() uint32 {
	pending := truth(m.floppy.irq)<<1 | truth(m.sound.irq())<<2 | truth(m.videoIRQ)<<3 | truth(m.sonic.irq())<<4 | truth(m.scsi.interrupt != 0)<<5 |
		truth(m.keyboard.irq(false))<<6 | truth(m.keyboard.irq(true))<<7 | truth(m.uart[0].interrupt() != 1)<<8 | truth(m.uart[1].interrupt() != 1)<<9
	active := uint16(pending) & m.irqEnable
	if active == 0 {
		return 0
	}
	return uint32(bits.TrailingZeros16(active)+1) * 4
}

func (m *Machine) mmio(address, size, value uint32, write bool) (uint32, bool) {
	switch {
	case inRange(address, size, 0x80000000, 0x1000):
		return m.boardIO(address-0x80000000, size, value, write)
	case inRange(address, size, 0x80001000, 0x1000):
		return m.sonic.access(m, address-0x80001000, size, value, write)
	case inRange(address, size, 0x80002000, 16):
		return m.scsi.access(m, address-0x80002000, size, value, write)
	case inRange(address, size, 0x80003000, 8) && size == 1:
		return uint32(m.floppy.access(m.cycles, address&7, byte(value), write)), true
	case address == 0x80004000 && size == 1:
		return uint32(m.rtc.access(m.cycles, byte(value), write)), true
	case address == 0x90000070 && size == 1:
		if write {
			m.rtc.index = byte(value) & 0x7f
		}
		return uint32(m.rtc.index), true
	case inRange(address, size, 0x80005000, 2):
		return uint32(m.keyboard.access(m.cycles, address&1, byte(value), write)), true
	case inRange(address, size, 0x80006000, 8), inRange(address, size, 0x80007000, 8):
		port := &m.uart[(address>>12)&1]
		return uint32(port.access(address&7, byte(value), write)), true
	case inRange(address, size, 0x80008000, 3) && size == 1:
		switch address & 3 {
		case 0:
			if write {
				m.parallelData = byte(value)
			}
			return uint32(m.parallelData), true
		case 1:
			return 0xdf, true
		case 2:
			if write {
				m.parallelControl = byte(value) & 31
			}
			return uint32(0xe0 | m.parallelControl), true
		}
	case inRange(address, size, 0x80009000, 0x2000):
		return memoryIO(m.nvram[address-0x80009000:], size, value, write)
	case inRange(address, size, 0x8000b000, 0x1000):
		if write && m.board[0x220/8]&1 == 0 {
			return 0, true
		}
		return memoryIO(m.station[address-0x8000b000:], size, value, write)
	case inRange(address, size, 0x8000c000, 0x1000):
		return m.sound.access(address-0x8000c000, size, value, write)
	case address == 0x8000f000:
		if write {
			m.led = byte(value)
		}
		return 0, true
	case address == 0xf0000002 && size == 2:
		if write {
			m.irqEnable = uint16(value) & 0x3ff
		}
		return uint32(m.irqEnable), true
	case address == 0xf0000000 && size <= 2:
		source := m.irqSource()
		if write {
			return 0, true
		}
		if source == 16 {
			m.videoIRQ = false
		}
		return source, true
	case inRange(address, size, 0x40000000, uint32(len(m.video))):
		return memoryIO(m.video[address-0x40000000:], size, value, write)
	case inRange(address, size, 0x60000000, 0x1000):
		off := address - 0x60000000
		out, ok := memoryIO(m.g300[off:], size, value, write)
		if write && off < 0x800 && off&7 < 4 {
			m.paletteWritten[off/8] = true
		}
		if write && off == 0xb00 {
			m.retraceNext = 0
			if value&1 != 0 {
				m.retraceNext = m.cycles + m.retracePeriod()
			}
		}
		return out, ok
	case inRange(address, size, 0x60008000, 0x1000):
		return memoryIO(m.cursor[address-0x60008000:], size, value, write)
	}
	return 0, false
}

func memoryIO(p []byte, size, value uint32, write bool) (uint32, bool) {
	if write {
		storeLE(p, size, value)
		return 0, true
	}
	return loadLE(p, size), true
}

func (m *Machine) retracePeriod() uint64 {
	line := uint64(binary.LittleEndian.Uint32(m.g300[0x948:]))
	lines := uint64(binary.LittleEndian.Uint32(m.g300[0x940:])) + uint64(binary.LittleEndian.Uint32(m.g300[0x938:])) + 3*uint64(binary.LittleEndian.Uint32(m.g300[0x930:]))
	pll := binary.LittleEndian.Uint32(m.g300[0xd00:])
	if line == 0 || line > 65535 || lines == 0 || lines > 65535 || pll&0x20 == 0 || pll&31 < 5 {
		return 416667
	}
	return max(1, cyclesPerSecond*line*2*lines/(8125000*uint64(pll&31)))
}

// Screen captures the Jazz 1280 by 1024 indexed framebuffer.
func (m *Machine) Screen() image.Image {
	const width, height = 1280, 1024
	palette := make(color.Palette, 256)
	for i := range palette {
		value := byte(i)
		palette[i] = color.RGBA{value, value, value, 255}
		if m.paletteWritten[i] {
			rgb := m.g300[i*8:]
			palette[i] = color.RGBA{rgb[0], rgb[1], rgb[2], 255}
		}
	}
	result := image.NewPaletted(image.Rect(0, 0, width, height), palette)
	mask := m.g300[0xa00]
	for i := range result.Pix {
		result.Pix[i] = m.video[i] & mask
	}
	return result
}
