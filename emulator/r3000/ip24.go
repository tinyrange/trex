package r3000

import (
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"time"

	irix "github.com/tinyrange/trex/binary/irix"
	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/scsi"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

const (
	ip24RAMBase    = 0x08000000
	ip24RAMSize    = 64 << 20
	ip24Clock      = 150_000_000
	ip24HPC        = 0x1fb80000
	ip24MC         = 0x1fa00000
	ip24IOC        = 0x1fbd9800
	ip24SerialPort = 1 // SCC channel B is ttyd1.
)

// IP24 models the 64 MiB R4400 configuration of the SGI Indy. Its
// serial boot path uses the 32-bit ARCS calling convention.
type IP24 struct {
	cpu        r4kCPU
	ram        []byte
	rom        []byte
	console    *channel.Memory
	scc        ip12SCC
	int3       ip12INT
	scsi       wd33c93
	targets    [8]*scsi.Disk
	dma        hpc3SCSI
	mc         [64]uint32
	vdma       mcVDMA
	ioc        [32]byte
	rtc        [8192]byte
	rtcBase    time.Time
	rtcCycles  uint64
	pioConfig  [16]uint32
	pbusConfig [8]uint32
	pbusDMA    [8]hpc3PBUS
	gioMisc    uint32
	ethernet   ip24Ethernet
	keyboard   keyboard
	newport    *newport
	eeprom     ip12EEPROM
	arcs       ip24ARCS
	breaks     map[uint64]bool
	cycles     uint64
	closed     bool
	lastFault  r4kStep
}

type IP24Stop struct {
	Kind                  string
	PC, Address, Physical uint64
	Cycles                uint64
	Instruction           uint32
	Exception             int
	Service               uint32
	Store                 bool
}

func NewIP24(prom storage.Reader) (*IP24, error) {
	return newIP24(prom, false)
}

func newIP24(prom storage.Reader, graphics bool) (*IP24, error) {
	var rom []byte
	if prom != nil {
		if prom.Size() != ip12ROMSize {
			return nil, fmt.Errorf("ip24: PROM must be exactly 512 KiB")
		}
		rom = make([]byte, ip12ROMSize)
		if _, err := block.ReadFullAt(prom, rom, 0); err != nil {
			return nil, err
		}
	}
	guest, host, err := channel.NewMemoryPair(1 << 20)
	if err != nil {
		return nil, err
	}
	m := &IP24{ram: make([]byte, ip24RAMSize), rom: rom, console: host, breaks: make(map[uint64]bool)}
	if graphics {
		m.newport = &newport{}
	}
	m.scc.ports[ip24SerialPort].stream = guest
	m.reset()
	return m, nil
}

func (m *IP24) reset() {
	m.cpu, m.scsi, m.dma, m.int3 = newR4400(), wd33c93{modelB: true}, hpc3SCSI{}, ip12INT{}
	port := m.scc.ports[ip24SerialPort].stream
	m.scc = ip12SCC{}
	m.scc.ports[ip24SerialPort].stream = port
	clear(m.mc[:])
	m.vdma = mcVDMA{}
	clear(m.ioc[:])
	clear(m.rtc[:])
	clear(m.pioConfig[:])
	clear(m.pbusConfig[:])
	clear(m.pbusDMA[:])
	m.cycles, m.rtcCycles, m.gioMisc = 0, 0, 0
	m.lastFault = r4kStep{exception: -1}
	m.ethernet = ip24Ethernet{}
	m.eeprom = ip12EEPROM{}
	m.eeprom.init()
	m.keyboard.init()
	m.keyboard.frameCycles = ip24Clock * 11 * 60 / 1_000_000
	if m.newport != nil {
		m.newport.reset()
	}
	m.rtcBase = time.Date(2003, 11, 1, 0, 0, 0, 0, time.UTC)
	m.rtc[0x0b] = 0x80
	copy(m.rtc[0xfa:], ip12EthernetAddress[:])
	m.mc[3] = 3 // MC revision 3 uses 16 MiB bank address units.
	m.mc[0x80/8] = 0x401
	m.mc[0xc0/8] = 0x23080000 // Bank 0 at 128 MiB, size 64 MiB.
	m.ioc[0x14] = 0xa1
	m.ioc[0x16] = 0x20 // IOC2 revision 1, Guinness.
}

func (m *IP24) Close() error {
	if !m.closed {
		m.closed = true
		clear(m.targets[:])
		m.ram, m.rom, m.newport = nil, nil, nil
		_ = m.scc.ports[ip24SerialPort].stream.Close()
		return m.console.Close()
	}
	return nil
}

func (m *IP24) Serial() channel.ByteChannel {
	return m.console
}

func (m *IP24) Screen() (*image.RGBA, error) {
	if m.newport == nil {
		return nil, fmt.Errorf("ip24: no active Newport display")
	}
	return m.newport.screen(), nil
}

func (m *IP24) Key(key string, down bool) error {
	if m.closed {
		return fmt.Errorf("ip24: machine closed")
	}
	return m.keyboard.key(m.cycles, key, down)
}

// Mouse queues a PS/2 mouse packet. Positive deltas move right and up.
// Button bits 0, 1 and 2 represent the left, right and middle buttons.
func (m *IP24) Mouse(dx, dy int, buttons byte) error {
	if m.closed || dx < -255 || dx > 255 || dy < -255 || dy > 255 || buttons > 7 {
		return fmt.Errorf("ip24: invalid PS/2 mouse event or closed machine")
	}
	k := &m.keyboard
	if !k.mouseEnabled || k.mouseRemote || k.command&0x20 != 0 {
		return fmt.Errorf("ip24: PS/2 mouse stream disabled")
	}
	if len(k.queue)-k.length < 3 {
		return channel.ErrWouldBlock
	}
	flags := byte(8|truth(dx < 0)<<4|truth(dy < 0)<<5) | buttons
	k.queueBytes(m.cycles, true, true, flags, byte(dx), byte(dy))
	return nil
}

func (m *IP24) AttachDisk(target int, media block.Device) error {
	if m.closed {
		return fmt.Errorf("ip24: machine closed")
	}
	if target < 0 || target >= len(m.targets) || target == 7 {
		return fmt.Errorf("ip24: invalid SCSI disk target %d", target)
	}
	if media == nil || media.Geometry().LogicalBlockSize != 512 {
		return fmt.Errorf("ip24: SCSI disks require 512-byte sectors")
	}
	disk, err := scsi.NewDisk(media, scsi.DiskIdentity{Vendor: "SGI", Product: "SCSI Disk", Revision: "1.0"})
	if err == nil {
		m.targets[target] = &disk
	}
	return err
}

func (m *IP24) memory(physical, size uint64) []byte {
	offset := physical
	switch {
	case physical >= ip24RAMBase:
		offset -= ip24RAMBase
	case physical >= 512<<10 || size > (512<<10)-physical:
		return nil
	}
	if offset > uint64(len(m.ram)) || size > uint64(len(m.ram))-offset {
		return nil
	}
	return m.ram[offset : offset+size]
}

// ReadPhysical copies RAM without executing a device read.
func (m *IP24) ReadPhysical(physical uint64, out []byte) error {
	p := m.memory(physical, uint64(len(out)))
	if p == nil {
		return fmt.Errorf("ip24: address %#x is not backed by RAM", physical)
	}
	copy(out, p)
	return nil
}

func (m *IP24) ReadEffective(address uint64, out []byte) error {
	for len(out) > 0 {
		n := min(len(out), 4096-int(address&4095))
		x := r4kInstruction{code: -1}
		physical := m.cpu.translate(address, false, &x)
		if x.code >= 0 {
			return fmt.Errorf("ip24: address %#x translation failed: exception %d", address, x.code)
		}
		if err := m.ReadPhysical(physical, out[:n]); err != nil {
			return err
		}
		address, out = address+uint64(n), out[n:]
	}
	return nil
}

func (m *IP24) read64(address uint64, size uint32) (uint64, bool) {
	if m.newport != nil && address >= newportBase && address < newportBase+0x2000 {
		return m.newport.access(uint32(address-newportBase), size, 0, false, m.cycles)
	}
	b := m.memory(address, uint64(size))
	if address >= ip12ROMBase && address < ip12ROMBase+ip12ROMSize && uint64(size) <= ip12ROMBase+ip12ROMSize-address {
		if m.rom == nil {
			return ^uint64(0) >> (64 - size*8), true
		}
		offset := address - ip12ROMBase
		b = m.rom[offset : offset+uint64(size)]
	}
	if b != nil {
		switch size {
		case 1:
			return uint64(b[0]), true
		case 2:
			return uint64(binary.BigEndian.Uint16(b)), true
		case 4:
			return uint64(binary.BigEndian.Uint32(b)), true
		case 8:
			return binary.BigEndian.Uint64(b), true
		}
	}
	return m.io(address, size, 0, false)
}

func (m *IP24) write64(address uint64, size uint32, data uint64) bool {
	if m.newport != nil && address >= newportBase && address < newportBase+0x2000 {
		_, ok := m.newport.access(uint32(address-newportBase), size, data, true, m.cycles)
		return ok
	}
	if b := m.memory(address, uint64(size)); b != nil {
		switch size {
		case 1:
			b[0] = byte(data)
		case 2:
			binary.BigEndian.PutUint16(b, uint16(data))
		case 4:
			binary.BigEndian.PutUint32(b, uint32(data))
		case 8:
			binary.BigEndian.PutUint64(b, data)
		default:
			return false
		}
		return true
	}
	_, ok := m.io(address, size, uint32(data), true)
	return ok
}

// Load stages a static big-endian 32-bit MIPS kernel at its linked
// addresses and supplies a 32-bit ARCS system parameter block.
func (m *IP24) Load(source storage.Reader, args, env []string) error {
	if m.closed {
		return fmt.Errorf("ip24: machine closed")
	}
	if source == nil {
		return fmt.Errorf("ip24: executable is required")
	}
	image, err := irix.Open(starfile.NewReader("IP24 ELF", source))
	if err != nil {
		return err
	}
	if image.Format != "elf" || image.Type != 2 || image.Class != 32 || image.Endian != "big" ||
		(image.ABI != "n32" && image.ABI != "o32") || (image.ISA != "mips3" && image.ISA != "mips2" && image.ISA != "mips1") ||
		image.Interpreter != "" || len(image.Libraries) != 0 {
		return fmt.Errorf("ip24: expected a static big-endian MIPS I–III ELF32 executable")
	}

	var segments []irix.Segment
	var payloads [][]byte
	entryMapped := false
	for _, s := range image.Segments {
		if s.Type != 1 || s.MemorySize == 0 {
			continue
		}
		if s.Address < 0x88004000 || s.Address >= 0x88000000+ip24RAMSize-0x10000 ||
			s.MemorySize > 0x88000000+ip24RAMSize-0x10000-s.Address || s.Size > s.MemorySize {
			return fmt.Errorf("ip24: ELF load segment %#x+%#x does not fit RAM", s.Address, s.MemorySize)
		}
		for _, previous := range segments {
			if s.Address < previous.Address+previous.MemorySize && previous.Address < s.Address+s.MemorySize {
				return fmt.Errorf("ip24: overlapping ELF load segments")
			}
		}
		if s.Flags&1 != 0 && image.Entry >= s.Address && image.Entry+4 <= s.Address+s.Size {
			entryMapped = true
		}
		var data []byte
		if s.Size != 0 {
			data = make([]byte, s.Size)
			if _, err := block.ReadFullAt(s.Data, data, 0); err != nil {
				return err
			}
		}
		segments, payloads = append(segments, s), append(payloads, data)
	}
	if !entryMapped || image.Entry&3 != 0 {
		return fmt.Errorf("ip24: entry %#x is outside executable data", image.Entry)
	}
	arcs, argv, envp, err := makeIP24ARCS(args, env)
	if err != nil {
		return err
	}

	clear(m.ram)
	m.reset()
	for i, s := range segments {
		copy(m.ram[s.Address-0x88000000:], payloads[i])
	}
	m.arcs = arcs
	copy(m.ram[0x1000:0x4000], arcs.parameterBlock[:])
	copy(m.ram[ip24RAMSize-0x8000:], arcs.arguments[:])
	m.cpu.pc, m.cpu.next = mipsWord(uint32(image.Entry)), mipsWord(uint32(image.Entry)+4)
	m.cpu.cp0[status] = bev | r4kKX | r4kFR | 1<<28
	m.cpu.gpr[4], m.cpu.gpr[5], m.cpu.gpr[6] = uint64(len(args)), mipsWord(argv), mipsWord(envp)
	m.cpu.gpr[28], m.cpu.gpr[29] = mipsWord(uint32(image.GP)), mipsWord(0x88000000+ip24RAMSize-0x8010)
	return nil
}

func (m *IP24) Run(ctx context.Context, budget uint64, stopOnException bool) (IP24Stop, error) {
	var exceptions uint32
	if stopOnException {
		exceptions = ^uint32(0)
	}
	return m.run(ctx, budget, exceptions)
}

func (m *IP24) run(ctx context.Context, budget uint64, exceptions uint32) (IP24Stop, error) {
	if m.closed {
		return IP24Stop{}, fmt.Errorf("ip24: machine closed")
	}
	for i := uint64(0); i < budget; i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return IP24Stop{}, err
			}
		}
		pc := m.cpu.pc
		if m.breaks[pc] {
			return IP24Stop{Kind: "breakpoint", PC: pc, Cycles: i}, nil
		}
		if uint32(pc) >= ip24ARCSTrap && uint32(pc) < ip24ARCSTrap+0x400 && pc == mipsWord(uint32(pc)) {
			service := (uint32(pc) - ip24ARCSTrap) / 4
			done, err := m.arcsCall(service)
			if err != nil {
				return IP24Stop{}, err
			}
			if !done {
				return IP24Stop{Kind: "firmware", PC: pc, Service: service, Cycles: i}, nil
			}
		} else {
			m.updateInterrupts()
			result := m.cpu.step(m)
			if result.exception >= 0 {
				m.lastFault = result
				if exceptions&(1<<result.exception) != 0 {
					m.advanceClock()
					return IP24Stop{Kind: "exception", PC: pc, Address: result.address, Physical: result.physical,
						Instruction: result.word, Exception: result.exception, Store: result.store, Cycles: i + 1}, nil
				}
			}
		}
		m.advanceClock()
	}
	return IP24Stop{Kind: "budget", PC: m.cpu.pc, Cycles: budget}, nil
}

func (m *IP24) advanceClock() {
	m.cycles++
	m.cpu.tick(m.cycles&1 == 0)
}

// rtcAccess provides the battery-backed SRAM and DS1386 time-of-day registers.
func (m *IP24) rtcAccess(index uint64, value byte, write bool) byte {
	if index >= uint64(len(m.rtc)) {
		return 0xff
	}
	if index <= 0x0b && m.rtc[0x0b]&0x80 != 0 {
		now := m.rtcBase.Add(time.Duration((m.cycles-m.rtcCycles)/ip24Clock)*time.Second + time.Duration((m.cycles-m.rtcCycles)%ip24Clock)*time.Second/ip24Clock)
		m.rtc[0], m.rtc[1], m.rtc[2] = rtcBCD(now.Nanosecond()/10_000_000), rtcBCD(now.Second()), rtcBCD(now.Minute())
		m.rtc[4], m.rtc[6] = rtcBCD(now.Hour()), byte(now.Weekday()+1)
		m.rtc[8], m.rtc[9], m.rtc[10] = rtcBCD(now.Day()), rtcBCD(int(now.Month())), rtcBCD(now.Year()%100)
	}
	if write {
		if index == 0x0b && m.rtc[index]&0x80 == 0 && value&0x80 != 0 {
			year := rtcDecimal(m.rtc[10])
			if year < 70 {
				year += 100
			}
			m.rtcBase = time.Date(1900+year, time.Month(rtcDecimal(m.rtc[9]&0x1f)), rtcDecimal(m.rtc[8]),
				rtcDecimal(m.rtc[4]&0x3f), rtcDecimal(m.rtc[2]&0x7f), rtcDecimal(m.rtc[1]&0x7f), 0, time.UTC)
			m.rtcCycles = m.cycles
		}
		m.rtc[index] = value
	}
	return m.rtc[index]
}

var _ io.Closer = (*IP24)(nil)
