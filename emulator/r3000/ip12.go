package r3000

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"sort"
	"strings"

	irix "github.com/tinyrange/trex/binary/irix"
	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/scsi"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

const (
	ip12ROMBase = 0x1fc00000
	ip12ROMSize = 512 << 10
)

// IP12 is a big-endian R3000A Personal IRIS 4D/35.
type IP12 struct {
	cpu             cpu
	pic             ip12PIC
	int2            ip12INT
	scsi            wd33c93
	targets         [8]*scsi.Disk
	dma             ip12DMA
	gdma            ip12GraphicsDMA
	nvram           ip12EEPROM
	rtc             ip12RTC
	dspRegs         [14]uint32
	parallel        [6]uint32
	parallelControl byte
	graphics        ip12GR1
	ethernet        ip12Ethernet
	dspRAM          [1 << 15]uint32
	scc             [3]ip12SCC
	keyboard, mouse ip12Input
	console         *channel.Memory
	ram, rom        []byte
	breaks          map[uint32]bool
	cycles          uint64
	closed          bool
}

// NewIP12 creates a machine with an optional PROM in CPU byte order. With no
// PROM, Load starts a standalone executable directly.
func NewIP12(memory int, rom storage.Reader) (*IP12, error) {
	if memory == 0 {
		memory = 32 << 20
	}
	if memory < 8<<20 || memory > 96<<20 || memory%(8<<20) != 0 {
		return nil, fmt.Errorf("ip12: memory must be 8–96 MiB in 8 MiB increments")
	}
	m := &IP12{ram: make([]byte, memory), breaks: make(map[uint32]bool)}
	if rom != nil {
		m.rom = bytes.Repeat([]byte{0xff}, ip12ROMSize)
		if err := readSeed(m.rom, rom, false); err != nil {
			return nil, fmt.Errorf("ip12 PROM: %w", err)
		}
	}
	guest, host, err := channel.NewMemoryPair(1 << 20)
	if err != nil {
		return nil, err
	}
	m.console = host
	m.scc[1].ports[1].stream = guest
	m.resetCPU()
	m.nvram.init()
	m.rtc = newIP12RTC()
	m.graphics.init()
	m.pic.reset(m.ram, rom == nil)
	return m, nil
}

func (m *IP12) resetCPU() {
	m.cpu = newCPU()
	m.cpu.bigEndian = true
	m.cpu.cp0[15] = 0x230
	m.cpu.fpuRevision = 0x340
}

func (m *IP12) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	m.ram, m.rom = nil, nil
	m.pic = ip12PIC{}
	m.graphics.raster.pixels = nil
	m.graphics.raster.depth = nil
	_ = m.scc[1].ports[1].stream.Close()
	return m.console.Close()
}

// Screen returns the current GR1 display as an independent image.
func (m *IP12) Screen() image.Image {
	return m.graphics.screen()
}

// Serial returns the Personal IRIS console's duplex byte channel.
func (m *IP12) Serial() (channel.ByteChannel, error) {
	if m.closed {
		return nil, fmt.Errorf("ip12: machine closed")
	}
	return m.console, nil
}

func (m *IP12) memory(address, size uint32) []byte {
	if data := m.pic.memory(address, size); data != nil {
		return data
	}
	if inRange(address, size, ip12ROMBase, uint32(len(m.rom))) {
		offset := address - ip12ROMBase
		return m.rom[offset : offset+size]
	}
	return nil
}

// Read copies physical RAM or ROM without invoking device side effects.
func (m *IP12) Read(address uint32, out []byte) error {
	if len(out) == 0 {
		return nil
	}
	if uint64(len(out)) > 1<<32-1 {
		return fmt.Errorf("ip12: read too large")
	}
	data := m.memory(address, uint32(len(out)))
	if data == nil {
		return fmt.Errorf("ip12: unmapped physical memory at %#x", address)
	}
	copy(out, data)
	return nil
}

// ReadEffective reads mapped RAM and ROM at CPU virtual addresses.
func (m *IP12) ReadEffective(address uint32, out []byte) error {
	return m.cpu.readEffective(address, out, m.Read)
}

func (m *IP12) readBus(address, size uint32) (uint32, bool) {
	if data := m.memory(address, size); data != nil {
		switch size {
		case 1:
			return uint32(data[0]), true
		case 2:
			return uint32(binary.BigEndian.Uint16(data)), true
		default:
			return binary.BigEndian.Uint32(data), true
		}
	}
	return m.mmio(address, size, 0, false)
}

func (m *IP12) writeBus(address, size, value uint32) bool {
	data := m.pic.memory(address, size)
	if data == nil {
		_, ok := m.mmio(address, size, value, true)
		return ok
	}
	switch size {
	case 1:
		data[0] = byte(value)
	case 2:
		binary.BigEndian.PutUint16(data, uint16(value))
	default:
		binary.BigEndian.PutUint32(data, value)
	}
	return true
}

func (m *IP12) mmio(address, size, value uint32, write bool) (uint32, bool) {
	switch {
	case inRange(address, size, 0x1f000000, 0x10000):
		return m.graphics.access(address, size, value, write)
	case address == ip12PICBase+8 && size == 4 && !write:
		return 0x40 | truth(!m.gdma.active)<<3 | truth(m.gdma.failed)<<2, true
	case size == 4 && (address >= ip12GDMARegisters && address <= ip12GDMARegisters+16 || address == ip12GDMAStart):
		return m.graphicsDMA(address, value, write)
	case inRange(address, size, ip12PICBase, 1<<20):
		return m.pic.access(address, size, value, write)
	case size == 4 && address >= 0x1fb80000 && address < 0x1fb80058:
		return m.ethernet.channel(address-0x1fb80000, value, write)
	case address >= 0x1fb80100 && address < 0x1fb80120 && (size == 4 || size == 1 && address&3 == 3):
		return m.ethernet.seeq((address-0x1fb80100)/4, byte(value), write), true
	case size == 4 && address >= 0x1fb80088 && address <= 0x1fb80098:
		return m.hpcSCSI(address, value, write), true
	case size == 4 && address >= 0x1fb800a8 && address < 0x1fb800c0:
		index := (address - 0x1fb800a8) / 4
		if write {
			m.parallel[index] = value
		}
		return m.parallel[index], true
	case size == 1 && address == 0x1fb80132:
		return 0, true // Disconnected parallel peripheral.
	case size == 1 && address == 0x1fb80135:
		if write {
			m.parallelControl = byte(value)
		}
		return uint32(m.parallelControl), true
	case size == 4 && address >= 0x1fb80180 && address < 0x1fb801b8:
		index := (address - 0x1fb80180) / 4
		if write {
			m.dspRegs[index] = value
		}
		return m.dspRegs[index], true
	case size == 4 && address >= 0x1fbe0000 && address < 0x1fc00000:
		index := (address - 0x1fbe0000) / 4
		if write {
			m.dspRAM[index] = value & 0xffffff
		}
		return m.dspRAM[index], true
	case size == 1 && address == 0x1fb801bf:
		return m.nvram.access(byte(value), write), true
	case size == 1 && (address == 0x1fb80122 || address == 0x1fb80126):
		return m.scsi.port(m, address == 0x1fb80126, byte(value), write), true
	case size == 1 && address >= 0x1fb801c0 && address < 0x1fb80200 && address&3 == 3:
		return m.int2.access((address-0x1fb801c0)/4, byte(value), write)
	case size == 1 && address >= 0x1fb80d00 && address < 0x1fb80d30 && address&3 == 3:
		offset := address - 0x1fb80d00
		if offset == 15 && write && m.scc[0].ports[0].wr[5]&8 != 0 {
			m.keyboardCommand(byte(value))
		}
		return m.scc[offset/16].access((offset%16)/4, byte(value), write), true
	case address >= 0x1fb80e00 && address < 0x1fb80e80 && (size == 4 || size == 1 && address&3 == 3):
		return m.rtc.access(m.cycles, (address-0x1fb80e00)/4, byte(value), write), true
	case inRange(address, size, 0x1fbd0000, 4):
		return 0, !write // Personal IRIS board revision.
	default:
		return 0, false
	}
}

type ip12LoadRange struct {
	begin, end uint32
	data       storage.Reader
}

// Load replaces RAM and CPU state with a static, big-endian MIPS I executable
// at its linked KSEG0/KSEG1 addresses. Arguments and environment are passed as
// the pre-ARCS PROM's argc, argv and envp. Omit args to pass an empty vector.
func (m *IP12) Load(source storage.Reader, args, env []string) error {
	if m.closed {
		return fmt.Errorf("ip12: machine closed")
	}
	if source == nil {
		return fmt.Errorf("ip12: executable is required")
	}
	image, err := irix.Open(starfile.NewReader("IP12 executable", source))
	if err != nil {
		return err
	}
	if image.Endian != "big" || image.Class != 32 || image.ISA != "mips1" || image.ABI != "o32" ||
		image.Interpreter != "" || len(image.Libraries) != 0 {
		return fmt.Errorf("ip12: expected a static big-endian MIPS I executable")
	}
	if image.Format == "ecoff" && image.Type == 0 || image.Format == "elf" && image.Type != 2 {
		return fmt.Errorf("ip12: expected an executable image")
	}
	entry := uint32(image.Entry)
	if entry&3 != 0 {
		return fmt.Errorf("ip12: unaligned entry %#x", entry)
	}
	// Reserve the top 64 KiB of RAM for the initial stack and vectors.
	stackBase := uint32(len(m.ram)) - (64 << 10)
	var ranges []ip12LoadRange
	entryMapped := false
	add := func(address, size uint64, data storage.Reader, executable bool) error {
		if size == 0 {
			return nil
		}
		if address < 0x80000000 || address >= 0xc0000000 {
			return fmt.Errorf("ip12: load address %#x is outside unmapped kernel segments", address)
		}
		begin := uint32(address) & 0x1fffffff
		if begin >= stackBase || size > uint64(stackBase-begin) {
			return fmt.Errorf("ip12: load range %#x+%#x exceeds available RAM", address, size)
		}
		end := begin + uint32(size)
		ranges = append(ranges, ip12LoadRange{begin, end, data})
		if executable && data != nil && image.Entry >= address && image.Entry-address+4 <= uint64(data.Size()) {
			entryMapped = true
		}
		return nil
	}
	if image.Format == "ecoff" {
		for _, s := range image.Sections {
			// STYP_TEXT, DATA, BSS, RDATA, SDATA and SBSS.
			if s.Flags&0x7e0 != 0 {
				var data storage.Reader
				if s.Data != nil {
					data = s.Data
				}
				if err := add(s.Address, s.Size, data, s.Flags&0x20 != 0); err != nil {
					return err
				}
			}
		}
	} else {
		for _, s := range image.Segments {
			if s.Type == 1 { // PT_LOAD
				if err := add(s.Address, s.MemorySize, s.Data, s.Flags&1 != 0); err != nil {
					return err
				}
			}
		}
	}
	if !entryMapped {
		return fmt.Errorf("ip12: entry %#x is outside executable file data", entry)
	}

	sort.Slice(ranges, func(i, j int) bool { return ranges[i].begin < ranges[j].begin })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].begin < ranges[i-1].end {
			return fmt.Errorf("ip12: overlapping load ranges at physical address %#x", ranges[i].begin)
		}
	}

	// Stage only the initialized ranges so a short media read leaves the
	// existing machine intact.
	payloads := make([][]byte, len(ranges))
	for i, r := range ranges {
		if r.data != nil {
			if r.data.Size() < 0 || r.data.Size() > int64(r.end-r.begin) {
				return fmt.Errorf("ip12: load data exceeds destination")
			}
			payloads[i] = make([]byte, r.data.Size())
			if _, err := block.ReadFullAt(r.data, payloads[i], 0); err != nil {
				return err
			}
		}
	}
	// Leave stack space below the vectors for the program's own stack frames.
	parameters := make([]byte, 32<<10)
	paramsBase := uint32(len(m.ram)) - uint32(len(parameters))
	cursor := uint32(0)
	vector := func(values []string) (uint32, error) {
		if len(values) >= len(parameters)/4 || (len(values)+1)*4 > len(parameters)-int(cursor) {
			return 0, fmt.Errorf("ip12: argument vectors exceed available space")
		}
		head := cursor
		cursor += uint32((len(values) + 1) * 4)
		for i, value := range values {
			if len(value) >= len(parameters)-int(cursor) || strings.ContainsRune(value, 0) {
				return 0, fmt.Errorf("ip12: invalid or oversized argument string")
			}
			binary.BigEndian.PutUint32(parameters[int(head)+4*i:], 0x80000000+paramsBase+cursor)
			copy(parameters[cursor:], value)
			cursor += uint32(len(value) + 1)
		}
		cursor = (cursor + 3) &^ 3
		return 0x80000000 + paramsBase + head, nil
	}
	argv, err := vector(args)
	if err != nil {
		return err
	}
	envp, err := vector(env)
	if err != nil {
		return err
	}
	clear(m.ram)
	for i, r := range ranges {
		copy(m.ram[r.begin:r.end], payloads[i])
	}
	copy(m.ram[paramsBase:], parameters)
	m.resetCPU()
	m.pic.reset(m.ram, true)
	m.int2, m.scsi, m.dma = ip12INT{}, wd33c93{}, ip12DMA{}
	clear(m.parallel[:])
	m.parallelControl = 0
	m.graphics = ip12GR1{}
	m.ethernet = ip12Ethernet{}
	clear(m.dspRegs[:])
	clear(m.dspRAM[:])
	console := m.scc[1].ports[1].stream
	m.scc = [3]ip12SCC{}
	m.scc[1].ports[1].stream = console
	m.cpu.pc, m.cpu.next = entry, entry+4
	m.cpu.gpr[4], m.cpu.gpr[5], m.cpu.gpr[6] = uint32(len(args)), argv, envp
	m.cpu.gpr[28] = uint32(image.GP)
	m.cpu.gpr[29] = 0x80000000 + paramsBase - 16
	m.cycles = 0
	m.rtc.millis = 0
	return nil
}

func (m *IP12) Run(ctx context.Context, budget uint64, stopOnException bool) (Stop, error) {
	if m.closed {
		return Stop{}, fmt.Errorf("ip12: machine closed")
	}
	for i := uint64(0); i < budget; i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return Stop{}, err
			}
		}
		if m.breaks[m.cpu.pc] {
			return Stop{Kind: "breakpoint", PC: m.cpu.pc, Cycles: i}, nil
		}
		if len(m.rom) == 0 && m.cpu.pc >= 0xbfc00000 && m.cpu.pc < 0xbfc00000+ip12ROMSize {
			handled, err := m.promCall()
			if err != nil {
				return Stop{}, err
			}
			if !handled {
				return Stop{Kind: "firmware", PC: m.cpu.pc, Cycles: i}, nil
			}
			m.cycles++
			continue
		}
		m.int2.update(m.cycles)
		m.graphics.ge.run(m.cycles, &m.graphics.raster, m.graphics.display[1]&2 != 0, &m.gdma, &m.pic)
		m.int2.reg[0] = m.int2.reg[0]&^0x75 | byte(truth(m.scsi.irq)<<2)
		if m.graphics.ge.queued > 256 {
			m.int2.reg[0] |= 1
		}
		if m.graphics.ge.irq {
			m.int2.reg[0] |= 1 << 6
		}
		if m.gdma.done && m.pic.control&(1<<4) != 0 {
			m.int2.reg[0] |= 1 << 4
		}
		// At 60 Hz, 41 of 1065 lines fall outside the visible raster.
		m.int2.reg[2] &^= 1 << 7
		m.int2.reg[4] &^= 1
		if m.cycles%600000 >= 576901 {
			m.int2.reg[2] |= 1 << 7
			m.int2.reg[4] |= 1
		}
		m.keyboard.deliver(&m.scc[0].ports[0], m.cycles, ip12KeyboardFrame)
		m.mouse.deliver(&m.scc[0].ports[1], m.cycles, ip12MouseFrame)
		if m.scc[0].irq() || m.scc[1].irq() || m.scc[2].irq() {
			m.int2.reg[0] |= 1 << 5
		}
		m.cpu.cp0[cause] = m.cpu.cp0[cause]&^0x7c00 | m.int2.interrupts()
		if m.cpu.fcsr>>12&m.cpu.fcsr>>7&31 != 0 {
			m.cpu.cp0[cause] |= 1 << 10
		}
		result := m.cpu.step(m)
		m.cycles++
		if stopOnException && result.Kind == "exception" {
			result.Cycles = i + 1
			return result, nil
		}
	}
	return Stop{Kind: "budget", PC: m.cpu.pc, Cycles: budget}, nil
}

func (m *IP12) AttachDisk(target int, media block.Device) error {
	if m.closed {
		return fmt.Errorf("ip12: machine closed")
	}
	if target < 0 || target >= len(m.targets) {
		return fmt.Errorf("ip12: invalid SCSI target %d", target)
	}
	if media == nil || media.Geometry().LogicalBlockSize != 512 {
		return fmt.Errorf("ip12: SCSI disk requires 512-byte sectors")
	}
	disk, err := scsi.NewDisk(media, scsi.DiskIdentity{Vendor: "SGI", Product: "SCSI Disk", Revision: "1.0"})
	if err != nil {
		return err
	}
	m.targets[target] = &disk
	return nil
}

func (m *IP12) scsiTarget(target byte) *scsi.Disk {
	return m.targets[target]
}

func (m *IP12) scsiDMAEnabled(toRAM bool) bool {
	return m.dma.control&ip12DMAActive != 0 && (m.dma.control&ip12DMAToRAM != 0) == toRAM
}

func (m *IP12) scsiTransfer(data []byte, toRAM bool) bool {
	return m.dma.transfer(&m.pic, data, toRAM)
}
