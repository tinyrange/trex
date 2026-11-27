package r3000

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
)

func newTestIP12(t *testing.T) *IP12 {
	t.Helper()
	m, err := NewIP12(8<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func testECOFF(entry uint32, words ...uint32) *starfile.Bytes {
	const data = 20 + 56 + 40
	be := binary.BigEndian
	image := make([]byte, data+4*len(words))
	be.PutUint16(image[0:], 0x160)
	be.PutUint16(image[2:], 1)
	be.PutUint16(image[16:], 56)
	be.PutUint16(image[20:], 0x107)
	be.PutUint32(image[36:], entry)
	copy(image[76:], ".text")
	be.PutUint32(image[88:], 0x80002000)
	be.PutUint32(image[92:], uint32(len(words))*4)
	be.PutUint32(image[96:], data)
	be.PutUint32(image[112:], 0x20)
	for i, word := range words {
		be.PutUint32(image[data+4*i:], word)
	}
	return &starfile.Bytes{Data: image}
}

func TestIP12LoadsBigEndianECOFF(t *testing.T) {
	m := newTestIP12(t)
	image := testECOFF(0x80002000,
		0x3c088000, // lui t0, 0x8000
		0x3c091122, // lui t1, 0x1122
		0x35293344, // ori t1, t1, 0x3344
		0xa9091001, // swl t1, 4097(t0)
		0xb9091004, // swr t1, 4100(t0)
		0x890a1001, // lwl t2, 4097(t0)
		0x990a1004, // lwr t2, 4100(t0)
		0x910b1002, // lbu t3, 4098(t0)
		0xa5091006, // sh t1, 4102(t0)
		0x950c1006, // lhu t4, 4102(t0)
		0x0000000d, // break
	)
	if err := m.Load(image, []string{"unix.IP12"}, []string{"console=d"}); err != nil {
		t.Fatal(err)
	}
	argv := m.cpu.gpr[5]
	arg := binary.BigEndian.Uint32(m.promRAM(argv, 4, false))
	if got, err := m.promString(arg); got != "unix.IP12" || err != nil || m.cpu.gpr[4] != 1 {
		t.Fatalf("argc=%d argv[0]=%q, %v", m.cpu.gpr[4], got, err)
	}
	stop, err := m.Run(context.Background(), 100, true)
	if err != nil || stop.Kind != "exception" || stop.Exception != 9 {
		t.Fatalf("run = %+v, %v", stop, err)
	}
	if t2, t3, t4 := m.cpu.gpr[10], m.cpu.gpr[11], m.cpu.gpr[12]; t2 != 0x11223344 || t3 != 0x22 || t4 != 0x3344 {
		t.Fatalf("big-endian loads = %#x %#x %#x", t2, t3, t4)
	}
	mem := make([]byte, 8)
	if err := m.Read(0x1000, mem); err != nil || !bytes.Equal(mem, []byte{0, 0x11, 0x22, 0x33, 0x44, 0, 0x33, 0x44}) {
		t.Fatalf("big-endian stores = %x, %v", mem, err)
	}
	saved := m.cpu.pc
	if err := m.Load(testECOFF(0x80002004, 0), nil, nil); err == nil || m.cpu.pc != saved {
		t.Fatal("invalid executable changed guest state")
	}
}

func TestIP12SCSIReadThroughHPC1DMA(t *testing.T) {
	m := newTestIP12(t)
	contents := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 128)
	disk, err := block.NewFileDevice(&starfile.Bytes{Data: contents}, block.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AttachDisk(1, disk); err != nil {
		t.Fatal(err)
	}
	// Split one READ(6) block across a pair of HPC1 DMA descriptors.
	for i, word := range [...]uint32{128, 0x2000, 0x100c, 384, ip12DMAEnd | 0x3000, 0} {
		m.writeBus(0x1000+uint32(i)*4, 4, word)
	}
	m.writeBus(0x1fb80090, 4, 0x1000)
	m.writeBus(0x1fb80094, 4, ip12DMAActive|ip12DMAToRAM)
	writeRegister := func(address, value uint32) {
		m.writeBus(0x1fb80122, 1, address)
		m.writeBus(0x1fb80126, 1, value)
	}
	writeRegister(0, 7)
	writeRegister(3, 0x08)
	writeRegister(7, 1)
	writeRegister(19, 2)
	writeRegister(21, 0x41)
	writeRegister(wdCommand, 8)
	if !bytes.Equal(m.ram[0x2000:0x2080], contents[:128]) || !bytes.Equal(m.ram[0x3000:0x3180], contents[128:]) {
		t.Fatal("HPC1 did not scatter SCSI data to both guest buffers")
	}
	if m.scsi.transferCount() != 0 || !m.scsi.irq || m.dma.control&ip12DMAActive != 0 {
		t.Fatal("transfer did not complete")
	}
	m.writeBus(0x1fb80122, 1, wdStatus)
	status, _ := m.readBus(0x1fb80126, 1)
	if status != 0x16 || m.scsi.irq {
		t.Fatalf("status = %#x, irq = %v", status, m.scsi.irq)
	}
}

func TestIP12PROMWriteUpdatesCachedMappedRAM(t *testing.T) {
	m := newTestIP12(t)
	const address = 0xffffd020
	m.cpu.tlb[0] = tlbEntry{hi: address &^ 0xfff, lo: 0x1000 | 0x700}
	m.writeBus(0x1020, 4, 0xaabbccdd)
	x := instruction{exception: -1}
	if got := m.cpu.access(m, address, 4, false, false, 0, &x); got != 0xaabbccdd {
		t.Fatalf("initial cached read = %#x", got)
	}
	m.cpu.pc, m.cpu.gpr[4], m.cpu.gpr[31] = ip12PROMEaddr, address, 0x80002000
	if handled, err := m.promCall(); err != nil || !handled {
		t.Fatalf("PROM call handled=%v, err=%v", handled, err)
	}
	want := binary.BigEndian.Uint32(ip12EthernetAddress[:])
	if got := m.cpu.access(m, address, 4, false, false, 0, &x); got != want {
		t.Fatalf("cached result = %#x, want %#x", got, want)
	}
}

func TestIP12GR1FIFOExecutesRasterMicrocode(t *testing.T) {
	m := newTestIP12(t)
	if err := m.Load(testECOFF(0x80002000, 0x08000800, 0), nil, nil); err != nil {
		t.Fatal(err)
	}
	const base = 0x1f000000
	write := func(offset, value uint32) {
		t.Helper()
		if !m.writeBus(base+offset, 4, value) {
			t.Fatalf("GR1 write at %#x", offset)
		}
	}
	read := func(offset uint32) uint32 {
		t.Helper()
		result, ok := m.readBus(base+offset, 4)
		if !ok {
			t.Fatalf("GR1 read at %#x", offset)
		}
		return result
	}
	load := func(address uint32, word uint64) {
		t.Helper()
		write(0xc00+(address>>8)*4, 0)
		offset := (address & 255) * 4
		write(0xe00, 0)
		write(offset, uint32(word))
		write(0xe04, 0)
		write(offset, uint32(word>>32))
	}

	const fifoSource = 1 << 38
	const busDestination = 1 << 33
	const secondary = 1 << 36
	load(0, fifoSource|busDestination|8<<29)
	load(2, 2<<38|busDestination|secondary|1<<29)
	load(3, 0xbc<<32|0x201<<19)
	registers := []struct{ address, value uint32 }{
		{6, 3}, {0x3a, 1023}, {0x3c, 1279}, {0x21, 0xffffff},
		{0x0b, 4<<12 | 3}, {0x1a, 1 << 14}, {0x1c, 2},
		{0x0a, 0x3d8ef2}, {0x1f, 1},
	}
	pc := uint32(0x201)
	for _, r := range registers {
		load(pc, fifoSource|secondary)
		load(pc+1, 0x9c<<32|uint64(r.address)<<19)
		pc += 2
	}
	load(pc, 2<<38|busDestination|secondary)
	load(pc+1, 0xb6<<32)
	load(pc+2, 2<<38|busDestination|12<<29)

	// Program the monitor mode and identity transfer function through
	// the same ports used by the guest.
	write(0x5e0, 1)
	write(0x4b4, 3)
	write(0x4bc, 33)
	if options := read(0x414); options != 0x18 {
		t.Fatalf("XMAP hardware options = %#x", options)
	}
	write(0x4bc, 0)
	for channel := uint32(0); channel < 3; channel++ {
		for i := uint32(0); i < 256; i++ {
			write(0x504+channel*0x20, i)
		}
	}
	write(0xc00, 0)
	read(0) // A microstore read selects the sequencer entry point.
	write(0x640, 0)

	if stop, err := m.Run(context.Background(), 20, false); err != nil || stop.Kind != "budget" {
		t.Fatalf("start sequencer: %+v %v", stop, err)
	}
	if m.graphics.ge.wait != ge5WaitFIFO {
		t.Fatal("sequencer did not wait for the first token")
	}
	write(0x804, 0)
	for _, r := range registers {
		write(0x800, r.value)
	}
	if stop, err := m.Run(context.Background(), 120, false); err != nil || stop.Kind != "budget" {
		t.Fatalf("run sequencer: %+v %v", stop, err)
	}
	if flag := read(0x2000); flag != 1 || m.graphics.raster.drawn != 2 {
		t.Fatalf("finish = %d, pixels = %d", flag, m.graphics.raster.drawn)
	}
	screen := m.graphics.screen()
	for x := 3; x < 5; x++ {
		if got := screen.RGBAAt(x, gr1Height-1-4); got.R != 0x3d || got.G != 0x8e || got.B != 0xf2 {
			t.Fatalf("pixel %d: %v", x, got)
		}
	}
}

func TestGE5BranchSamplesPriorFloatingPointCondition(t *testing.T) {
	var ge ip12GE5
	var raster ip12RE2
	ge.fpu.regs[1] = 0x3f800000 // 1.0
	ge.fpu.regs[2] = 0x40000000 // 2.0
	const memoryToBus = 2<<38 | 1<<33
	const subtract = 2<<26 | 1<<21 | 2<<16 | 3<<11 | 1<<3
	const addZero = 3<<26 | 7<<3 | 3<<1
	ge.code[0] = memoryToBus | subtract
	for i := 1; i < 5; i++ {
		ge.code[i] = memoryToBus | addZero
	}
	ge.code[5] = memoryToBus | 1<<36 | 2<<29 | addZero
	ge.code[6] = 0xbc<<32 | 9<<19
	for range 6 {
		ge.step(&raster, false, nil, nil)
	}
	if ge.pc != 9 {
		t.Fatalf("negative branch PC = %d, want 9", ge.pc)
	}
}

func TestIP12KeyboardConfigurationAndMousePacket(t *testing.T) {
	m := newTestIP12(t)
	const keyboardData = 0x1fb80d0f
	const mouseData = 0x1fb80d07
	keyboard, mouse := &m.scc[0].ports[0], &m.scc[0].ports[1]
	keyboard.wr[3], keyboard.wr[5] = 1, 8
	mouse.wr[3] = 1

	if !m.writeBus(keyboardData, 1, 0x10) {
		t.Fatal("keyboard configuration command was not mapped")
	}
	m.keyboard.deliver(keyboard, ip12KeyboardFrame-1, ip12KeyboardFrame)
	if keyboard.rxReady {
		t.Fatal("keyboard replied before the serial frame completed")
	}
	for i, want := range []uint32{0x6e, 0} {
		m.keyboard.deliver(keyboard, uint64(i+1)*ip12KeyboardFrame, ip12KeyboardFrame)
		if !keyboard.rxReady {
			t.Fatalf("keyboard byte %d was not delivered", i)
		}
		if got, ok := m.readBus(keyboardData, 1); !ok || got != want {
			t.Fatalf("keyboard configuration byte %d = %#x, want %#x", i, got, want)
		}
	}
	if err := m.KeyCode(7, false); err != nil {
		t.Fatal(err)
	}
	m.keyboard.deliver(keyboard, 3*ip12KeyboardFrame, ip12KeyboardFrame)
	if got, ok := m.readBus(keyboardData, 1); !ok || got != 0x87 {
		t.Fatalf("keyboard release = %#x", got)
	}

	if err := m.Mouse(-6, 20, 4); err != nil {
		t.Fatal(err)
	}
	for i, want := range []uint32{0x83, 0xfa, 20, 0, 0} {
		m.mouse.deliver(mouse, uint64(i+1)*ip12MouseFrame, ip12MouseFrame)
		if !mouse.rxReady {
			t.Fatalf("mouse byte %d was not delivered", i)
		}
		if got, ok := m.readBus(mouseData, 1); !ok || got != want {
			t.Fatalf("mouse byte %d = %#x, want %#x", i, got, want)
		}
	}
}

func TestIP12DoublePrecisionRegisterWordOrder(t *testing.T) {
	m := newTestIP12(t)
	program := testECOFF(0x80002000,
		0x3c088000, // lui t0, 0x8000
		0xc5013000, // lwc1 f1, 0x3000(t0), high word in big-endian RAM
		0xc5003004, // lwc1 f0, 0x3004(t0), low word
		0,
		0x46200080, // add.d f2, f0, f0
		0xe5033008, // swc1 f3, 0x3008(t0), high word
		0xe502300c, // swc1 f2, 0x300c(t0), low word
		0x0000000d,
	)
	if err := m.Load(program, nil, nil); err != nil {
		t.Fatal(err)
	}
	m.cpu.cp0[status] |= 1 << 29
	m.writeBus(0x3000, 4, 0x3ff80000) // 1.5
	stop, err := m.Run(context.Background(), 20, true)
	if err != nil || stop.Exception != 9 {
		t.Fatalf("run: %+v %v", stop, err)
	}
	var result [8]byte
	if err := m.Read(0x3008, result[:]); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint64(result[:]); got != 0x4008000000000000 {
		t.Fatalf("1.5 + 1.5 = %#x, want 3.0", got)
	}
}

func TestIP12GraphicsDMAWaitsForPICAndTransfersContext(t *testing.T) {
	m := newTestIP12(t)
	if err := m.Load(testECOFF(0x80002000, 0x08000800, 0), nil, nil); err != nil {
		t.Fatal(err)
	}
	ge := &m.graphics.ge
	ge.wait = ge5Running
	ge.code[0] = 2<<38 | 1<<35 | 1<<33 | 15<<29 // GE SRAM to host
	ge.code[1] = 1<<38 | 1<<35 | 2<<33 | 15<<29 // Host to GE SRAM
	ge.code[2] = 2<<38 | 1<<33 | 12<<29         // Stall
	ge.data[1], ge.data[2], ge.dmaCount = 0x12345678, 0x90abcdef, 2

	// Two outbound descriptors followed by one inbound descriptor.
	for i, descriptor := range [][5]uint32{
		{0x4000, ip12GDMAToRAM | 4, 0, 0, 0x3014},
		{0x4100, ip12GDMAToRAM | 4, 0, 0, 0x3028},
		{0x4200, ip12GDMAEnd | 4, 0, 0, 0},
	} {
		for j, word := range descriptor {
			m.writeBus(0x3000+uint32(i*20+j*4), 4, word)
		}
	}
	m.writeBus(0x4200, 4, 0x05274819)
	run := func() {
		t.Helper()
		stop, err := m.Run(context.Background(), 100, false)
		if err != nil || stop.Kind != "budget" {
			t.Fatalf("run: %+v %v", stop, err)
		}
	}
	run()
	if ge.wait != ge5WaitDMA || ge.memptr != 0 || ge.dmaCount != 2 {
		t.Fatalf("GE made progress before the PIC started")
	}
	if !m.writeBus(ip12GDMARegisters, 4, 0x3000) || !m.writeBus(ip12GDMAStart, 4, 0) {
		t.Fatal("PIC graphics DMA start was not mapped")
	}
	if status, _ := m.readBus(ip12PICBase+8, 4); status&8 != 0 {
		t.Fatalf("PIC reported DMA idle while active")
	}
	run()
	a, _ := m.readBus(0x4000, 4)
	b, _ := m.readBus(0x4100, 4)
	status, _ := m.readBus(ip12PICBase+8, 4)
	if a != 0x12345678 || b != 0x90abcdef || ge.data[3] != 0x05274819 || ge.queued != 0 {
		t.Fatalf("DMA transferred RAM %#x/%#x, GE SRAM %#x, FIFO %d", a, b, ge.data[3], ge.queued)
	}
	if status&12 != 8 || m.gdma.words != 3 || ge.wait != ge5Halted {
		t.Fatalf("PIC status = %#x, transferred words = %d, GE state = %d", status, m.gdma.words, ge.wait)
	}
}
