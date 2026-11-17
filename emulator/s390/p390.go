package s390

import (
	"encoding/binary"
	"fmt"
)

const (
	P390ApertureSize = 4 << 20
	p390Combuf       = 0x20000
	p390Mailbox      = p390Combuf + 0x40
)

// P390Operation is a bounded observation of an original host monitor request.
// Arguments and options retain the bytes before the operation mutates replies.
type P390Operation struct {
	Kind      string
	Command   byte
	Arguments [12]byte
	Options   [6]byte
}

// P390 implements the host-facing monitor ABI using the architectural engine,
// not an interpreter for IBM's private 128-bit ASIC microinstructions. Uploaded
// microstore bytes remain available for inspection, but are not executed.
// Unsupported monitor commands fail explicitly, without publishing completion.
// All calls belong to one device owner; this value has no host I/O or goroutines.
type P390 struct {
	Machine          *Machine
	Aperture         []byte
	windows          [15]bool
	Initialized      bool
	Initializations  uint64
	MonitorLoads     uint64
	microstoreDirty  bool
	Commands         uint64
	LastCommand      byte
	LastError        string
	CacheMegabytes   byte
	StepCount        uint32
	StepRemaining    uint64
	ManualCommands   uint64
	LastManual       byte
	interrupts       [512]Subchannel
	IOStatusReports  uint64
	IOPending        bool
	IOInstruction    uint16
	ioSubchannel     uint16
	ipl              *p390IPL
	IORequests       uint64
	IOCompletions    uint64
	IOAborted        uint64
	InterruptPending bool
	InterruptReason  byte
	Operations       []P390Operation
	RunReason        StopReason
}

func NewP390(memory int) (*P390, error) {
	return NewP390WithConfig(Config{Memory: memory, CPUs: 1, CPUModel: 0x7490})
}

// NewP390WithConfig selects the native architectural CPU and initial clock.
// The original OS/2 host transport remains the ESA-format monitor ABI even
// when the explicit S/370 compatibility CPU is selected. It is not ASIC mode emulation.
func NewP390WithConfig(cfg Config) (*P390, error) {
	memory := cfg.Memory
	if cfg.CPUs != 0 && cfg.CPUs != 1 {
		return nil, fmt.Errorf("p390: exactly one CPU is supported")
	}
	cfg.CPUs = 1
	if memory < 1<<20 || memory > 128<<20 || memory&0xffff != 0 {
		return nil, fmt.Errorf("p390: storage must be 1..128 MiB in 64 KiB units")
	}
	p := &P390{Machine: NewMachine(cfg), Aperture: make([]byte, P390ApertureSize)}
	p.Machine.p390 = p
	return p, nil
}

// byteView resolves a PCI memory byte. An unprogrammed window retains its
// private communication area; programmed windows select architectural storage.
// AWS370DD supplies little-endian 32-bit descriptors; consumers retain the
// low twelve bits as the offset in the selected frame.
func (p *P390) byteView(off uint32) ([]byte, uint32, error) {
	if off >= P390ApertureSize {
		return nil, 0, fmt.Errorf("p390: aperture offset %#x", off)
	}
	// AWS370DD IOCTL 5e maps BAR1+10000 for the PCI card (2e00).
	// The ESA host indexes one byte per 4K, independently of the CPU's
	// architectural key size. A 2K-key CPU can expose a 4K protection key
	// only when both halves agree; ReadAperture rejects mixed protection.
	// R/C bits are aggregated, and host 4K writes update both halves.
	if off >= 0x10000 && off < 0x20000 && off-0x10000 < uint32(len(p.Machine.S.Mem)>>12) {
		return p.Machine.S.Keys, (off - 0x10000) << (12 - p.Machine.S.KeyShift), nil
	}
	if off >= 0x20000 && off < 0x200000 {
		window := (off - 0x20000) >> 17
		if p.windows[window] {
			descriptor := binary.LittleEndian.Uint32(p.Aperture[0x210+window*16:])
			address := uint64(descriptor&0xfffff000) + uint64((off-0x20000)&0x1ffff)
			if address >= uint64(len(p.Machine.S.Mem)) {
				return nil, 0, fmt.Errorf("p390: window %d descriptor %#x exceeds storage at %#x", window, descriptor, address)
			}
			return p.Machine.S.Mem, uint32(address), nil
		}
	}
	return p.Aperture, off, nil
}

// mappedStorage distinguishes architectural storage from the private monitor
// and direct key array. Host device-manager transfers are channel storage
// accesses: their reference/change bits must be visible to guest RRB/ISK.
func (p *P390) mappedStorage(off uint32) bool {
	return off >= 0x20000 && off < 0x200000 && p.windows[(off-0x20000)>>17]
}

// hostKeyPair identifies the explicitly restricted 4K host view of 2K keys.
// It never changes the CPU's key geometry or bypasses channel protection.
func (p *P390) hostKeyPair(off uint32) bool {
	return p.Machine.S.KeyShift == 11 && off >= 0x10000 && off < 0x20000 && off-0x10000 < uint32(len(p.Machine.S.Mem)>>12)
}

func (p *P390) ReadAperture(off uint32, data []byte) error {
	if uint64(off)+uint64(len(data)) > P390ApertureSize {
		return fmt.Errorf("p390: aperture read exceeds range")
	}
	for i := range data {
		src, at, err := p.byteView(off + uint32(i))
		if err != nil {
			return err
		}
		data[i] = src[at]
		if p.hostKeyPair(off + uint32(i)) {
			if (src[at]^src[at+1])&0xf8 != 0 {
				return fmt.Errorf("p390: ESA 4K key view cannot represent mixed S/370 protection keys at %#x: %02x/%02x", (off+uint32(i)-0x10000)<<12, src[at], src[at+1])
			}
			data[i] |= src[at+1] & (keyRef | keyChg)
		}
		if p.mappedStorage(off + uint32(i)) {
			*p.Machine.S.key(at) |= keyRef
		}
	}
	return nil
}

func (p *P390) WriteAperture(off uint32, data []byte) error {
	if uint64(off)+uint64(len(data)) > P390ApertureSize {
		return fmt.Errorf("p390: aperture write exceeds range")
	}
	for i := range data {
		if _, _, err := p.byteView(off + uint32(i)); err != nil {
			return err
		}
	}
	// A new bootstrap/LIC upload starts a new monitor lifetime at service 02.
	// CPU-only resets must not detach live original OS/2 device managers.
	if len(data) != 0 && uint64(off)+uint64(len(data)) > 0x200000 {
		p.microstoreDirty = true
	}
	changedStorage := false
	for i, b := range data {
		dst, at, _ := p.byteView(off + uint32(i))
		dst[at] = b
		if p.hostKeyPair(off + uint32(i)) {
			dst[at+1] = b
		}
		if p.mappedStorage(off + uint32(i)) {
			*p.Machine.S.key(at) |= keyRef | keyChg
		}
		if off+uint32(i) >= 0x10000 && off+uint32(i) < 0x200000 {
			changedStorage = true
		}
	}
	if changedStorage {
		for _, c := range p.Machine.CPUs {
			c.purgeTLB()
		}
	}
	for window := range p.windows {
		reg := uint32(0x210 + window*16)
		if off < reg+4 && uint64(off)+uint64(len(data)) > uint64(reg) {
			// AWSCHAN D28c polls the descriptor until the card has latched
			// its page address. Low twelve operand-offset bits read as zero.
			descriptor := binary.LittleEndian.Uint32(p.Aperture[reg:])
			binary.LittleEndian.PutUint32(p.Aperture[reg:], descriptor&^0xfff)
			p.windows[window] = true
		}
	}
	if off <= 0x101 && uint64(off)+uint64(len(data)) > 0x101 && p.Aperture[0x101]&1 != 0 {
		// Original MANOPS Control -> External Interrupt writes PCS+101=01.
		// Queue an interrupt-key condition: PSW/CR0 masking and stopped
		// state are handled by the architectural engine, not a PCI IRQ.
		p.Machine.CPUs[0].extPending |= extInterruptKey
		p.Aperture[0x101] &^= 1
	}
	if off <= 0x101 && uint64(off)+uint64(len(data)) > 0x101 && p.Aperture[0x101]&4 != 0 {
		if p.IOPending {
			if err := p.completeChannel(); err != nil {
				return err
			}
		}
		if err := p.completeHostIO(); err != nil {
			return err
		}
		p.Aperture[0x101] &^= 4
	}
	if off <= 0x101 && uint64(off)+uint64(len(data)) > 0x101 && binary.LittleEndian.Uint16(p.Aperture[0x100:])&0x200 != 0 {
		if err := p.manual(); err != nil {
			return err
		}
		binary.LittleEndian.PutUint16(p.Aperture[0x100:], binary.LittleEndian.Uint16(p.Aperture[0x100:])&^0x200)
	}
	if off <= 0x103 && uint64(off)+uint64(len(data)) > 0x103 && p.Aperture[0x103] == 0x60 {
		return p.service()
	}
	return nil
}

func (p *P390) observe(kind string, command byte) {
	op := P390Operation{Kind: kind, Command: command}
	copy(op.Arguments[:], p.Aperture[p390Combuf+0x34:p390Combuf+0x40])
	copy(op.Options[:], p.Aperture[p390Combuf+0x5e:p390Combuf+0x64])
	if len(p.Operations) == 32 {
		copy(p.Operations, p.Operations[1:])
		p.Operations = p.Operations[:31]
	}
	p.Operations = append(p.Operations, op)
}

func (p *P390) service() error {
	command := p.Aperture[p390Mailbox+3]
	if command == 0 || p.Aperture[p390Mailbox] == 0xff {
		return nil
	}
	p.observe("service", command)
	p.Commands++
	p.LastCommand = command
	p.LastError = ""
	if p.ipl != nil {
		return fmt.Errorf("p390: service request during IPL")
	}
	switch command {
	case 2:
		p.discardCPUAssist()
		// AWSMAIN's post-LIC-load initialize helper (259c..26a7) issues
		// selector 2, then requires a nonzero BE monitor version at +6.
		// Publish OUR ABI revision 0100, not IBM's uploaded LIC revision.
		for _, c := range p.Machine.CPUs {
			c.resetCPU(false)
		}
		p.RunReason = StopReason{Kind: "stopped"}
		if !p.Initialized || p.microstoreDirty {
			// Private catalog entries contain process-lifetime OS/2 far
			// pointers. They cannot survive a new monitor upload/host launch.
			p.resetChannels()
			clear(p.Aperture[p390Subchannels : p390Subchannels+512*64])
			// SCHIBINI consumes this before installing its private entries.
			// It is not a permanent field in an active channel catalog.
			p.Aperture[p390Subchannels+0x68] = 0xff
			p.MonitorLoads++
			p.microstoreDirty = false
		}
		p.Initialized = true
		p.Initializations++
		// SF mailbox dispatch is understood by AWS370DD 23b9..2744.
		p.Aperture[p390Combuf], p.Aperture[p390Combuf+1] = 0xe2, 0xc6
		// AWSMAIN 0EF9..0F09 reads COMBUF+02 on a subsequent launch and
		// appends it as the numeric suffix of AWS39Xn.MCD. It is the
		// microcode-family selector, NOT the architectural mode. This
		// adapter implements family zero; +62 below selects the ESA ABI.
		p.Aperture[p390Combuf+2] = 0
		// AWSCHAN calls SCHIBINI only with the ESA catalog flag set.
		p.Aperture[p390Combuf+0x62] = 3 // MANOPS 60ed..613b: ESA/390, including ARs.
		binary.BigEndian.PutUint16(p.Aperture[p390Combuf+6:], 0x0100)
		binary.BigEndian.PutUint32(p.Aperture[p390Mailbox+4:], uint32(len(p.Machine.S.Mem)-1))
	case 4:
		// AWSMAIN's CACHE argument is shifted into commbuf+5e's high
		// nibble (1eb9..1edb). MANOPS warns that changing this setting
		// performs a system reset. Bit 08 at +5f is its SIM2KEY option.
		// The architectural engine has coherent storage, not cache timing.
		if !p.Initialized {
			return fmt.Errorf("p390: cache configuration before monitor initialization")
		}
		p.discardCPUAssist()
		p.RunReason = StopReason{Kind: "stopped"}
		if p.Aperture[p390Combuf+0x5f]&0x80 != 0 {
			p.CacheMegabytes = p.Aperture[p390Combuf+0x5e] >> 4
			for _, c := range p.Machine.CPUs {
				c.resetCPU(false)
			}
		} else {
			// MANOPS Resets -> System Reset Clear issues service 04,
			// then 02 and channel reset 24. With +5f bit 80 clear this
			// is storage/register clearing, not cache configuration.
			clear(p.Machine.S.Mem)
			clear(p.Machine.S.Keys)
			for _, c := range p.Machine.CPUs {
				c.Reset(true)
			}
		}
		shift := uint(12)
		if p.Machine.S370 || p.Aperture[p390Combuf+0x5f]&8 != 0 {
			shift = 11
		}
		if p.Machine.S.KeyShift != shift {
			p.Machine.S.setKeyBlock(shift)
		}
		for _, c := range p.Machine.CPUs {
			c.purgeTLB()
		}
		binary.BigEndian.PutUint32(p.Aperture[p390Mailbox+4:], uint32(len(p.Machine.S.Mem)-1))
	case 6:
		p.discardCPUAssist()
		p.RunReason = StopReason{Kind: "stopped"}
		// MANOPS Resets -> Initial CPU Reset uses IOCTL47 selector3,
		// which AWS370DD 089a translates to service06. The returned
		// storage top is also read by P370InstalledStorageSizeInBytes;
		// that export reads the retained result, not a new reset request.
		for _, c := range p.Machine.CPUs {
			c.resetCPU(true)
		}
		binary.BigEndian.PutUint32(p.Aperture[p390Mailbox+4:], uint32(len(p.Machine.S.Mem)-1))
	default:
		p.LastError = fmt.Sprintf("p390: unsupported monitor command %#02x", command)
		return fmt.Errorf("%s", p.LastError)
	}
	p.publishCPU()
	p.Aperture[p390Mailbox] = 0xff
	return nil
}

// publishCPU is the BE architectural image read by MANOPS: PSW at +08,
// general registers at +80, and stopped indication at +63 bit 04. The
// manual request word at +32 is retained for the caller's completion path.
func (p *P390) publishCPU() {
	c := p.Machine.CPUs[0]
	if !p.IOPending {
		binary.BigEndian.PutUint64(p.Aperture[p390Combuf+8:], c.PSW.Encode())
	}
	// The register-dialog snapshot is separate from the execution PSW.
	binary.BigEndian.PutUint64(p.Aperture[p390Combuf+0x48:], c.PSW.Encode())
	for r, v := range c.GR {
		binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x80+r*4:], v)
	}
	for r, v := range c.CR {
		binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xc0+r*4:], v)
	}
	for r, v := range c.AR {
		binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x100+r*4:], v)
	}
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x64:], c.Prefix)
	// MANOPS 68b7..68cf selects +180 for the four legacy HFP
	// doublewords, displayed as eight 32-bit words.
	for r := 0; r < 4; r++ {
		binary.BigEndian.PutUint64(p.Aperture[p390Combuf+0x180+r*8:], c.FPR[r*2])
	}
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xe0c:], uint32(p.StepRemaining))
	p.Aperture[p390Combuf+0x63] &^= 4
	if c.Stopped || c.Check {
		p.Aperture[p390Combuf+0x63] |= 4
	}
}

func (p *P390) manual() error {
	request := p.Aperture[p390Combuf+0x33]
	p.observe("manual", request)
	p.ManualCommands++
	p.LastManual = request
	c := p.Machine.CPUs[0]
	if p.ipl != nil {
		return fmt.Errorf("p390: manual request during IPL")
	}
	switch request {
	case 0x20, 0x21: // MANOPS normal/clear IPL, driver selectors 14/15.
		return p.startIPL(request == 0x21)
	case 0x06: // MANOPS instruction-step Set, driver selector 1.
		count := binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x34:])
		if count == 0 {
			return fmt.Errorf("p390: zero instruction-step count is unsupported")
		}
		p.StepCount, p.StepRemaining = count, uint64(count)
		p.Aperture[p390Combuf+0x61] |= 1
		binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xe08:], count)
	case 0x08: // MANOPS instruction-step Reset, driver selector 2.
		p.StepCount, p.StepRemaining = 0, 0
		p.Aperture[p390Combuf+0x61] &^= 1
	case 0x30: // MANOPS Control -> Restart (AWS370DD selector 10).
		if c.Check {
			return fmt.Errorf("p390: RESTART requires reset after check-stop")
		}
		c.Restart()
		p.StepRemaining = uint64(p.StepCount)
		p.RunReason = StopReason{Kind: "running"}
	case 0x1f: // Original MANOPS Control -> Store Status (driver selector 13).
		if !c.Stopped || !c.S.valid(c.Prefix, 0x200) {
			return fmt.Errorf("p390: store status requires a stopped CPU and valid prefix")
		}
		c.storeStatus(c.Prefix)
		c.purgeTLB()
	case 0x22:
		// Original AWSIPL's non-clearing path: normal reset (02), 22,
		// initial reset (06). Its clearing path skips 22. MANOPS also
		// uses it before channel reset/IPL on the PCI adapter. No arguments
		// or architectural result are consumed by either client.
		// Implement this observed pre-reset synchronization boundary, NOT
		// an invented storage clear or a claim to execute private ASIC LIC.
		// The single-owner engine has no deferred host writes or hardware
		// cache to drain; invalidate translations before acknowledging it.
		if !p.Initialized || !c.Stopped || p.IOPending {
			return fmt.Errorf("p390: preparation requires an initialized, stopped, idle CPU")
		}
		c.purgeTLB()
	case 0x24: // MANOPS 44ec: reset channel before draining IOCMP/ENDIO queues.
		p.Machine.CSS.reset()
		p.resetChannels()
	case 0x18: // MANOPS commits a changed register image with masks at +34.
		if !c.Stopped {
			return fmt.Errorf("p390: register edit requires a stopped CPU")
		}
		mask := binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x34:])
		// MANOPS 606e..60c8 uses its BE mask table at data+f60:
		// GR=1, CR=2, legacy FP=4, PSW=8, prefix=10, AR=20.
		// Prefix is packed in the high 20 bits of the mask; PSW is
		// passed in the following two words, not the snapshot at +48.
		allowed := uint32(0x3f)
		if mask&0x10 != 0 {
			allowed |= 0xfffff000
		}
		psw := binary.BigEndian.Uint64(p.Aperture[p390Combuf+0x38:])
		if mask&^allowed != 0 || mask&8 == 0 && psw != 0 {
			return fmt.Errorf("p390: unsupported register-edit arguments")
		}
		// Validate every potentially failing bank before changing any CPU
		// state: an invalid PSW/prefix must not partially commit GR/CR.
		if mask&8 != 0 {
			if _, ok := c.decodePSW(psw); !ok {
				return fmt.Errorf("p390: register edit has invalid PSW %016x", psw)
			}
		}
		prefix := mask & 0x7ffff000
		if mask&0x10 != 0 && !c.S.valid(prefix, 4096) {
			return fmt.Errorf("p390: register edit has invalid prefix %08x", prefix)
		}
		// MANOPS editing either R8 or R9 writes the same mask 1: it
		// selects the whole GPR bank, not a bit for one register.
		if mask&1 != 0 {
			for r := range c.GR {
				c.GR[r] = binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x80+r*4:])
			}
		}
		if mask&2 != 0 {
			for r := range c.CR {
				c.CR[r] = binary.BigEndian.Uint32(p.Aperture[p390Combuf+0xc0+r*4:])
			}
			c.purgeTLB()
		}
		if mask&4 != 0 {
			for r := 0; r < 4; r++ {
				c.FPR[r*2] = binary.BigEndian.Uint64(p.Aperture[p390Combuf+0x180+r*8:])
			}
		}
		if mask&0x20 != 0 {
			for r := range c.AR {
				c.AR[r] = binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x100+r*4:])
			}
			c.purgeTLB()
		}
		if mask&0x10 != 0 {
			c.Prefix = prefix
			c.purgeTLB()
		}
		if mask&8 != 0 {
			c.loadPSW(psw)
			c.next = c.PSW.IA
			c.pswChanged = true
		}
	case 0x1a: // AWS370DD manual selector 8: MANOPS general-register snapshot.
		// publishCPU below copies the live architectural GR bank to +80.
	case 0x14: // MANOPS STOP: 1aa9 -> 48d2; waits for +63 bit 04.
		c.Stopped = true
		p.RunReason = StopReason{Kind: "stopped"}
	case 0x12: // The alternate START branch at MANOPS 1ac0.
		if c.Check {
			return fmt.Errorf("p390: START requires reset after check-stop")
		}
		psw := binary.BigEndian.Uint64(p.Aperture[p390Combuf+8:])
		if _, ok := c.decodePSW(psw); !ok {
			return fmt.Errorf("p390: START has invalid PSW %016x", psw)
		}
		c.loadPSW(psw)
		c.next = c.PSW.IA
		c.pswChanged = true
		for r := range c.GR {
			c.GR[r] = binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x80+r*4:])
		}
		c.purgeTLB()
		c.Stopped = false
		p.StepRemaining = uint64(p.StepCount)
		p.RunReason = StopReason{Kind: "running"}
	default:
		p.LastError = fmt.Sprintf("p390: unsupported manual request %#02x", request)
		return fmt.Errorf("%s", p.LastError)
	}
	p.publishCPU()
	// MANOPS 49ef..4a35 accepts a nonzero word, but the original driver
	// 0798..07a1 requires byte +30 == ff for successful completion.
	binary.BigEndian.PutUint16(p.Aperture[p390Combuf+0x30:], 0xff00)
	return nil
}

// AcknowledgeInterrupt releases the PCI interrupt latch. Mailbox contents are
// retained for the host driver; acknowledgment does not repeat CPU execution.
func (p *P390) AcknowledgeInterrupt() {
	p.InterruptPending = false
	p.InterruptReason = 0
	p.Aperture[0x100] &^= 0x10
}

// ResetAdapter asserts the hardware reset line, halting the processor and
// invalidating monitor/window state. Like CPU reset it preserves main storage.
func (p *P390) ResetAdapter() {
	for _, c := range p.Machine.CPUs {
		c.Reset(true)
		c.Check = false
	}
	p.Machine.CSS.reset()
	p.Initialized = false
	p.microstoreDirty = false
	p.StepCount, p.StepRemaining = 0, 0
	p.interrupts = [512]Subchannel{}
	p.discardCPUAssist()
	p.ipl = nil
	p.windows = [15]bool{}
	clear(p.Aperture)
	p.AcknowledgeInterrupt()
	p.RunReason = StopReason{Kind: "adapter-reset"}
}

func (p *P390) Running() bool {
	c := p.Machine.CPUs[0]
	return p.Initialized && p.ipl == nil && !p.IOPending && !c.Stopped && !c.Check
}

// Advance executes a bounded slice on the same device-owner thread. It never
// runs the host CPU concurrently with monitor/storage mutation.
func (p *P390) Advance(budget uint64) {
	if !p.Running() {
		return
	}
	c := p.Machine.CPUs[0]
	before := c.Instructions
	if p.StepCount != 0 {
		budget = min(budget, p.StepRemaining)
	}
	p.RunReason = p.Machine.Run(budget)
	if p.StepCount != 0 {
		p.StepRemaining -= min(p.StepRemaining, c.Instructions-before)
		if !p.IOPending && !c.Check && p.StepRemaining == 0 {
			p.finishStep()
		}
	}
	if p.RunReason.Kind == "check-stop" {
		p.Machine.CPUs[0].Stopped = true
		// A check-stop is not an invented host-kernel instruction.
		// In particular, invented request 0400 makes AWSINTF log KRN901.
		// Disabled wait, unlike check-stop or operator STOP, leaves the
		// architectural CPU operating (Wait=true, Stopped=false). The host
		// must not mistake it for an operator stop and tear down its worker.
		// A check-stop remains available through RunReason, not a fabricated
		// IBM instruction-step/PER/address-compare stop notification.
	}
	p.publishCPU()
}

// finishStep reports a genuine instruction-count stop. AWSINTF 0431/04d8
// recognises 0406 as KRN041, distinct from a disabled wait or check-stop.
// It is a stop notification, not a channel assist awaiting a condition code.
func (p *P390) finishStep() {
	c := p.Machine.CPUs[0]
	c.Stopped = true
	p.RunReason = StopReason{Kind: "instruction-step"}
	base := p390Combuf + 0x10
	clear(p.Aperture[base : base+16])
	binary.BigEndian.PutUint16(p.Aperture[base+2:], 0x0406)
	p.Aperture[0x100] |= 0x10
	p.InterruptPending, p.InterruptReason = true, 1
}
