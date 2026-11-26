package s390

import "fmt"

const (
	rkmMemorySize9020E = 1 << 15
	// The FAA permits 167 ms for completion. Model one operator byte
	// every 4 us, so a full 32 KiB pass fits inside that window.
	rkmOperatorCycle9020E = 4 * todMicro
	// Model console exchange as one scheduled cycle. The reply timeout
	// uses the midpoint of the documented 36–54 ms range (Appendix K).
	rkmConsoleCycle9020E = 1000 * todMicro
	rkmQueueReply9020E   = 45000 * todMicro
	rkmConstants9020E    = 0x3ff8
)

type rkm9020E struct {
	Memory       *[rkmMemorySize9020E]byte
	Address      uint16
	Queue        uint16
	Polling      bool
	Operator     rkmOperator9020E
	Consoles     [32]rkmConsole9020E
	FetchAt      uint64
	FetchConsole byte
	FetchDAU     int
	AttentionA   bool
	Interrupted  bool
	Input        []rkmInput9020E
	PollAt       uint64
	ReplyBy      uint64
	PollDAU      int
	AttentionB   bool
	ConsoleEntry bool
	PausedAt     uint64
}

type rkmConsole9020E struct {
	Attached  bool
	Constants [8]byte
}

type rkmInput9020E struct {
	Code, Data byte
}

// The console selectors are addressed by their active RKM group. Groups
// 1 and 2 share RKM 3. The independent expansion group uses RKM 5.
// IBM 9020 D/E System Design Data, figure 10-7 and table 10-8, and
// FAA DB8B3100, CONFRCON and RCONINV.
var rkmConsoleRoutes9020E = [...]struct{ offset, spare uint16 }{
	{16, 3}, // RCON1
	{17, 3}, // RCON2
	{},      // Direct connection to RKM3
	{27, 5}, // RCON4
	{},      // Direct connection to RKM5
}

func (s *ChannelSubsystem) rkmConsoleDestination(number, position uint16) uint16 {
	route := rkmConsoleRoutes9020E[number-1]
	if route.spare != 0 {
		console := &s.rcuEndpoints9020[route.offset]
		if console.RCONConfigured && console.Configuration[position/8]&(0x80>>(position%8)) == 0 {
			return route.spare
		}
	}
	return number
}

func (s *ChannelSubsystem) rkmConsoleSource(number, position uint16) *rkm9020E {
	var source *rkm9020E
	for i, route := range rkmConsoleRoutes9020E {
		group := uint16(i + 1)
		if group != number && route.spare != number {
			continue
		}
		e := s.radarKeyboard9020E(group)
		if e != nil && e.RKM.Consoles[position].Attached && s.rkmConsoleDestination(group, position) == number {
			if source != nil {
				return nil // Conflicting assignments to the same spare input.
			}
			source = &e.RKM
		}
	}
	return source
}

// AttachRKMConsole connects a 9020E console position and supplies its
// eight raw display constants. Specify the active RKM for a switched
// console or the wired RKM for a direct connection.
func (s *ChannelSubsystem) AttachRKMConsole(rkm, position uint16, constants [8]byte) error {
	e := s.radarKeyboard9020E(rkm)
	if e == nil || int(position) >= len(e.RKM.Consoles) {
		return fmt.Errorf("invalid 9020E RKM %d console position %d", rkm, position)
	}
	e.RKM.Consoles[position] = rkmConsole9020E{Attached: true, Constants: constants}
	return nil
}

// QueueRKMInput supplies a three-bit console operation and its data byte
// for delivery on the next poll of an attached console.
func (s *ChannelSubsystem) QueueRKMInput(rkm, position, operation uint16, data byte) error {
	e := s.radarKeyboard9020E(rkm)
	if e == nil || int(position) >= len(e.RKM.Consoles) || !e.RKM.Consoles[position].Attached {
		return fmt.Errorf("no console at 9020E RKM %d position %d", rkm, position)
	}
	if operation > 7 {
		return fmt.Errorf("invalid RKM console operation %d", operation)
	}
	r := &e.RKM
	r.Input = append(r.Input, rkmInput9020E{Code: byte(operation<<5 | position), Data: data})
	s.scheduleRKMPoll(s.rkmConsoleDestination(rkm, position))
	s.reschedule()
	return nil
}

func (s *ChannelSubsystem) scheduleRKMPoll(number uint16) {
	e := s.radarKeyboard9020E(number)
	if e != nil && !e.Stopped && !e.InterfacesOff && e.RKM.Polling && e.RKM.PollAt == 0 {
		e.RKM.PollAt = s.m.tod + rkmConsoleCycle9020E
	}
}

func (s *ChannelSubsystem) schedulePendingRKMInput() {
	for i, offset := range rkmOffsets9020E {
		for _, entry := range s.rcuEndpoints9020[offset].RKM.Input {
			s.scheduleRKMPoll(s.rkmConsoleDestination(uint16(i+1), uint16(entry.Code&31)))
		}
	}
}

func (s *ChannelSubsystem) pollRKM(number uint16, e *rcuEndpoint9020, at uint64) {
	r := &e.RKM
	r.PollAt = 0
	written := false
	for position := range uint16(len(r.Consoles)) {
		if !r.Polling {
			break
		}
		source := s.rkmConsoleSource(number, position)
		if source == nil {
			continue
		}
		// Leave undelivered input on the console side of the selector
		// so that it follows a change in the mask before the next poll.
		remaining := source.Input[:0]
		for _, entry := range source.Input {
			if uint16(entry.Code&31) != position || !r.Polling {
				remaining = append(remaining, entry)
				continue
			}
			written = e.storeRKMInput(entry) || written
		}
		if len(remaining) == 0 {
			remaining = nil
		}
		source.Input = remaining
	}
	if written && !r.ConsoleEntry {
		r.ConsoleEntry, r.AttentionB, r.Interrupted = true, true, true
		r.ReplyBy = at + rkmQueueReply9020E
	}
}

func (e *rcuEndpoint9020) storeRKMInput(entry rkmInput9020E) bool {
	r := &e.RKM
	memory := r.memory()
	for i, value := range [...]byte{entry.Code, entry.Data} {
		memory[r.Queue] = value
		r.Queue = (r.Queue + 1) & (rkmMemorySize9020E - 1)
		if r.Queue == 0 {
			r.Polling = false
			e.raiseStatus(0, 0x01) // DB8B4100 routine 4 checks RCU attention.
			return i == 1
		}
	}
	return true
}

func (s *ChannelSubsystem) finishRKMFetch(number uint16, e *rcuEndpoint9020) {
	rkm := &e.RKM
	if source := s.rkmConsoleSource(number, uint16(rkm.FetchConsole)); source != nil {
		console := &source.Consoles[rkm.FetchConsole]
		copy(rkm.memory()[rkmConstants9020E:], console.Constants[:])
	} else {
		// No start is reported in RKM Error 1 without raising RCU Error Out.
		e.Status[0] |= 0x02
	}
	rkm.FetchAt = 0
	rkm.AttentionA, rkm.Interrupted = true, true
}

// Orders are the formatted bytes on the RKM interface. The FAA DB8B1100
// diagnostic exercises the 32 KiB circular memory and the modifier's
// character translation using channel commands C1/E1 and C2/E2.
func (e *rcuEndpoint9020) execRKM(order byte, data []byte, count int) ([]byte, int, bool) {
	rkm := &e.RKM
	switch {
	case order <= 2:
		return []byte{e.readRKMStatus(order)}, 0, true
	case order == 0xc0: // Read Queue Address and stop polling.
		rkm.Polling, rkm.ConsoleEntry = false, false
		rkm.PollAt, rkm.ReplyBy = 0, 0
		return []byte{byte(rkm.Queue >> 8), byte(rkm.Queue)}, 0, true
	case rkmWriteOrder(order):
		for _, value := range data {
			rkm.writeRKMByte(order, value)
		}
		return nil, len(data), true
	case rkmReadOrder(order):
		out := make([]byte, count)
		for i := range out {
			out[i] = rkm.readRKMByte(order)
			rkm.advanceRKMAddress()
		}
		return out, 0, true
	}
	return nil, 0, false
}

func rkmReadOrder(order byte) bool { return order&^byte(4) == 0xd8 }

func rkmWriteOrder(order byte) bool { return order&^byte(4) == 0x98 }

func (r *rkm9020E) advanceRKMAddress() {
	r.Address = (r.Address + 1) & (rkmMemorySize9020E - 1)
}

func (r *rkm9020E) writeRKMByte(order, value byte) {
	r.memory()[r.Address] = rkmTransferByte(order, value)
	r.advanceRKMAddress()
}

func (r *rkm9020E) readRKMByte(order byte) byte {
	if r.Memory == nil {
		return 0
	}
	return rkmTransferByte(order, r.Memory[r.Address])
}

func (rkm *rkm9020E) applyRKMOperand(op rkmOperator9020E) bool {
	switch {
	case op.Order&^byte(4) == 0xa0: // Load I/O Address.
		rkm.Address = op.Target
	case op.Order&0xe8 == 0xa8: // Bit Modify.
		mask := byte(0x80 >> (op.Order & 7))
		value := &rkm.memory()[op.Target]
		*value &^= mask
		if op.Order&0x10 != 0 {
			*value |= mask
		}
	case op.Order == 0xb0 || op.Order == 0xb4: // Keyboard Write, DB8B1100 routine 7.
		memory := rkm.memory()
		memory[op.Target] = byte(op.Source)
		marker := byte(0x80)
		if op.Order&4 != 0 {
			marker = 0x08
		}
		memory[(op.Target+1)&(rkmMemorySize9020E-1)] = marker
	default:
		return false
	}
	return true
}

func (r *rkm9020E) memory() *[rkmMemorySize9020E]byte {
	if r.Memory == nil {
		r.Memory = new([rkmMemorySize9020E]byte)
	}
	return r.Memory
}

func rkmTransferByte(order, value byte) byte {
	if order&4 != 0 && value&0x3e == 0x3e {
		return value ^ 1
	}
	return value
}

// The same error latches feed Read Status at the RCU and the two
// read-to-clear error orders at the DAU (A27-2734-2, Appendix K, §3.1.3.1).
func (e *rcuEndpoint9020) readRKMStatus(order byte) byte {
	switch order {
	case 1, 2:
		index := order - 1
		status := e.Status[index]
		e.Status[index] = 0
		if order == 1 {
			// DB8B4100 checks the timeout, no-start and overflow across reads.
			e.Status[index] = status & 0x0b
		}
		if e.Status[0]|e.Status[1] == 0 {
			// Error Out is a level on the RKM configuration interface.
			e.Report = false
		}
		return status
	default:
		var status byte
		if e.RKM.FetchAt == 0 {
			status |= 0x10 // Display Constants Fetched (also set in the reset baseline).
		}
		if e.RKM.Interrupted {
			status |= 0x20
			e.RKM.Interrupted = false
		}
		if e.RKM.Operator.Order != 0 {
			status |= 0x40
		}
		if e.RKM.Polling {
			status |= 0x04
		}
		if e.RKM.ConsoleEntry {
			status |= 0x08
		}
		if e.Status[0] != 0 {
			status |= 0x01
		}
		if e.Status[1] != 0 {
			status |= 0x02
		}
		return status
	}
}

// The operator's two addresses do not wrap like the channel I/O address.
// Next is the first unexecuted storage cycle, in the machine's TOD units.
type rkmOperator9020E struct {
	Order                     byte
	Target, Source, Remaining uint16
	Next, PausedAt            uint64
	SpecialPhase              uint8
}

const (
	rkmSpecialRun       = 15
	rkmSpecialSecondRun = 35
	rkmSpecialPeriod    = 75
)

func (e *rcuEndpoint9020) prepareRKMOrder(order byte, data []byte, pending *rkmOperator9020E) (int, bool) {
	var size int
	switch {
	case order == 0x84: // Fetch Display Constants.
		if len(data) != 1 || e.RKM.FetchAt != 0 {
			e.raiseStatus(0, 0x04)
			return min(len(data), 1), true
		}
		*pending = rkmOperator9020E{Order: order, Target: uint16(data[0] & 0x1f)}
		return 1, true
	case order == 0x80 || order&^byte(4) == 0xa0 || order&0xe8 == 0xa8:
		size = 2 // Load Queue Address, Load I/O Address, Bit Modify.
	case order == 0xb0 || order == 0xb4:
		size = 3 // Keyboard Write.
	case order == 0x90 || order == 0x94 || order == 0x92 || order == 0x96:
		size = 4
	case order == 0x8c || order == 0x88: // Move Data and Special Move.
		size = 6
	default:
		return 0, false
	}
	if len(data) != size || size >= 4 && e.RKM.Operator.Order != 0 {
		e.raiseStatus(0, 0x04)
		return min(len(data), size), true
	}
	if size < 4 {
		*pending = rkmOperator9020E{Order: order, Target: be.Uint16(data) & (rkmMemorySize9020E - 1)}
		if size == 3 {
			pending.Source = uint16(data[2])
		}
		return size, true
	}
	remaining := be.Uint16(data[2:])
	if remaining == 0 {
		return size, true
	}
	*pending = rkmOperator9020E{Order: order, Target: be.Uint16(data) & (rkmMemorySize9020E - 1), Remaining: remaining}
	if size == 6 {
		pending.Source = be.Uint16(data[4:]) & (rkmMemorySize9020E - 1)
	}
	return size, true
}

// The channel need only wake for completion or overflow. An intervening
// access materializes the completed prefix at that operation's clock time.
func (op *rkmOperator9020E) deadline() uint64 {
	if op.Order == 0 || op.PausedAt != 0 {
		return 0
	}
	valid := rkmMemorySize9020E - int(op.Target)
	switch op.Order {
	case 0x8c:
		valid = min(valid, rkmMemorySize9020E-int(op.Source))
	case 0x88:
		phase := int(op.SpecialPhase)
		// Count the source bytes before phase, then locate the first
		// scheduled source read outside RKM storage in the same pattern.
		readsPerPeriod := 2 * rkmSpecialRun
		readsBeforePhase := min(phase, rkmSpecialRun) + min(max(phase-rkmSpecialSecondRun, 0), rkmSpecialRun)
		readIndex := readsBeforePhase + rkmMemorySize9020E - int(op.Source)
		period, inPeriod := readIndex/readsPerPeriod, readIndex%readsPerPeriod
		offset := period*rkmSpecialPeriod + inPeriod
		if inPeriod >= rkmSpecialRun {
			offset += rkmSpecialSecondRun - rkmSpecialRun
		}
		valid = min(valid, offset-phase)
	}
	cycles := min(int(op.Remaining), valid+1)
	return op.Next + uint64(cycles-1)*rkmOperatorCycle9020E
}

func (e *rcuEndpoint9020) advanceRKMOperator(now uint64) bool {
	rkm := &e.RKM
	op := &rkm.Operator
	if op.Order == 0 || op.PausedAt != 0 || now < op.Next {
		return false
	}
	memory := rkm.memory()
	for op.Remaining != 0 && now >= op.Next {
		phase := op.SpecialPhase
		readSource := op.Order == 0x8c || op.Order == 0x88 &&
			(phase < rkmSpecialRun || phase >= rkmSpecialSecondRun && phase < rkmSpecialSecondRun+rkmSpecialRun)
		if op.Target == rkmMemorySize9020E || readSource && op.Source == rkmMemorySize9020E {
			*op = rkmOperator9020E{}
			e.raiseStatus(1, 0x10) // Data Operator Address Overflow.
			return true
		}
		switch op.Order {
		case 0x90, 0x94:
			memory[op.Target] = 0x6c
		case 0x92:
			memory[op.Target] &^= 0x80
		case 0x96:
			memory[op.Target] |= 0x80
		case 0x88, 0x8c:
			value := byte(0x6c)
			// A forward overlap sees the previously written bytes.
			if readSource {
				value = memory[op.Source]
				op.Source++
			}
			memory[op.Target] = value
			if op.Order == 0x88 {
				// DB8B1100 routine 0E verifies the two copy runs and
				// the blank writes. DB8B3100 supplies compact source rows.
				op.SpecialPhase = (phase + 1) % rkmSpecialPeriod
			}
		}
		op.Target++
		op.Remaining--
		op.Next += rkmOperatorCycle9020E
	}
	if op.Remaining == 0 {
		*op = rkmOperator9020E{}
	}
	return false
}
