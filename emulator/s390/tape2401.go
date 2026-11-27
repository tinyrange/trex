package s390

import (
	"slices"
	"time"
)

// Tape2401 models 2401, 2415 and 2420 block transports. Sense and ending status follow the
// 2400-Series Component Descriptions (IBM A22-6866-4).
type Tape2401 struct {
	*Tape3420
	model2415 bool
}

const (
	nrziFramesPerInch = 800
	peSyncCells       = 41
	peMarkCells       = 40
	sevenTrackGap     = nrziFramesPerInch * 3 / 4
	nineTrackGap      = nrziFramesPerInch * 6 / 10
	nominalEraseGap   = nrziFramesPerInch * 7 / 2
	nrzi2415EraseGap  = nrziFramesPerInch * 15 / 4
)

// setReelEOT sets the position of the reflective end-of-tape marker on
// a reel. SIMH and AWS record boundaries do not encode it.
func (t *Tape2401) setReelEOT(inches int) {
	t.reelEOT = int64(inches) * nrziFramesPerInch
	var end int64
	for i := range t.blocks {
		end += t.blockLength(t.blocks[i])
		t.blocks[i].reelEnd = end
	}
}

func (t *Tape2401) blockGap() int64 {
	// IBM A22-6866-4 figure 8 specifies the gap by track count.
	if t.sevenTrack {
		return sevenTrackGap
	}
	return nineTrackGap
}

func (t *Tape2401) blockLength(block tapeBlock) int64 {
	density := int64(block.density)
	if density == 0 {
		switch {
		case t.sevenTrack:
			density = int64(t.density())
		case t.peOnly:
			density = 1600
		}
	}
	frames := int64(block.n)
	if density == 1600 {
		frames += int64(peFramingCells(block))
	} else if block.mark && block.leadIn != 0 {
		frames = 5 // NRZI mark and LRC span five character positions
	}
	if density != 0 && density != nrziFramesPerInch {
		frames = (frames*nrziFramesPerInch + density - 1) / density
	}
	return block.leadIn + frames + t.blockGap()
}

// intactSuffix locates the first intact block beyond an overwrite and
// measures the blank distance from the overwrite to that block's data.
func (t *Tape2401) intactSuffix(remaining int64) (int, int64) {
	for end := t.pos; end < len(t.blocks); end++ {
		old := t.blocks[end]
		if remaining <= old.leadIn {
			return end, old.leadIn - remaining
		}
		length := t.blockLength(old)
		if remaining < length {
			// Overwriting the start of a block removes its framing. The
			// next intact block remains at the same physical position.
			if end+1 < len(t.blocks) {
				return end + 1, length - remaining + t.blocks[end+1].leadIn
			}
			return len(t.blocks), 0
		}
		remaining -= length
	}
	return len(t.blocks), 0
}

// overwriteBlock replaces only the overwritten span. A surviving block
// keeps its distance from the load point.
func (t *Tape2401) overwriteBlock(block tapeBlock) int64 {
	alreadyPassed := t.blankTravel
	block.leadIn += alreadyPassed
	extent := t.blockLength(block)
	end, leadIn := t.intactSuffix(extent)
	if end < len(t.blocks) {
		t.blocks[end].leadIn = leadIn
	}
	t.blocks = slices.Replace(t.blocks, t.pos, end, block)
	t.pos++
	t.blankTravel = 0
	return extent - alreadyPassed
}

func (t *Tape2401) eraseGap(distance int64) {
	t.blankTravel += distance
	end, leadIn := t.intactSuffix(t.blankTravel)
	if end < len(t.blocks) {
		t.blocks[end].leadIn = t.blankTravel + leadIn
	}
	t.blocks = slices.Delete(t.blocks, t.pos, end)
}

// PE framing precedes and follows each data block. A tape mark occupies
// 40 character cells without data framing (IBM A22-6862-4, figures 20–21).
func peFramingCells(block tapeBlock) int {
	if block.mark {
		return peMarkCells
	}
	return 2 * peSyncCells
}

// reelUsesPE represents the load-point density identification in the
// first record or tape mark. AWS and SIMH imports have no density tag.
func (t *Tape2401) reelUsesPE() bool {
	if t.eraseDensity != 0 {
		return t.eraseDensity == 1600
	}
	if len(t.blocks) == 0 {
		return false
	}
	density := t.blocks[0].density
	return density == 1600 || density == 0 && t.peOnly
}

// remountWithRing changes the ring on the same reel and loads it at BOT.
func (t *Tape2401) remountWithRing(inserted bool) {
	t.fileProtected = !inserted
	t.unloaded = false
	t.manual = false
	t.readyArmed = false
	t.pos = 0
	t.pastLoadPoint = false
	t.eraseDensity = 0
	t.reelPosition = 0
	t.blankTravel = 0
	t.tapeIndicate = false
	t.backward, t.writeMode, t.turnaround = false, false, 0
	t.loadPointDelay = 0
	t.unloadUntil, t.reload = 0, 0
	t.readyEnd = false
	t.rewindDisconnect = 0
	t.goInhibitUntil, t.readMotionEnd, t.goDelay = 0, 0, 0
}

func (s *ChannelSubsystem) remountTape(x *Subchannel, tape *Tape2401, inserted bool) {
	if tape.unloadUntil > s.m.tod {
		tape.reload = 1
		if inserted {
			tape.reload = 2
		}
		s.reschedule()
		return
	}
	tape.remountWithRing(inserted)
	s.tapeReadyEnd(x, tape)
}

func (s *ChannelSubsystem) tapeReadyEnd(x *Subchannel, tape *Tape2401) {
	if s.busyTapePeer(x) != nil {
		tape.readyEnd = true
		return
	}
	s.Unsolicited(x.devno, usDE)
}

func (s *ChannelSubsystem) setTapeManual(x *Subchannel, tape *Tape2401, manual bool) {
	if tape.manual == manual {
		return
	}
	tape.manual = manual
	if manual {
		tape.readMotionEnd = 0
	}
	if x.tapeSenseInFlight(s.m.tod) {
		// Y22-2918-0, Sense Operation. The controller samples successive
		// sense bytes in separate read-clock cycles. Update the remainder
		// of the existing nominal sense delay after an operator change.
		elapsed := s.m.tod - (x.finishAt - x.endCE)
		sense := tape.senseBytes()
		sent := min(int(elapsed*uint64(len(sense))/x.endCE), len(x.op.Out))
		copy(x.op.Out[sent:], sense[sent:])
		if manual {
			tape.readyArmed = true
		}
	}
	if manual {
		if tape.model2415 {
			tape.tapeIndicate = false
		}
		tape.readyEnd = false
		return
	}
	if tape.readyArmed {
		tape.readyArmed = false
		s.tapeReadyEnd(x, tape)
	}
}

func (x *Subchannel) tapeSenseInFlight(now uint64) bool {
	return x.op != nil && x.op.Cmd == 0x04 && x.endCE != 0 && x.finishAt > now
}

func (t *Tape2401) TestIOStatus() byte {
	if t.notReadyForSelection() {
		t.readyArmed = true
		return usUnitCheck
	}
	return 0
}

func (t *Tape2401) notReadyForSelection() bool {
	return t.manual || t.unloaded && (t.model2415 || t.transportModel != 0)
}

// Swap2401Reels interchanges two compatible reels and loads both at
// their load points. Drive readiness and track and converter settings are unchanged.
func (s *ChannelSubsystem) Swap2401Reels(first, second uint16) error {
	if first == second {
		return errorString("tape interchange requires two drives")
	}
	a, b := s.bydev[first], s.bydev[second]
	if a == nil || b == nil {
		return errorString("tape interchange requires attached drives")
	}
	at, aok := a.dev.(*Tape2401)
	bt, bok := b.dev.(*Tape2401)
	if !aok || !bok || at.sevenTrack != bt.sevenTrack || at.dualDensity != bt.dualDensity || at.peOnly != bt.peOnly {
		return errorString("tape interchange requires compatible 2401 drives")
	}
	if a.working() || b.working() || a.deAt != 0 || b.deAt != 0 || a.pending || b.pending ||
		at.unloaded || bt.unloaded || at.manual || bt.manual {
		return errorString("tape interchange requires ready, idle drives")
	}
	at.blocks, bt.blocks = bt.blocks, at.blocks
	at.reelEOT, bt.reelEOT = bt.reelEOT, at.reelEOT
	at.fileProtected, bt.fileProtected = bt.fileProtected, at.fileProtected
	at.remountWithRing(!at.fileProtected)
	bt.remountWithRing(!bt.fileProtected)
	return nil
}

func (t *Tape2401) seekReel() {
	t.reelPosition = 0
	if t.pos > 0 {
		t.reelPosition = t.blocks[t.pos-1].reelEnd
	}
}

// rewindTravelTime estimates reel travel from the rated full-reel time
// for 2,400 feet (IBM A22-6866-4, figure 39).
func (t *Tape2401) rewindTravelTime(unload bool) time.Duration {
	distance := t.reelPosition
	if t.reelEOT == 0 {
		distance += t.blankTravel
		for _, block := range t.blocks[:t.pos] {
			distance += t.blockLength(block)
		}
	}
	if t.transportModel == 7 && !unload {
		// IBM GC20-1730-0, Magnetic Tape Units. The 2420 rewinds
		// in-column at 500 ips, then at 200 ips for the last 100 feet.
		const slowFrames = 100 * 12 * nrziFramesPerInch
		slow := time.Duration(min(distance, slowFrames)) * time.Second / (200 * nrziFramesPerInch)
		fast := time.Duration(max(0, distance-slowFrames)) * time.Second / (500 * nrziFramesPerInch)
		return slow + fast
	}
	fullReel := 240 * time.Second // 2415
	switch t.transportModel {
	case 1, 4:
		fullReel = 180 * time.Second
		if unload {
			fullReel = 132 * time.Second
		}
	case 2, 5:
		fullReel = 84 * time.Second
		if unload {
			fullReel = 90 * time.Second
		}
	case 3, 6, 7:
		fullReel = 60 * time.Second
		if unload {
			fullReel = 66 * time.Second
		}
	}
	const fullReelFrames = 2400 * 12 * nrziFramesPerInch
	return time.Duration(distance/fullReelFrames)*fullReel + time.Duration(distance%fullReelFrames)*fullReel/fullReelFrames
}

// Rewind disconnects the control independently of when the reel stops
// (IBM A22-6866-4, figure 39).
func (t *Tape2401) rewindDisconnectTime() time.Duration {
	switch {
	case t.model2415:
		return 30 * time.Microsecond
	case t.transportModel == 7:
		return 25 * time.Microsecond
	case t.transportModel != 0:
		return 30 * time.Millisecond
	default:
		return 0
	}
}

// senseForwardMarker latches Tape Indicate only when forward motion
// crosses the marker. Backward motion can clear the latch beyond EOT.
func (t *Tape2401) senseForwardMarker(from int64) {
	if from < t.reelEOT && t.reelPosition >= t.reelEOT {
		t.tapeIndicate = true
	}
}

func (t *Tape2401) writeRecord(data []byte) int64 {
	if t.sevenTrack {
		data = encodeSevenTrack(data, t.sevenMode)
	} else {
		data = slices.Clone(data)
	}
	block := tapeBlock{data: data, n: len(data), density: t.density()}
	if t.model2415 && t.loadPointDelay != 0 && !t.transferPE {
		block.leadIn = nrzi2415EraseGap
	}
	return t.overwriteBlock(block)
}

// finishWrite records the portion accepted by the channel, then reports
// write checks and the end-of-tape indication (A22-6866-4, fig. 15).
func (t *Tape2401) finishWrite(data []byte) byte {
	travel := t.writeRecord(data)
	t.eraseDensity = 0
	block := &t.blocks[t.pos-1]
	t.pastLoadPoint = true
	var status byte
	if t.writeChecks > 0 && t.pos-1 == t.writeCheckRecord {
		t.writeChecks--
		block.bad = true
		t.sense[0] |= senseDataCheck
		status |= usUnitCheck
	}
	if t.reelEOT != 0 {
		from := t.reelPosition
		t.reelPosition += travel
		block.reelEnd = t.reelPosition
		t.senseForwardMarker(from)
		if t.tapeIndicate {
			status |= usUnitExcept
		}
	}
	return status
}

func (t *Tape2401) snapshotKind() string {
	if t.model2415 {
		return "2415"
	}
	if t.transportModel == 7 {
		return "2420"
	}
	return "2401"
}

func (t *Tape2401) Reset() {
	t.goInhibitUntil, t.readMotionEnd, t.goDelay = 0, 0, 0
	t.transferPE = t.peOnly || t.model2415 && t.dualDensity
	// A22-6866-4, Mode Set Commands. System reset sets the Model 2
	// controller to 1600 bpi. A dual-density transport selects its
	// mounted reel's recording mode when it reads at load point.
	t.writePE = t.transferPE || t.transportModel >= 4
	t.sevenMode = 0x80 | tapeConvert
	if t.noConverter {
		t.sevenMode = 0x80 | tapeOdd
	}
}

func (t *Tape2401) sharesControl(other *Tape2401) bool {
	if t.model2415 || other.model2415 {
		return t.model2415 && other.model2415
	}
	return t.transportModel != 0 && other.transportModel != 0 && t.nrziTapeControl() == other.nrziTapeControl()
}

func (x *Subchannel) sharesTapeControl(other *Subchannel, tape, peer *Tape2401) bool {
	if x.controller9020 != 0 || other.controller9020 != 0 {
		return x.controller9020 == other.controller9020
	}
	return x.devno>>3 == other.devno>>3 && tape.sharesControl(peer)
}

func (s *ChannelSubsystem) setTapeMode(x *Subchannel, tape *Tape2401, cmd, status byte) {
	nine := status == usCE|usDE && (cmd == 0xc3 || cmd == 0xcb)
	seven := tape.sevenTrack && isSevenTrackModeSet(cmd) && (status == usCE|usDE || tape.sense[0]&senseCmdReject != 0)
	if !nine && !seven {
		return
	}
	for _, peer := range s.subs {
		other, ok := peer.dev.(*Tape2401)
		if !ok || !x.sharesTapeControl(peer, tape, other) {
			continue
		}
		if nine {
			other.writePE = cmd == 0xc3
		} else if other.sevenTrack {
			other.sevenMode = tape.sevenMode
		}
	}
}

func (t *Tape2401) controlUnitBusy() bool {
	switch t.lastCommand {
	case 0x17, 0x1f, 0x27, 0x2f, 0x37, 0x3f:
		return true
	}
	return false
}

func (t *Tape2401) senseBytes() []byte {
	notReady := t.unloaded || t.manual
	t.status()
	sense := t.sense
	if notReady {
		sense[0] |= senseIntervReq
		sense[1] &^= 0x48 // ready and load point are unavailable
		if t.model2415 || t.transportModel != 0 {
			sense[1] |= 0x20 // a tape unit exists but is not ready
		}
	}
	if t.pastLoadPoint {
		sense[1] &^= 0x08
	}
	if t.sevenTrack {
		sense[1] |= 0x10
	}
	if t.fileProtected {
		sense[1] |= 0x02
	}
	if t.model2415 {
		if !notReady && t.writeMode {
			sense[1] |= 0x04
		}
		sense[2] = 0x03 // forced for 2415, including after a data check
	} else {
		if t.tapeIndicate {
			sense[1] |= 0x04
		}
		if t.sevenTrack || sense[0]&senseDataCheck == 0 {
			sense[2] = 0x03 // no track in error (NRZI)
		}
	}
	// A22-6866-4, Sense Byte 3. The transport supplies recording
	// mode and direction when it is selected and ready.
	if !notReady && t.transferPE {
		sense[3] |= 0x04
	}
	if !notReady && t.backward {
		sense[3] |= 0x02
	}
	return sense[:6]
}

func (t *Tape2401) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	t.lastCommand = cmd
	t.turnaround, t.loadPointDelay = 0, 0
	t.goDelay = 0
	if t.notReadyForSelection() {
		t.readyArmed = true
		if cmd != 0x04 {
			// A22-6866-4, Sense Byte 1. Only Sense
			// can pass initial selection with the transport not ready.
			t.chanT, t.devT = 0, 0
			t.check(senseIntervReq, 0)
			return nil, 0, usUnitCheck
		}
	}
	if cmd == 0x04 {
		t.chanT, t.devT = tapeControl, 0
		return t.senseBytes(), 0, usCE | usDE
	}
	if t.peOnly && (cmd == 0xc3 || cmd == 0xcb) {
		t.chanT, t.devT = 0, 0
		return nil, 0, usCE | usDE
	}
	if cmd != 0x03 {
		t.sense = [24]byte{}
	}
	atLoadPoint := t.pos == 0 && !t.pastLoadPoint
	if t.model2415 && atLoadPoint && (cmd == 0x01 || cmd == 0x02) {
		t.loadPointDelay = 204 * time.Millisecond // IBM A22-6866-4, figure 39
	}
	if t.fileProtected && !t.unloaded && (cmd == 0x01 || cmd == 0x17 || cmd == 0x1f) {
		t.chanT, t.devT = 0, 0
		t.sense[0] = senseCmdReject
		return nil, 0, usUnitCheck
	}
	if t.peOnly && !t.unloaded && (cmd == 0x02 || cmd == 0x0c) && len(t.blocks) != 0 && !t.reelUsesPE() {
		t.chanT, t.devT = 0, 0
		return t.check(0, 0x01) // tape unit does not support the reel's density
	}
	if t.dualDensity {
		switch cmd {
		case 0xc3, 0xcb:
			t.writePE = cmd == 0xc3
			if t.model2415 {
				t.transferPE = t.writePE
			}
			t.chanT, t.devT = 0, 0
			return nil, 0, usCE | usDE
		case 0x01, 0x17, 0x1f:
			t.transferPE = t.reelUsesPE()
			if t.pos == 0 && !t.pastLoadPoint {
				t.transferPE = t.writePE
			}
		default:
			t.transferPE = t.reelUsesPE()
		}
	}
	if t.sevenTrack && isSevenTrackModeSet(cmd) {
		t.chanT, t.devT = 0, 0
		if cmd&0x38 == tapeConvert && t.noConverter {
			// A22-6866-4, figure 14. The command still selects
			// density, odd parity, and translator off.
			t.sevenMode = cmd&0xc0 | tapeOdd
			t.sense[0] = senseCmdReject
			return nil, 0, usUnitCheck
		}
		t.sevenMode = cmd & 0xf8
		return nil, 0, usCE | usDE
	}
	if cmd == 0x01 && !t.unloaded {
		// The channel records the accepted bytes when the transfer
		// ends, which may be early if HALT I/O stops the write.
		t.setMotionDirection(cmd, atLoadPoint)
		t.chanT, t.devT = t.writeTransferDuration(len(data)), 0
		return nil, len(data), usCE | usDE
	}
	pos := t.pos
	blankTravel := t.blankTravel
	var rewindTravel time.Duration
	if (t.model2415 || t.transportModel != 0) && cmd == 0x07 && !t.unloaded {
		rewindTravel = t.rewindTravelTime(false)
	}
	var out []byte
	var used int
	var status byte
	var travel int64
	if cmd == 0x1f && !t.unloaded {
		// A22-6866-4, figure 9. A tape mark is recorded beyond
		// its leading erase gap.
		travel = t.overwriteBlock(tapeBlock{mark: true, density: t.density(), leadIn: nrzi2415EraseGap})
		t.motion(0)
		status = usCE | usDE
	} else {
		out, used, status = t.Tape3420.Exec(cmd, data, chained)
	}
	if cmd == 0x17 && status == usCE|usDE && t.dualDensity && !t.pastLoadPoint {
		// A load-point write-type operation samples the controller's
		// density. An erase can do this before the first block exists.
		t.eraseDensity = t.density()
	}
	if cmd == 0x1f && status == usCE|usDE {
		t.eraseDensity = 0
	}
	if cmd == 0x17 && status == usCE|usDE {
		travel = nominalEraseGap
		if t.model2415 && !t.transferPE {
			travel = nrzi2415EraseGap
		}
		if t.sevenTrack {
			if err := t.eraseSevenTrackGap(travel); err != nil {
				travel = 0
				_, _, status = t.check(senseDataCheck, 0)
			}
		} else {
			t.eraseGap(travel)
		}
	}
	if t.sevenTrack && (cmd == 0x02 || cmd == 0x0c) && len(out) != 0 {
		out = t.readSevenTrack(out, cmd == 0x0c)
		if t.blocks[min(pos, t.pos)].lrcDelta != 0 {
			t.sense[0] |= senseDataCheck
			t.sense[3] |= 0x40 // longitudinal redundancy check
		}
		if t.sense[0] != 0 {
			status |= usUnitCheck
		}
	}
	switch cmd {
	case 0x07, 0x0f: // rewind, rewind and unload
		t.pastLoadPoint = false
		t.eraseDensity = 0
		t.blankTravel = 0
		if t.model2415 && cmd == 0x07 && status == usCE|usDE {
			// Rewind leaves the transport in forward status (A22-6866-4, figure 39).
			t.backward = false
		}
	case 0x02, 0x17, 0x1f, 0x37, 0x3f: // forward motion
		if t.chanT >= tapeStart || t.devT >= tapeStart {
			t.pastLoadPoint = true
		}
	case 0x0c, 0x27, 0x2f: // backward motion
		if !t.unloaded && (pos == 0 || cmd == 0x2f && t.pos == 0 && (len(t.blocks) == 0 || !t.blocks[0].mark)) {
			t.pastLoadPoint = false
			t.blankTravel = 0
			status |= usUnitCheck
			if cmd == 0x0c {
				t.transfer(0)
			} else if t.devT == 0 {
				t.motion(0)
			}
		}
	}
	if t.pos != pos && cmd != 0x17 {
		t.blankTravel = 0
		backspaceToMark := cmd == 0x2f && t.pos < pos && t.blocks[t.pos].mark
		if cmd == 0x0c || t.sevenTrack && cmd == 0x27 || backspaceToMark {
			// Stop at the start of the record. An extended leading
			// gap remains between the head and the prior block. BSF
			// stops when it finds the gap just before the tape mark.
			t.blankTravel = t.blocks[t.pos].leadIn
		}
	}
	if t.reelEOT != 0 && !t.unloaded {
		from := t.reelPosition
		switch cmd {
		case 0x07:
			t.reelPosition, t.tapeIndicate = 0, false
		case 0x0c, 0x27, 0x2f:
			t.seekReel()
			t.reelPosition += t.blankTravel
			// A22-6866-4, figure 15. The 2401 Models 4–6, 2420,
			// and 2415 clear the latch only when they pass the marker.
			if !t.model2415 && t.transportModel < 4 || t.reelPosition < t.reelEOT {
				t.tapeIndicate = false
			}
		case 0x02, 0x37, 0x3f:
			if t.pos != pos {
				t.seekReel()
				t.senseForwardMarker(from)
			}
		case 0x17, 0x1f:
			t.reelPosition += travel
			if cmd == 0x1f && status == usCE|usDE {
				t.blocks[t.pos-1].reelEnd = t.reelPosition
			}
			t.senseForwardMarker(from)
			if t.tapeIndicate {
				status |= usUnitExcept
			}
		}
	} else if cmd == 0x07 || cmd == 0x0f {
		t.reelPosition, t.tapeIndicate = 0, false
	}
	if t.chanT >= tapeStart || t.devT >= tapeStart {
		t.setMotionDirection(cmd, atLoadPoint)
	}
	// Convert generic transfer and spacing times to the mounted density
	// and the 2401 drive's gap time.
	if t.chanT >= tapeStart {
		if !t.sevenTrack && t.pos != pos && (cmd == 0x02 || cmd == 0x0c) {
			block := t.blocks[min(pos, t.pos)]
			gap := blankTravel
			if cmd == 0x02 {
				gap = block.leadIn - blankTravel
			}
			t.chanT += time.Duration(gap*int64(t.density())/nrziFramesPerInch) * tapeByte
			if t.transferPE {
				t.chanT += time.Duration(peFramingCells(block)) * tapeByte
			}
		}
		t.chanT = t.motionTime(t.chanT)
	}
	if t.devT >= tapeStart {
		switch {
		case t.transportModel != 0 && cmd == 0x07:
			if atLoadPoint {
				// No reel travel. Present Device End separately from
				// the immediately accepted channel-end status.
				t.devT = time.Nanosecond
			} else {
				t.devT = max(rewindTravel, t.rewindDisconnectTime())
			}
		case t.transportModel == 7 && cmd == 0x0f:
			t.devT = time.Millisecond // A32-0004-0, figure 1
		case t.transportModel == 7 && cmd == 0x1f:
			const cells = 2*nrzi2415EraseGap + peMarkCells
			t.devT = t.motionTime(tapeStart + cells*tapeByte)
		case t.model2415 && cmd == 0x0f:
			// The controller reports unload initiation at disconnect,
			// while the reel continues moving (A22-6866-4, figure 39).
			t.devT = 30 * time.Microsecond
		case t.transportModel != 0 && cmd == 0x0f:
			t.devT = 45 * time.Millisecond // A22-6866-4, figure 39
		case t.model2415 && !t.transferPE && cmd == 0x17:
			// On the 2415, turnaround precedes the independent erase
			// counter. End status begins after 217 ms (Y22-2918-0, 3-12).
			t.devT = 217*time.Millisecond + t.turnaround
		case t.model2415 && t.transferPE && cmd == 0x17:
			// A22-6866-4 specifies approximately 3.5 inches of
			// erasure. Model travel at the 2415's nominal 18.75 ips.
			t.devT = t.turnaround + nominalEraseGap*time.Second/(nrziFramesPerInch*75/4)
		case t.model2415 && cmd == 0x1f:
			// Initiation through disconnect, including read-back
			// (IBM A22-6866-4, figure 39).
			markTime := 219 * time.Millisecond
			if t.transferPE {
				markTime = 220 * time.Millisecond
			}
			t.devT = markTime + t.turnaround
		case cmd == 0x17:
			t.devT = t.turnaround + t.travelTime(travel)
		case cmd == 0x1f:
			t.devT = t.turnaround + t.writeTapeMarkTime2401()
		default:
			if (cmd == 0x27 || cmd == 0x2f || cmd == 0x37 || cmd == 0x3f) && pos != t.pos {
				distance := blankTravel - t.blankTravel
				if t.pos > pos {
					distance = -blankTravel
				}
				for _, block := range t.blocks[min(pos, t.pos):max(pos, t.pos)] {
					distance += t.blockLength(block)
				}
				t.devT = t.turnaround + t.loadPointDelay + t.travelTime(distance)
			} else {
				t.devT = t.motionTime(t.devT)
			}
		}
	}
	if t.model2415 && cmd == 0x07 && t.devT != 0 {
		t.devT = max(t.devT, rewindTravel)
	}
	if cmd == 0x0f && t.devT != 0 {
		status |= usUnitCheck
	}
	if t.devT != 0 && status&(usUnitCheck|usUnitExcept) != 0 {
		status |= usCUE
	}
	return out, used, status
}

// writeTapeMarkTime2401 is initiation through disconnect, by capstan
// speed and recording format (A22-6866-4, figure 39).
func (t *Tape2401) writeTapeMarkTime2401() time.Duration {
	var microseconds [3]int
	switch {
	case t.nrziTapeControl() && t.sevenTrack:
		microseconds = [3]int{103000, 51000, 35000}
	case t.nrziTapeControl():
		microseconds = [3]int{99000, 49000, 33500}
	case t.sevenTrack:
		microseconds = [3]int{104400, 52200, 34800}
	case t.transferPE:
		microseconds = [3]int{101200, 50000, 33700}
	default:
		microseconds = [3]int{100000, 50500, 33500}
	}
	speedIndex := t.capstanSpeed()/150 - 1
	return time.Duration(microseconds[speedIndex]) * time.Microsecond
}

func (t *Tape2401) nrziTapeControl() bool {
	return t.transportModel >= 1 && t.transportModel <= 3 && !t.modeCompatible
}

// setMotionDirection accounts for capstan turnaround before data or
// positioning motion. Rewind uses the reel motors.
func (t *Tape2401) setMotionDirection(cmd byte, atLoadPoint bool) {
	if !t.model2415 && t.transportModel == 0 {
		return
	}
	var backward, write bool
	switch cmd {
	case 0x0c, 0x27, 0x2f:
		backward = true
	case 0x01, 0x17, 0x1f:
		write = true
	case 0x02, 0x37, 0x3f:
	default:
		return
	}
	if t.transportModel == 7 {
		// A32-0004-0, figure 1. Reversal is part of the load-point
		// delay. The first data byte follows the gap and PE preamble.
		if atLoadPoint && (cmd == 0x01 || cmd == 0x02) {
			t.loadPointDelay = 42*time.Millisecond - peSyncCells*time.Second/320000
		} else if backward != t.backward || atLoadPoint && !backward {
			t.turnaround = 16 * time.Millisecond
		}
		t.backward = backward
		return
	}
	if t.transportModel != 0 {
		// A22-6866-4, figure 39. Load-point and direction-change
		// allowances for the 2401 depend on the tape control.
		speed := t.capstanSpeed()/150 - 1
		if atLoadPoint && (cmd == 0x01 || cmd == 0x02) {
			loadPoint := [3]time.Duration{320 * time.Millisecond, 64 * time.Millisecond, 48 * time.Millisecond}
			if t.nrziTapeControl() {
				loadPoint = [3]time.Duration{350 * time.Millisecond, 75 * time.Millisecond, 48 * time.Millisecond}
			}
			t.loadPointDelay = loadPoint[speed]
		}
		if backward != t.backward || atLoadPoint && !backward {
			change := [3]time.Duration{224 * time.Millisecond, 16 * time.Millisecond, 16 * time.Millisecond}
			switch {
			case backward && t.writeMode:
				change = [3]time.Duration{236 * time.Millisecond, 20800 * time.Microsecond, 20800 * time.Microsecond}
			case !backward && write:
				change = [3]time.Duration{236200 * time.Microsecond, 22400 * time.Microsecond, 21 * time.Millisecond}
			}
			if t.nrziTapeControl() {
				change = [3]time.Duration{264 * time.Millisecond, 32 * time.Millisecond, 16 * time.Millisecond}
				if backward && t.writeMode {
					change = [3]time.Duration{276 * time.Millisecond, 36800 * time.Microsecond, 20800 * time.Microsecond}
				}
			}
			t.turnaround = change[speed]
		}
		t.backward, t.writeMode = backward, write
		return
	}
	if atLoadPoint && !t.transferPE && (cmd == 0x37 || cmd == 0x3f) {
		// The NRZI 2415 uses its read load-point delay before forward
		// spacing (Y22-2918-0, p. 3-9). Physical lead-in already
		// traversed in that interval counts toward the delay.
		t.loadPointDelay = max(0, 153*time.Millisecond-t.travelTime(t.blocks[0].leadIn))
	}
	if backward != t.backward {
		// Y22-2918-0 pp. 3-16–3-17: 32 ms braking and 173 ms
		// acceleration, preceded by a short erase in write status.
		t.turnaround = 205 * time.Millisecond
		if backward && t.writeMode {
			t.turnaround += 19 * time.Millisecond
		}
		t.backward = backward
	}
	t.writeMode = write
}

// capstanSpeed is in quarter-inches per second (A22-6866-4, figure 12).
func (t *Tape2401) capstanSpeed() int64 {
	if t.model2415 {
		return 75
	}
	switch t.transportModel {
	case 1, 4:
		return 150
	case 3, 6:
		return 450
	case 7:
		return 800
	default:
		return 300
	}
}

func (t *Tape2401) motionTime(duration time.Duration) time.Duration {
	frames := int64((duration - tapeStart) / tapeByte)
	gapFrames := t.blockGap() * int64(t.density()) / nrziFramesPerInch
	travel := time.Duration(frames+gapFrames) * time.Second / time.Duration(t.frameRate())
	return t.turnaround + t.loadPointDelay + travel
}

// travelTime converts physical distance in 800-bpi frames to capstan time.
func (t *Tape2401) travelTime(distance int64) time.Duration {
	return time.Duration(distance*4) * time.Second / time.Duration(nrziFramesPerInch*t.capstanSpeed())
}

// inhibitGo follows the 2401 Inhibit Go output after a read-type motion
// (IBM A22-6862-4, figure 8). Its nominal hold ends on the device clock.
func (t *Tape2401) inhibitGo(readEnd uint64) {
	switch {
	case t.transportModel == 4 || t.modeCompatible && t.transportModel == 1:
		t.goInhibitUntil = readEnd + durationTOD(4*time.Millisecond)
	case t.transportModel == 5 || t.modeCompatible && t.transportModel == 2:
		t.goInhibitUntil = readEnd + durationTOD(1200*time.Microsecond)
	}
}

func (t *Tape2401) finishReadMotion(end, duration uint64) {
	t.inhibitGo(end)
	// Figure 23 in GA22-6862-6 specifies the full-speed coast
	// envelope after at least 20 ms with Go asserted.
	if !t.manual && (t.transportModel == 3 || t.transportModel == 6) &&
		duration >= durationTOD(t.turnaround+t.loadPointDelay+20*time.Millisecond) {
		t.readMotionEnd = end
	}
}

// spaceRestart accounts for tape runout still ahead of the head
// and for the reduced acceleration loss if Go is reasserted during runout.
// Use a linear ramp with nominal start (3 ms), minimum coast (1.1 ms),
// and the midpoint of the 2–3 ms forward stop range (A22-6862-4, fig. 14).
func (t *Tape2401) spaceRestart(now uint64) time.Duration {
	const (
		start = 3 * time.Millisecond
		coast = 1100 * time.Microsecond
		stop  = 2500 * time.Microsecond
	)
	down := now - t.readMotionEnd
	if t.readMotionEnd == 0 || down >= durationTOD(stop) {
		return 0
	}
	elapsed := time.Duration(down * uint64(time.Microsecond) / todMicro)
	if elapsed <= coast {
		return coast - elapsed + (stop-coast)/2 - start/2
	}
	braking := stop - coast
	remaining := stop - elapsed
	// Both distances are expressed as times at nominal tape speed.
	runout := remaining * remaining / (2 * braking)
	acceleration := start * (elapsed - coast) / braking
	launchLoss := acceleration * (elapsed - coast) / (2 * braking)
	return runout + launchLoss - start/2
}

func (t *Tape2401) scheduleMotion(now uint64, cmd byte) {
	restart := t.spaceRestart(now)
	if t.chanT >= tapeStart || t.devT >= tapeStart || cmd == 0x07 || cmd == 0x0f {
		t.readMotionEnd = 0
	}
	if t.goInhibitUntil > now {
		delay := time.Duration((t.goInhibitUntil - now) * uint64(time.Microsecond) / todMicro)
		switch cmd {
		case 0x01, 0x02, 0x0c:
			if t.chanT >= tapeStart {
				t.goDelay = delay
				t.chanT += delay
			}
		case 0x17, 0x1f, 0x27, 0x2f, 0x37, 0x3f:
			if t.devT >= tapeStart {
				t.devT += delay
			}
		}
	}
	switch cmd {
	case 0x27, 0x2f, 0x37, 0x3f:
		if t.devT >= tapeStart {
			if t.turnaround == 0 && t.loadPointDelay == 0 {
				t.devT += restart
			}
			duration := durationTOD(t.devT)
			t.finishReadMotion(now+duration, duration)
		}
	case 0x07, 0x0f:
		t.goInhibitUntil = 0
	}
}

func (t *Tape2401) transferredBytes(cmd byte, read bool, elapsed time.Duration) int {
	elapsed -= min(elapsed, t.goDelay)
	sent := int(max(0, elapsed-t.dataStartTime()) * time.Duration(t.frameRate()) / time.Second)
	if t.sevenTrack && t.sevenMode&0x38 == tapeConvert && cmd != 0x0c {
		sent = sent * 3 / 4
	}
	if !read && cmd == 0x01 {
		if elapsed > t.firstWriteByteTime() {
			sent++
		}
	}
	return sent
}

func (t *Tape2401) dataStartTime() time.Duration {
	start := tapeStart
	if t.transferPE {
		start += peSyncCells * tapeByte
	}
	return t.motionTime(start)
}

func (t *Tape2401) firstWriteByteTime() time.Duration {
	if t.model2415 {
		// The 2415 starts requesting data 4 ms after the write start.
		return t.loadPointDelay + t.turnaround + 4*time.Millisecond
	}
	// The 2803 requests a byte at selection (Y22-2853-1 p. 97).
	return 0
}

func (t *Tape2401) writeTransferDuration(n int) time.Duration {
	frames := n
	if t.sevenTrack && t.sevenMode&0x38 == tapeConvert {
		frames = (n*8 + 5) / 6
	}
	if t.transferPE {
		frames += 2 * peSyncCells
	}
	return t.motionTime(tapeStart + time.Duration(frames)*tapeByte)
}

func (t *Tape2401) streamByteDelay(cmd byte, n uint32) time.Duration {
	if n == 0 {
		return 0
	}
	frames := time.Duration(n)
	if t.sevenTrack && t.sevenMode&0x38 == tapeConvert && cmd != 0x0c {
		frames = (frames*4 + 2) / 3
	}
	rate := time.Duration(t.frameRate())
	return t.dataStartTime() + (frames*time.Second+rate-1)/rate
}

func (t *Tape2401) readByteDelay(cmd byte, n uint32) time.Duration {
	at := t.goDelay + t.streamByteDelay(cmd, n)
	return (at + time.Microsecond - 1) / time.Microsecond * time.Microsecond
}

// writeByteDelay inverts transferredBytes on the channel's microsecond
// clock, including the byte requested before the regular stream starts.
func (t *Tape2401) writeByteDelay(n uint32) time.Duration {
	at := min(t.streamByteDelay(0x01, n), max(t.firstWriteByteTime()+1, t.streamByteDelay(0x01, n-1))) + t.goDelay
	return (at + time.Microsecond - 1) / time.Microsecond * time.Microsecond
}

// haltTransfer ends transfer at the selector channel's current byte count.
// The control unit supplies its ending status separately from the channel.
func (t *Tape2401) haltTransfer(op *ccwOp, elapsed time.Duration) byte {
	sent := t.transferredBytes(op.Cmd, op.Read, elapsed)
	if op.Read {
		op.Out = op.Out[:min(sent, len(op.Out))]
	} else if op.TimedOutput {
		op.Used = int(op.OutputFetched)
	} else {
		op.Used = min(sent, op.Used)
	}
	elapsed -= min(elapsed, t.goDelay)
	status := byte(usCE | usDE)
	if op.Cmd == 0x01 && op.Status == status && op.Used == 0 {
		t.sense[0] = 0x02 // word count zero
		status |= usUnitCheck
		if t.model2415 && t.loadPointDelay != 0 && !t.transferPE && elapsed >= t.turnaround+t.loadPointDelay {
			// The load-point erase finished before the first request
			// for data. No record exists, but the tape moved.
			t.pastLoadPoint = true
			if !t.sevenTrack {
				t.eraseGap(nrzi2415EraseGap)
				if t.dualDensity {
					t.eraseDensity = 800
				}
			}
			if t.reelEOT != 0 {
				from := t.reelPosition
				t.reelPosition += nrzi2415EraseGap
				t.senseForwardMarker(from)
			}
		}
	}
	return status
}
