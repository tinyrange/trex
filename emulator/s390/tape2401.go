package s390

import "time"

// Tape2401 models the 2401 Model 2 on a 2803 control unit. It
// shares the AWS/SIMH block transport with the 3420. Sense and ending
// status follow 2400-Series Component Descriptions (IBM A22-6866-4).
type Tape2401 struct {
	*Tape3420
}

const (
	nrziFramesPerInch = 800
	nrziBlockGap      = nrziFramesPerInch * 3 / 4
	nrziEraseGap      = nrziFramesPerInch * 7 / 2
)

// setReelEOT sets the position of the reflective end-of-tape marker on
// a nine-track reel. SIMH and AWS record boundaries do not encode it.
func (t *Tape2401) setReelEOT(inches int) {
	t.reelEOT = int64(inches) * nrziFramesPerInch
	var end int64
	for i := range t.blocks {
		end += int64(t.blocks[i].n) + nrziBlockGap
		t.blocks[i].reelEnd = end
	}
}

func (t *Tape2401) seekReel() {
	t.reelPosition = 0
	if t.pos > 0 {
		t.reelPosition = t.blocks[t.pos-1].reelEnd
	}
}

// finishWrite records the portion accepted by the channel, then reports
// whether the write ended in the end-of-tape area (A22-6866-4, fig. 15).
func (t *Tape2401) finishWrite(data []byte) byte {
	t.writeRecord(data)
	t.pastLoadPoint = true
	if t.reelEOT != 0 {
		t.reelPosition += int64(len(data)) + nrziBlockGap
		t.blocks[t.pos-1].reelEnd = t.reelPosition
		t.tapeIndicate = t.reelPosition >= t.reelEOT
		if t.tapeIndicate {
			return usUnitExcept
		}
	}
	return 0
}

func (t *Tape2401) snapshotKind() string { return "2401" }

func (t *Tape2401) Reset() {
	t.sevenMode = 0x80 | tapeConvert
	if t.noConverter {
		t.sevenMode = 0x80 | tapeOdd
	}
}

func (t *Tape2401) controlUnitBusy() bool {
	switch t.lastCommand {
	case 0x17, 0x1f, 0x27, 0x2f, 0x37, 0x3f:
		return true
	}
	return false
}

func (t *Tape2401) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	t.lastCommand = cmd
	if cmd == 0x04 {
		t.chanT, t.devT = tapeControl, 0
		t.status()
		sense := t.sense
		if t.pastLoadPoint {
			sense[1] &^= 0x08
		}
		if t.sevenTrack {
			sense[1] |= 0x10
		}
		if t.tapeIndicate {
			sense[1] |= 0x04
		}
		if t.sevenTrack || sense[0]&senseDataCheck == 0 {
			sense[2] = 0x03 // no track in error (NRZI)
		}
		return sense[:6], 0, usCE | usDE
	}
	if cmd != 0x03 {
		t.sense = [24]byte{}
	}
	mode := cmd & 0x38
	if t.sevenTrack && cmd&0x07 == 0x03 && (mode == tapeConvert || mode >= tapeEven) {
		t.chanT, t.devT = 0, 0
		if mode == tapeConvert && t.noConverter {
			t.sense[0] = senseCmdReject
			return nil, 0, usUnitCheck
		}
		t.sevenMode = cmd & 0xf8
		return nil, 0, usCE | usDE
	}
	if cmd == 0x01 && !t.unloaded {
		// The channel records the accepted bytes when the transfer
		// ends, which may be early if HALT I/O stops the write.
		frames := len(data)
		if t.sevenTrack && t.sevenMode&0x38 == tapeConvert {
			frames = (len(data)*8 + 5) / 6
		}
		t.transfer(frames)
		t.chanT = t.motionTime(t.chanT)
		return nil, len(data), usCE | usDE
	}
	pos := t.pos
	out, used, status := t.Tape3420.Exec(cmd, data, chained)
	if t.sevenTrack && cmd == 0x17 && status == usCE|usDE {
		if err := t.eraseSevenTrackGap(); err != nil {
			_, _, status = t.check(senseDataCheck, 0)
		}
	}
	if t.sevenTrack && (cmd == 0x02 || cmd == 0x0c) && len(out) != 0 {
		out = t.readSevenTrack(out, cmd == 0x0c)
		if t.sense[0] != 0 {
			status |= usUnitCheck
		}
	}
	switch cmd {
	case 0x07, 0x0f: // rewind, rewind and unload
		t.pastLoadPoint = false
	case 0x02, 0x17, 0x1f, 0x37, 0x3f: // forward motion
		if t.chanT >= tapeStart || t.devT >= tapeStart {
			t.pastLoadPoint = true
		}
	case 0x0c, 0x27, 0x2f: // backward motion
		if !t.unloaded && (pos == 0 || cmd == 0x2f && t.pos == 0 && (len(t.blocks) == 0 || !t.blocks[0].mark)) {
			t.pastLoadPoint = false
			status |= usUnitCheck
			if cmd == 0x0c {
				t.transfer(0)
			} else if t.devT == 0 {
				t.motion(0)
			}
		}
	}
	if t.reelEOT != 0 && !t.unloaded {
		switch cmd {
		case 0x07, 0x0c, 0x27, 0x2f:
			t.seekReel()
			t.tapeIndicate = false
		case 0x02, 0x37, 0x3f:
			if t.pos != pos {
				t.seekReel()
				t.tapeIndicate = t.reelPosition >= t.reelEOT
			}
		case 0x17, 0x1f:
			if cmd == 0x17 {
				t.reelPosition += nrziEraseGap
			} else {
				t.reelPosition += nrziBlockGap
				t.blocks[t.pos-1].reelEnd = t.reelPosition
			}
			t.tapeIndicate = t.reelPosition >= t.reelEOT
			if t.tapeIndicate {
				status |= usUnitExcept
			}
		}
	} else if cmd == 0x0f {
		t.reelPosition, t.tapeIndicate = 0, false
	}
	// Model 2 transfers 60,000 bytes per second. The 3/4-inch NRZI
	// interblock gap takes 10ms at 75 inches per second.
	if t.chanT >= tapeStart {
		t.chanT = t.motionTime(t.chanT)
	}
	if t.devT >= tapeStart {
		t.devT = t.motionTime(t.devT)
	}
	if cmd == 0x0f && t.devT != 0 {
		status |= usUnitCheck
	}
	if t.devT != 0 && status&(usUnitCheck|usUnitExcept) != 0 {
		status |= usCUE
	}
	return out, used, status
}

func (t *Tape2401) motionTime(duration time.Duration) time.Duration {
	n := (duration - tapeStart) / tapeByte
	return 10*time.Millisecond + n*time.Second/time.Duration(t.frameRate())
}

// haltTransfer ends transfer at the selector channel's current byte count.
// The control unit supplies its ending status separately from the channel.
func (t *Tape2401) haltTransfer(op *ccwOp, elapsed time.Duration) byte {
	sent := int(max(0, elapsed-t.motionTime(tapeStart)) * time.Duration(t.frameRate()) / time.Second)
	if t.sevenTrack && t.sevenMode&0x38 == tapeConvert && op.Cmd != 0x0c {
		sent = sent * 3 / 4
	}
	if op.Read {
		op.Out = op.Out[:min(sent, len(op.Out))]
	} else {
		// The 2803 requests the first write byte immediately after
		// selection, before starting the tape (IBM Y22-2853-1 p. 97).
		if op.Cmd == 0x01 && elapsed > 0 {
			sent++
		}
		op.Used = min(sent, op.Used)
	}
	status := byte(usCE | usDE)
	if op.Cmd == 0x01 && op.Status == status && op.Used == 0 {
		t.sense[0] = 0x02 // word count zero
		status |= usUnitCheck
	}
	return status
}
