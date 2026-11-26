package s390

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func simhRecord(class byte, data string) []byte {
	w := uint32(class)<<28 | uint32(len(data))
	p := binary.LittleEndian.AppendUint32(nil, w)
	p = append(p, data...)
	if len(data)&1 != 0 {
		p = append(p, 0)
	}
	return binary.LittleEndian.AppendUint32(p, w)
}

func Test2415ReadTimingAndFileProtection(t *testing.T) {
	data := bytes.Repeat([]byte{0xa5}, 1500)
	tape := &Tape2401{Tape3420: &Tape3420{fileProtected: true}, model2415: true}
	tape.Tape3420.writeRecord(data)
	tape.pos = 0
	out, _, status := tape.Exec(0x02, nil, false)
	if !bytes.Equal(out, data) || status != usCE|usDE || tape.chanT != 336*time.Millisecond {
		t.Fatalf("2415 read: %d bytes, status %02x, time %s", len(out), status, tape.chanT)
	}
	if _, used, status := tape.Exec(0x01, data, false); used != 0 || status != usUnitCheck {
		t.Fatalf("2415 write without a ring: used %d bytes, status %02x", used, status)
	}
	sense, _, _ := tape.Exec(0x04, nil, false)
	if len(sense) != 6 || sense[0]&senseCmdReject == 0 || sense[1]&0x02 == 0 {
		t.Fatalf("2415 write-protect sense: %x", sense)
	}
}

func Test2401ModelTransferRates(t *testing.T) {
	data := bytes.Repeat([]byte{0xa5}, 1500)
	for _, test := range []struct {
		model          uint8
		rwTime         time.Duration
		loadPointWrite time.Duration
		reverseWrite   time.Duration
		reverseRead    time.Duration
		density        int
		compatible     bool
	}{
		{1, 66 * time.Millisecond, 614 * time.Millisecond, 264 * time.Millisecond, 276 * time.Millisecond, 800, false},
		{2, 33 * time.Millisecond, 107 * time.Millisecond, 32 * time.Millisecond, 36800 * time.Microsecond, 800, false},
		{3, 22 * time.Millisecond, 64 * time.Millisecond, 16 * time.Millisecond, 20800 * time.Microsecond, 800, false},
		{1, 66 * time.Millisecond, 556200 * time.Microsecond, 236200 * time.Microsecond, 236 * time.Millisecond, 800, true},
		{2, 33 * time.Millisecond, 86400 * time.Microsecond, 22400 * time.Microsecond, 20800 * time.Microsecond, 800, true},
		{3, 22 * time.Millisecond, 69 * time.Millisecond, 21 * time.Millisecond, 20800 * time.Microsecond, 800, true},
		{4, 42366666 * time.Nanosecond, 556200 * time.Microsecond, 236200 * time.Microsecond, 236 * time.Millisecond, 1600, false},
		{5, 21183333 * time.Nanosecond, 86400 * time.Microsecond, 22400 * time.Microsecond, 20800 * time.Microsecond, 1600, false},
		{6, 14122222 * time.Nanosecond, 69 * time.Millisecond, 21 * time.Millisecond, 20800 * time.Microsecond, 1600, false},
	} {
		tape := &Tape2401{Tape3420: &Tape3420{transportModel: test.model, modeCompatible: test.compatible, peOnly: test.density == 1600}}
		tape.Reset()
		_, used, status := tape.Exec(0x01, data, false)
		if used != len(data) || status != usCE|usDE || tape.chanT != test.loadPointWrite+test.rwTime {
			t.Fatalf("model %d write: transferred %d bytes, status %02X after %s", test.model, used, status, tape.chanT)
		}
		tape.finishWrite(data)
		out, _, status := tape.Exec(0x0c, nil, false)
		if !bytes.Equal(out, data) || status != usCE|usDE || tape.chanT != test.rwTime+test.reverseRead {
			t.Fatalf("model %d read backward: transferred %d bytes, status %02X after %s", test.model, len(out), status, tape.chanT)
		}
		_, used, status = tape.Exec(0x01, data, false)
		if used != len(data) || status != usCE|usDE || tape.chanT != test.reverseWrite+test.rwTime {
			t.Fatalf("model %d write after backward read: transferred %d bytes, status %02X after %s", test.model, used, status, tape.chanT)
		}
		tape.finishWrite(data)
		tape.pos = 0
		out, _, status = tape.Exec(0x02, nil, false)
		if !bytes.Equal(out, data) || status != usCE|usDE || tape.chanT != test.rwTime || tape.density() != test.density {
			t.Fatalf("model %d read: transferred %d bytes at density %d, status %02X after %s", test.model, len(out), tape.density(), status, tape.chanT)
		}
	}
}

func Test2420LoadPointAndReversal(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{transportModel: 7, peOnly: true}}
	tape.Reset()
	data := bytes.Repeat([]byte{0x5a}, 1500)
	for _, delay := range []time.Duration{49815625 * time.Nanosecond, 7943750 * time.Nanosecond} {
		_, used, status := tape.Exec(0x01, data, false)
		if status != usCE|usDE || used != len(data) || tape.chanT != delay {
			t.Fatalf("2420 write returned %d bytes and status %02X after %s, want %s", used, status, tape.chanT, delay)
		}
		tape.finishWrite(data)
	}
	out, _, status := tape.Exec(0x0c, nil, false)
	if !bytes.Equal(out, data) || status != usCE|usDE || tape.chanT != 23943750*time.Nanosecond {
		t.Fatalf("2420 read backward returned %d bytes and status %02X after %s", len(out), status, tape.chanT)
	}
	if _, _, status := tape.Exec(0x07, nil, false); status != usCE|usDE || tape.devT != 7943750*time.Nanosecond {
		t.Fatalf("2420 rewind status %02X after %s", status, tape.devT)
	}
	tape.setReelEOT(2400 * 12)
	tape.reelPosition, tape.pastLoadPoint = 110*12*nrziFramesPerInch, true
	if _, _, status := tape.Exec(0x07, nil, false); status != usCE|usDE || tape.devT != 6240*time.Millisecond {
		t.Fatalf("2420 rewind over the speed transition: status %02X after %s", status, tape.devT)
	}
}

func Test2401And2420SenseRecordingModeAndDirection(t *testing.T) {
	for _, model := range []uint8{3, 6, 7} {
		tape := &Tape2401{Tape3420: &Tape3420{transportModel: model, peOnly: model >= 6}}
		tape.Reset()
		want := byte(0)
		if model >= 6 {
			want = 0x04
		}
		if sense, _, _ := tape.Exec(0x04, nil, false); sense[3] != want {
			t.Fatalf("model %d at load point: sense %X, want mode %02X", model, sense, want)
		}
		data := make([]byte, 3200)
		tape.Exec(0x01, data, false)
		tape.finishWrite(data)
		tape.Exec(0x0c, nil, false)
		if sense, _, _ := tape.Exec(0x04, nil, false); sense[3] != want|0x02 {
			t.Fatalf("model %d after read backward: sense %X, want mode and direction %02X", model, sense, want|0x02)
		}
	}
}

func Test2415CapstanTurnaround(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	data := bytes.Repeat([]byte{0xa5}, 1500)
	for range 2 {
		tape.Tape3420.writeRecord(data)
	}
	tape.pos = 0
	for _, step := range []struct {
		command          byte
		transfer, ending time.Duration
	}{
		{0x02, 336 * time.Millisecond, 0},
		{0x02, 132 * time.Millisecond, 0},
		{0x0c, 337 * time.Millisecond, 0},
		{0x0c, 132 * time.Millisecond, 0},
		{0x37, 0, 337 * time.Millisecond},
		{0x37, 0, 132 * time.Millisecond},
		{0x27, 0, 337 * time.Millisecond},
	} {
		if _, _, status := tape.Exec(step.command, nil, false); status != usCE|usDE {
			t.Fatalf("2415 command %02x status %02x", step.command, status)
		}
		if transfer, ending := tape.CommandTiming(step.command, 0); transfer != step.transfer || ending != step.ending {
			t.Fatalf("2415 command %02x timing %s/%s, want %s/%s", step.command, transfer, ending, step.transfer, step.ending)
		}
	}
}

func Test2415ForwardSpacingAtLoadPointAndImageEnd(t *testing.T) {
	for _, tc := range []struct {
		command byte
		leadIn  int64
		status  byte
		pos     int
		ending  time.Duration
	}{
		{0x37, 0, usCE | usDE, 1, 265 * time.Millisecond},
		{0x37, nrzi2415EraseGap, usCE | usDE, 1, 312 * time.Millisecond},
		{0x3f, 0, usCE | usDE | usCUE | usUnitCheck, 2, 417 * time.Millisecond},
	} {
		tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
		tape.Tape3420.writeRecord(make([]byte, 1200))
		tape.Tape3420.writeRecord(make([]byte, 1800))
		tape.blocks[0].leadIn = tc.leadIn
		tape.pos = 0
		_, _, status := tape.Exec(tc.command, nil, false)
		channelEnd, deviceEnd := tape.CommandTiming(tc.command, 0)
		if status != tc.status || tape.pos != tc.pos || channelEnd != 0 || deviceEnd != tc.ending {
			t.Fatalf("space %02X: status %02X, position %d, time %s/%s", tc.command, status, tape.pos, channelEnd, deviceEnd)
		}
	}
}

func Test2415WriteStatusAndEraseBeforeReversal(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	data := bytes.Repeat([]byte{0xa5}, 1500)
	tape.Exec(0x01, data, false)
	tape.finishWrite(data)
	for range 2 {
		if sense, _, _ := tape.Exec(0x04, nil, false); sense[1] != 0x44 {
			t.Fatalf("2415 sense in write status: %x", sense)
		}
		tape.Exec(0x03, nil, false)
	}
	out, _, status := tape.Exec(0x0c, nil, false)
	if !bytes.Equal(out, data) || status != usCE|usDE || tape.chanT != 356*time.Millisecond {
		t.Fatalf("2415 read backward after write: %d bytes, status %02x, time %s", len(out), status, tape.chanT)
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[1] != 0x40 {
		t.Fatalf("2415 sense after entering read status: %x", sense)
	}
}

func Test2415LoadPointEraseCrossesEndMarker(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	tape.setReelEOT(4)
	data := make([]byte, 1000)
	tape.Exec(0x01, data, false)
	if status := tape.finishWrite(data); status != usUnitExcept || tape.reelPosition != 4480 {
		t.Fatalf("first write: status %02x, reel position %d", status, tape.reelPosition)
	}
	tape.Exec(0x01, data, false)
	tape.finishWrite(data)
	if tape.reelPosition != 5960 {
		t.Fatalf("second write should add only its block and gap: position %d", tape.reelPosition)
	}
	tape.Exec(0x07, nil, false)
	tape.Exec(0x02, nil, false)
	if !tape.tapeIndicate || tape.reelPosition != 4480 {
		t.Fatalf("read after rewind: tape indicate %t, reel position %d", tape.tapeIndicate, tape.reelPosition)
	}
}

func TestTapeEndMarkerOnBackwardMotion(t *testing.T) {
	for _, profile := range []struct {
		model  uint8
		is2415 bool
	}{
		{model: 2},
		{model: 5},
		{model: 7},
		{is2415: true},
	} {
		model := profile.model
		tape := &Tape2401{Tape3420: &Tape3420{transportModel: model, peOnly: model >= 5 || profile.is2415}, model2415: profile.is2415}
		tape.Reset()
		tape.setReelEOT(2)
		data := make([]byte, 3200)
		for range 2 {
			tape.Exec(0x01, data, false)
			tape.finishWrite(data)
		}
		for _, step := range []struct {
			command   byte
			indicated bool
		}{
			{0x04, true},
			{0x0c, model != 2},
			{0x0c, false},
		} {
			if _, _, status := tape.Exec(step.command, nil, false); status != usCE|usDE {
				t.Fatalf("model %d command %02X status %02X", model, step.command, status)
			}
			if tape.tapeIndicate != step.indicated {
				t.Fatalf("model %d at reel position %d: tape indicate %t, want %t", model, tape.reelPosition, tape.tapeIndicate, step.indicated)
			}
			if sense, _, _ := tape.Exec(0x04, nil, false); !profile.is2415 && (sense[1]&0x04 != 0) != step.indicated {
				t.Fatalf("model %d at reel position %d: sense %X, want tape indicate %t", model, tape.reelPosition, sense, step.indicated)
			}
		}
	}
}

func Test2415HaltBeforeFirstLoadPointWriteByte(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	data := make([]byte, 1500)
	tape.Exec(0x01, data, false)
	if tape.chanT != 336*time.Millisecond {
		t.Fatalf("load-point write time %s", tape.chanT)
	}
	op := ccwOp{Cmd: 0x01, Used: len(data), Status: usCE | usDE}
	if status := tape.haltTransfer(&op, 207*time.Millisecond); op.Used != 0 || status != usCE|usDE|usUnitCheck ||
		tape.sense[0] != 0x02 {
		t.Fatalf("halt before first byte: count %d, status %02x, sense %02x", op.Used, status, tape.sense[0])
	}
	op.Used = len(data)
	if status := tape.haltTransfer(&op, 209*time.Millisecond); op.Used != 1 || status != usCE|usDE {
		t.Fatalf("halt after first byte: count %d, status %02x", op.Used, status)
	}
}

func Test2415WriteTapeMarkTiming(t *testing.T) {
	for _, step := range []struct {
		sevenTrack, backward, pe bool
		delay                    time.Duration
	}{
		{false, false, false, 219 * time.Millisecond},
		{false, true, false, 424 * time.Millisecond},
		{true, false, false, 219 * time.Millisecond},
		{false, false, true, 220 * time.Millisecond},
	} {
		tape := &Tape2401{Tape3420: &Tape3420{sevenTrack: step.sevenTrack, peOnly: step.pe}, model2415: true}
		tape.Reset()
		tape.backward = step.backward
		if _, _, status := tape.Exec(0x1f, nil, false); status != usCE|usDE || len(tape.blocks) != 1 || !tape.blocks[0].mark {
			t.Fatalf("write tape mark: status %02x, records %d", status, len(tape.blocks))
		}
		if ce, de := tape.CommandTiming(0x1f, 0); ce != 0 || de != step.delay {
			t.Fatalf("write tape mark: delays %s/%s, want 0/%s", ce, de, step.delay)
		}
	}
}

func Test2415WriteTapeMarkCrossesEndMarker(t *testing.T) {
	for _, step := range []struct {
		name     string
		pe       bool
		position int64
	}{
		{name: "NRZI", position: 3485},
		{name: "PE", pe: true, position: 3500},
	} {
		t.Run(step.name, func(t *testing.T) {
			tape := &Tape2401{Tape3420: &Tape3420{peOnly: step.pe}, model2415: true}
			tape.Reset()
			tape.setReelEOT(4)
			if _, _, status := tape.Exec(0x1f, nil, false); status != usCE|usDE|usCUE|usUnitExcept ||
				tape.pos != 1 || tape.reelPosition != step.position {
				t.Fatalf("write tape mark: status %02x, position %d", status, tape.reelPosition)
			}
			tape.Exec(0x07, nil, false)
			if out, _, status := tape.Exec(0x02, nil, false); status != usCE|usDE|usUnitExcept ||
				len(out) != 0 || tape.reelPosition != step.position || !tape.tapeIndicate {
				t.Fatalf("read tape mark: status %02x, count %d, position %d, tape indicate %t", status, len(out), tape.reelPosition, tape.tapeIndicate)
			}
		})
	}
}

func Test2415PEDataFramingCrossesEndMarker(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{peOnly: true}, model2415: true}
	tape.Reset()
	tape.setReelEOT(2)
	data := bytes.Repeat([]byte{0xa5}, 2200)
	if _, used, status := tape.Exec(0x01, data, false); used != len(data) || status != usCE|usDE {
		t.Fatalf("start write: count %d, status %02x", used, status)
	}
	// The payload and gap reach 1580 frames. The framing adds 41
	// 800-bpi frames and crosses the end marker at 1600 frames.
	if status := tape.finishWrite(data); status != usUnitExcept || tape.reelPosition != 1621 {
		t.Fatalf("finish write: status %02x, position %d", status, tape.reelPosition)
	}
	tape.Exec(0x07, nil, false)
	if out, _, status := tape.Exec(0x02, nil, false); status != usCE|usDE ||
		!bytes.Equal(out, data) || tape.reelPosition != 1621 || !tape.tapeIndicate {
		t.Fatalf("read: status %02x, count %d, position %d, tape indicate %t", status, len(out), tape.reelPosition, tape.tapeIndicate)
	}
}

func Test2415WritePreservesLaterTapeMark(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sevenTrack bool
		leadIn     int64
		travel     int64
	}{
		{"nine-track", false, 1520, 2005},
		{"seven-track converter", true, 1066, 1671},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tape := &Tape2401{Tape3420: &Tape3420{sevenTrack: tc.sevenTrack}, model2415: true}
			tape.Reset()
			tape.setReelEOT(100)
			tape.Exec(0x1f, nil, false)
			tape.Exec(0x1f, nil, false)
			secondMarkEnd := tape.reelPosition
			tape.Exec(0x07, nil, false)
			tape.Exec(0x3f, nil, false)
			data := make([]byte, 1000)
			tape.Exec(0x01, data, false)
			tape.finishWrite(data)
			if len(tape.blocks) != 3 || tape.pos != 2 || !tape.blocks[2].mark || tape.blocks[2].leadIn != tc.leadIn {
				t.Fatalf("later tape mark or its spacing changed after writing a 1,000-byte record")
			}
			if _, _, status := tape.Exec(0x3f, nil, false); status != usCE|usDE || tape.reelPosition != secondMarkEnd {
				t.Fatalf("space over preserved tape mark: status %02X, position %d, want %d", status, tape.reelPosition, secondMarkEnd)
			}
			if want := time.Duration(tc.travel) * time.Second / 15000; tape.devT != want {
				t.Fatalf("space over preserved tape mark took %s, want %s", tape.devT, want)
			}
		})
	}
}

func Test2401BackspaceFileStopsNearTapeMark(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{transportModel: 3}}
	tape.setReelEOT(100)
	tape.Exec(0x17, nil, false)
	tape.Exec(0x17, nil, false)
	tape.Exec(0x1f, nil, false)
	firstMarkStart := tape.blocks[0].leadIn
	tape.Exec(0x17, nil, false)
	tape.Exec(0x1f, nil, false)
	tape.Exec(0x07, nil, false)
	tape.Exec(0x3f, nil, false)
	tape.Exec(0x3f, nil, false)
	forward := tape.devT
	tape.Exec(0x2f, nil, false)
	if _, _, status := tape.Exec(0x2f, nil, false); status != usCE|usDE {
		t.Fatalf("backspace file to the first mark: status %02X", status)
	}
	if tape.pos != 0 || tape.reelPosition != firstMarkStart || tape.devT != forward {
		t.Fatalf("backspace file ended at block %d, frame %d in %s, want block 0, frame %d in %s",
			tape.pos, tape.reelPosition, tape.devT, firstMarkStart, forward)
	}
}

func Test2415ErasePreservesLaterTapeMark(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	tape.setReelEOT(100)
	tape.Exec(0x1f, nil, false)
	tape.Exec(0x1f, nil, false)
	secondMarkEnd := tape.reelPosition
	tape.Exec(0x07, nil, false)
	tape.Exec(0x3f, nil, false)
	tape.Exec(0x17, nil, false)
	if _, _, status := tape.Exec(0x3f, nil, false); status != usCE|usDE || tape.reelPosition != secondMarkEnd {
		t.Fatalf("space after erasing the leading gap: status %02X, position %d, want %d", status, tape.reelPosition, secondMarkEnd)
	}
	if tape.devT != 32333333*time.Nanosecond {
		t.Fatalf("space after erase traversed the already erased gap: %s", tape.devT)
	}
}

func TestSevenTrackErasePreservesTailAndSensesEndMarker(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{sevenTrack: true, transportModel: 2}}
	tape.sevenMode = 0x80 | tapeOdd
	data := append(bytes.Repeat([]byte{0x24}, 2800), bytes.Repeat([]byte{0x19}, 400)...)
	data[0] = 0x25 // erased with the prefix, leaving the original LRCC behind
	tape.writeRecord(data)
	tape.Exec(0x1f, nil, false)
	tape.setReelEOT(3)
	originalEnd := tape.blocks[0].reelEnd
	markEnd := tape.blocks[1].reelEnd
	tape.Exec(0x07, nil, false)
	if _, _, status := tape.Exec(0x17, nil, false); status != usCE|usDE|usCUE|usUnitExcept || tape.reelPosition != 2800 {
		t.Fatalf("erase across the reflector: status %02X, position %d", status, tape.reelPosition)
	}
	if out, _, status := tape.Exec(0x02, nil, false); status != usCE|usDE|usUnitCheck ||
		!bytes.Equal(out, bytes.Repeat([]byte{0x19}, 400)) || tape.reelPosition != originalEnd {
		t.Fatalf("read erased block suffix: status %02X, length %d, position %d", status, len(out), tape.reelPosition)
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[0]&senseDataCheck == 0 || sense[3]&0x40 == 0 {
		t.Fatalf("partially erased block had no longitudinal check: sense %X", sense)
	}
	if _, _, status := tape.Exec(0x3f, nil, false); status != usCE|usDE || tape.reelPosition != markEnd {
		t.Fatalf("forward space to surviving mark: status %02X, position %d", status, tape.reelPosition)
	}
}

func Test2415SevenTrackEraseAfterBackspace(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{sevenTrack: true}, model2415: true}
	data := bytes.Repeat([]byte{0x24}, 4000)
	for _, tc := range []struct {
		mode      byte
		remaining int
		status    byte
	}{
		{0xb3, 1000, usCE | usDE},
		{0x73, 1915, usCE | usDE | usUnitCheck},
	} {
		tape.Exec(tc.mode, nil, false)
		tape.Exec(0x01, data, false)
		tape.finishWrite(data)
		tape.Exec(0x27, nil, false)
		tape.Exec(0x17, nil, false)
		tape.Exec(0x37, nil, false)
		out, _, status := tape.Exec(0x0c, nil, false)
		if status != tc.status || len(out) != tc.remaining {
			t.Fatalf("mode %02X: read %d remaining bytes with status %02X, want %d with status %02X", tc.mode, len(out), status, tc.remaining, tc.status)
		}
	}
}

func Test2415PESpaceUsesRecordedGeometry(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{peOnly: true}, model2415: true}
	tape.Reset()
	tape.setReelEOT(100)
	data := make([]byte, 1200)
	tape.Exec(0x01, data, false)
	tape.finishWrite(data)
	tape.Exec(0x1f, nil, false)
	tape.Exec(0x07, nil, false)
	for _, step := range []struct {
		cmd, status byte
		position    int
		duration    time.Duration
	}{
		// Data, 82 sync cells, 40 mark cells, 3.75-inch lead-in,
		// and a 0.6-inch gap after each block.
		{0x3f, usCE | usDE, 2, 9242 * time.Second / 30000},
		// Return over the mark and gap after reversing the capstan.
		{0x27, usCE | usDE | usCUE | usUnitExcept, 1, 205*time.Millisecond + 7000*time.Second/30000},
	} {
		_, _, status := tape.Exec(step.cmd, nil, false)
		channelEnd, deviceEnd := tape.CommandTiming(step.cmd, 0)
		if status != step.status || tape.pos != step.position || channelEnd != 0 || deviceEnd != step.duration {
			t.Fatalf("space %02x: status %02x, position %d, time %s/%s", step.cmd, status, tape.pos, channelEnd, deviceEnd)
		}
	}
}

func Test2415EraseGapTiming(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	tape.setReelEOT(100)
	for _, step := range []struct {
		backward bool
		delay    time.Duration
	}{
		{false, 217 * time.Millisecond},
		{true, 422 * time.Millisecond},
	} {
		tape.backward = step.backward
		if _, _, status := tape.Exec(0x17, nil, false); status != usCE|usDE {
			t.Fatalf("erase gap status: %02x", status)
		}
		if ce, de := tape.CommandTiming(0x17, 0); ce != 0 || de != step.delay {
			t.Fatalf("erase gap from backward=%t: delays %s/%s, want 0/%s", step.backward, ce, de, step.delay)
		}
	}
	if tape.reelPosition != 6000 {
		t.Fatalf("two erase gaps should advance 7.5 inches, got %d frame units", tape.reelPosition)
	}
}

func Test2415PEEraseGapTravel(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{peOnly: true}, model2415: true}
	tape.Reset()
	tape.setReelEOT(3)
	tape.backward = true
	if _, _, status := tape.Exec(0x17, nil, false); status != usCE|usDE|usCUE|usUnitExcept ||
		tape.reelPosition != 2800 {
		t.Fatalf("erase gap: status %02x, position %d", status, tape.reelPosition)
	}
	if ce, de := tape.CommandTiming(0x17, 0); ce != 0 || de != 205*time.Millisecond+2800*time.Second/15000 {
		t.Fatalf("erase gap: channel end %s, device end %s", ce, de)
	}
}

func Test2415RewindRestoresForwardStatus(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	data := bytes.Repeat([]byte{0x42}, 1500)
	tape.writeRecord(data)
	tape.Exec(0x0c, nil, false)
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[3]&0x02 == 0 {
		t.Fatalf("sense must indicate backward motion: %x", sense)
	}
	tape.Exec(0x07, nil, false)
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[3]&0x02 != 0 {
		t.Fatalf("sense must indicate forward after rewind: %x", sense)
	}
	if out, _, status := tape.Exec(0x02, nil, false); !bytes.Equal(out, data) ||
		status != usCE|usDE || tape.chanT != 336*time.Millisecond {
		t.Fatalf("read from load point: count %d, status %02x, delay %s", len(out), status, tape.chanT)
	}
}

func Test2415RewindDeviceEndDependsOnReelPosition(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	for range 8 {
		tape.Tape3420.writeRecord(make([]byte, 11520))
	}
	for _, trackMarker := range []bool{false, true} {
		tape.pos = len(tape.blocks)
		if trackMarker {
			tape.setReelEOT(24000)
			tape.seekReel()
		}
		_, _, status := tape.Exec(0x07, nil, false)
		channelEnd, deviceEnd := tape.CommandTiming(0x07, 0)
		if status != usCE|usDE || channelEnd != 0 || deviceEnd != time.Second || tape.pos != 0 {
			t.Fatalf("2415 rewind with marker tracking %t: status %02x, delays %s/%s, position %d", trackMarker, status, channelEnd, deviceEnd, tape.pos)
		}
	}
}

func Test2415DualDensityTimingAndSense(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{dualDensity: true}, model2415: true}
	tape.Reset()
	data := make([]byte, 1200)
	for _, tt := range []struct {
		command byte
		mode    byte
		time    time.Duration
		density int
	}{
		{0xc3, 0x04, 236*time.Millisecond + 1282*time.Second/30000, 1600},
		{0xcb, 0x00, 316 * time.Millisecond, 800},
	} {
		tape.remountWithRing(true)
		if _, _, status := tape.Exec(tt.command, nil, false); status != usCE|usDE {
			t.Fatalf("set density %d: status %02x", tt.density, status)
		}
		if sense, _, _ := tape.Exec(0x04, nil, false); sense[2] != 0x03 || sense[3] != tt.mode {
			t.Fatalf("sense in density %d: %x", tt.density, sense)
		}
		tape.Exec(0x01, data, false)
		tape.finishWrite(data)
		if tape.chanT != tt.time || tape.blocks[0].density != tt.density {
			t.Fatalf("write in density %d: timing %s, stored density %d", tt.density, tape.chanT, tape.blocks[0].density)
		}
	}
}

func TestDualDensityWriteAfterLoadPointErase(t *testing.T) {
	for _, model2415 := range []bool{false, true} {
		tape := &Tape2401{Tape3420: &Tape3420{dualDensity: true}, model2415: model2415}
		for _, command := range []byte{0xc3, 0x17, 0xcb, 0x17, 0x1f} {
			if _, _, status := tape.Exec(command, nil, false); status != usCE|usDE {
				t.Fatalf("2415=%t command %02X: status %02X", model2415, command, status)
			}
		}
		tape.Exec(0x01, make([]byte, 100), false)
		tape.finishWrite(make([]byte, 100))
		if !tape.blocks[0].mark || tape.blocks[0].density != 1600 || tape.blocks[1].density != 1600 {
			t.Fatalf("2415=%t recorded densities %d, %d", model2415, tape.blocks[0].density, tape.blocks[1].density)
		}
		tape.Exec(0x07, nil, false)
		tape.Exec(0x01, make([]byte, 100), false)
		tape.finishWrite(make([]byte, 100))
		if tape.blocks[0].density != 800 {
			t.Fatalf("2415=%t write after rewind used density %d", model2415, tape.blocks[0].density)
		}
	}
}

func Test2415PEOnlyModeAndIncompatibleReel(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{peOnly: true}, model2415: true}
	tape.Reset()
	if _, _, status := tape.Exec(0xcb, nil, false); status != usCE|usDE || !tape.transferPE {
		t.Fatalf("NRZI mode set must leave a PE-only drive in PE: status %02x", status)
	}
	data := bytes.Repeat([]byte{0xa5}, 1200)
	tape.Exec(0x01, data, false)
	tape.finishWrite(data)
	if tape.blocks[0].density != 1600 || tape.chanT != 236*time.Millisecond+1282*time.Second/30000 {
		t.Fatalf("PE-only write: density %d, time %s", tape.blocks[0].density, tape.chanT)
	}
	tape.remountWithRing(true)
	if out, _, status := tape.Exec(0x02, nil, false); status != usCE|usDE || !bytes.Equal(out, data) ||
		tape.chanT != 236*time.Millisecond+1282*time.Second/30000 {
		t.Fatalf("read PE reel: status %02x, bytes %d, time %s", status, len(out), tape.chanT)
	}
	for _, sample := range []struct {
		elapsed time.Duration
		count   int
	}{{237 * time.Millisecond, 0}, {238 * time.Millisecond, 19}} {
		op := ccwOp{Cmd: 0x02, Read: true, Out: data}
		if status := tape.haltTransfer(&op, sample.elapsed); status != usCE|usDE || len(op.Out) != sample.count {
			t.Fatalf("halt PE read at %s: status %02x, %d bytes", sample.elapsed, status, len(op.Out))
		}
	}
	tape.remountWithRing(true)
	tape.blocks[0].density = 800
	if out, _, status := tape.Exec(0x02, nil, false); status != usCE|usDE|usUnitCheck || len(out) != 0 {
		t.Fatalf("read NRZI reel: status %02x, bytes %d", status, len(out))
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[1]&1 == 0 || sense[3]&4 == 0 {
		t.Fatalf("incompatible reel sense %x", sense)
	}
}

func Test2415SevenTrackDensityControlsTravel(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{sevenTrack: true}, model2415: true}
	if _, _, status := tape.Exec(0x33, nil, false); status != usCE|usDE {
		t.Fatalf("select 200 bpi without translation: status %02x", status)
	}
	data := make([]byte, 3750)
	if _, n, status := tape.Exec(0x01, data, false); n != len(data) || status != usCE|usDE ||
		tape.chanT != 1244*time.Millisecond {
		t.Fatalf("seven-track transfer: count %d, status %02x, time %s", n, status, tape.chanT)
	}
	tape.finishWrite(data)
	if length := tape.blockLength(tape.blocks[0]); length != 18600 {
		t.Fatalf("3750 frames at 200 bpi plus load-point erase and gap: recorded length %d", length)
	}
}

func Test2415SenseAfterDataCheckAndUnload(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	tape.Tape3420.writeRecord([]byte{0xa5})
	tape.blocks[0].bad = true
	tape.pos = 0
	if _, _, status := tape.Exec(0x02, nil, false); status != usCE|usDE|usUnitCheck {
		t.Fatalf("2415 flagged record status %02x", status)
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); !bytes.Equal(sense, []byte{0x08, 0x40, 0x03, 0, 0, 0}) {
		t.Fatalf("2415 sense after data check: %x", sense)
	}
	tape.Exec(0x0f, nil, false)
	if sense, _, _ := tape.Exec(0x04, nil, false); !bytes.Equal(sense, []byte{0x40, 0x20, 0x03, 0, 0, 0}) {
		t.Fatalf("2415 sense after unload: %x", sense)
	}
}

func Test2401DualDensityReel(t *testing.T) {
	m, _ := newTest360(t, true, nil)
	tape := &Tape2401{Tape3420: &Tape3420{dualDensity: true}}
	target := &Tape2401{Tape3420: &Tape3420{dualDensity: true}}
	const sourceDev, targetDev = 0x3f0, 0x3f1
	if _, err := m.CSS.Attach(sourceDev, tape); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CSS.Attach(targetDev, target); err != nil {
		t.Fatal(err)
	}
	record := bytes.Repeat([]byte{0xa5}, 1200)
	const ok = usCE | usDE
	for _, tc := range []struct {
		mode, otherMode byte
		density         int
		wantTime        time.Duration
	}{
		{0xc3, 0xcb, 1600, 8*time.Millisecond + 1282*time.Second/120000},
		{0xcb, 0xc3, 800, 28 * time.Millisecond},
	} {
		tape.Exec(0x07, nil, false)
		if _, _, status := tape.Exec(tc.mode, nil, false); status != ok {
			t.Fatalf("mode %02x status %02x", tc.mode, status)
		}
		if _, used, status := tape.Exec(0x01, record, true); used != len(record) || status != ok || tape.chanT != tc.wantTime {
			t.Fatalf("mode %02x write used %d, status %02x, took %s", tc.mode, used, status, tape.chanT)
		}
		tape.finishWrite(record)
		if density := tape.blocks[0].density; density != tc.density {
			t.Fatalf("mode %02x recorded at %d bpi", tc.mode, density)
		}
		if err := m.CSS.Swap2401Reels(sourceDev, targetDev); err != nil {
			t.Fatal(err)
		}
		target.Exec(tc.otherMode, nil, false)
		for _, read := range []byte{0x02, 0x0c} {
			out, _, status := target.Exec(read, nil, false)
			if !bytes.Equal(out, record) || status != ok || target.chanT != tc.wantTime {
				t.Fatalf("mode %02x read %02x returned %d bytes, status %02x, took %s", tc.mode, read, len(out), status, target.chanT)
			}
		}
		if err := m.CSS.Swap2401Reels(sourceDev, targetDev); err != nil {
			t.Fatal(err)
		}
	}
}

func Test2401SevenTrackFrames(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{sevenTrack: true}}
	tape.Reset()
	data := []byte{0xde, 0xad, 0xbe}
	tape.writeRecord(data)
	if frames, err := tape.blocks[0].bytes(); err != nil || !bytes.Equal(frames, []byte{0x37, 0x2a, 0x76, 0x3e}) {
		t.Fatalf("converted physical frames % X, %v", frames, err)
	}
	tape.Exec(0x07, nil, false)
	if out, _, st := tape.Exec(0x02, nil, false); st != usCE|usDE || !bytes.Equal(out, data) {
		t.Fatalf("converted read % X status %02X", out, st)
	}
	tape.Exec(0x07, nil, false)
	tape.Exec(0xa3, nil, false) // 800 bpi, even redundancy, translator off
	if _, _, st := tape.Exec(0x02, nil, false); st != usCE|usDE|usUnitCheck {
		t.Fatalf("wrong redundancy status %02X", st)
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); !bytes.Equal(sense, []byte{0x08, 0x50, 0x03, 0x80, 0, 0}) {
		t.Fatalf("parity check sense % X", sense)
	}
	tape.Exec(0x07, nil, false)
	tape.Exec(0xab, nil, false) // 800 bpi, even redundancy, translator on
	text := EncodeEBCDIC(" 0A")
	tape.writeRecord(text)
	if frames, err := tape.blocks[0].bytes(); err != nil || !bytes.Equal(frames, []byte{0x50, 0x0a, 0x71}) {
		t.Fatalf("translated physical frames % X, %v", frames, err)
	}
	tape.Exec(0x07, nil, false)
	if out, _, st := tape.Exec(0x02, nil, false); st != usCE|usDE || !bytes.Equal(out, text) {
		t.Fatalf("translated read % X status %02X", out, st)
	}
}

func Test2401ReflectiveEndOfTape(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}}
	tape.setReelEOT(1)
	data := bytes.Repeat([]byte{0x12}, 160)
	if got := tape.finishWrite(data); got != 0 {
		t.Fatalf("write before marker: %02X", got)
	}
	if got := tape.finishWrite(data); got != usUnitExcept {
		t.Fatalf("write across marker: %02X", got)
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[1] != 0x44 {
		t.Fatalf("sense after crossing marker: %X", sense)
	}
	tape.Exec(0x27, nil, false)
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[1] != 0x40 {
		t.Fatalf("sense after backspacing: %X", sense)
	}
	if out, _, status := tape.Exec(0x02, nil, false); status != usCE|usDE || !bytes.Equal(out, data) {
		t.Fatalf("read across marker: status %02X, %d bytes", status, len(out))
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[1] != 0x44 {
		t.Fatalf("sense after reading past the marker: %X", sense)
	}
}

func TestSIMHTapePositionAndErrors(t *testing.T) {
	img := simhRecord(14, "metadata")
	img = append(img, simhRecord(0, "ABC")...)
	img = binary.LittleEndian.AppendUint32(img, 0) // mark
	img = append(img, simhRecord(8, "DEF")...)
	damaged := simhRecord(0, "GHI")
	damaged[len(damaged)-4] = 0
	img = append(img, damaged...)
	original := bytes.Clone(img)
	tp, err := MountSIMH(memReader(img))
	if err != nil {
		t.Fatal(err)
	}
	ok := byte(usCE | usDE)
	for i, tc := range []struct {
		cmd    byte
		want   string
		status byte
		pos    int
	}{
		{0x0c, "", ok | usUnitCheck, 0}, // BOT
		{0x02, "ABC", ok, 1},
		{0x0c, "CBA", ok, 0},
		{0x02, "ABC", ok, 1}, // backwards did not mutate source
		{0x02, "", ok | usUnitExcept, 2},
		{0x0c, "", ok | usUnitExcept, 1},
		{0x37, "", ok | usUnitExcept, 2},
		{0x02, "DEF", ok | usUnitCheck, 3}, // recovered bad data
		{0x0c, "FED", ok | usUnitCheck, 2},
		{0x37, "", ok, 3},
		{0x02, "", ok | usUnitCheck, 4}, // framing damage reached only now
		{0x0c, "", ok | usUnitCheck, 3},
	} {
		out, _, status := tp.Exec(tc.cmd, nil, false)
		if string(out) != tc.want || status != tc.status || tp.pos != tc.pos {
			t.Fatalf("step %d: out=%q status=%02x pos=%d", i, out, status, tp.pos)
		}
		if i >= 7 && tc.status&usUnitCheck != 0 && tp.sense[0]&senseDataCheck == 0 {
			t.Fatalf("step %d missing data check: %x", i, tp.sense)
		}
	}
	if !bytes.Equal(img, original) {
		t.Fatal("modified source")
	}
	tp.Exec(0x07, nil, false)
	tp.Exec(0x01, []byte("overlay"), false)
	out, _, _ := tp.Exec(0x0c, nil, false)
	if string(out) != "yalrevo" {
		t.Fatalf("backward overlay: %q", out)
	}
	out, _, _ = tp.Exec(0x02, nil, false)
	if string(out) != "overlay" || !bytes.Equal(img, original) {
		t.Fatalf("modified overlay/source: %q", out)
	}
}

func TestTapeReadBackwardChannel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		addr   uint32
		count  uint16
		flags  byte
		idaws  []uint32
		status byte
		want   map[uint32]string
	}{
		{"direct", 0x3209, 10, 0, nil, 0, map[uint32]string{0x3200: "0123456789"}},
		{"short", 0x3209, 5, ccwSLI, nil, 0, map[uint32]string{0x3205: "56789"}},
		{"ida", 0x3000, 10, ccwIDA, []uint32{0x3802, 0x47ff}, 0, map[uint32]string{0x3800: "789", 0x47f9: "0123456"}},
		{"bad_ida_alignment", 0x3000, 10, ccwIDA, []uint32{0x3802, 0x4000}, scsProgramCheck, nil},
		{"underflow", 2, 10, 0, nil, scsProgramCheck, nil},
		{"upper_boundary", (1 << 20) - 1, 10, 0, nil, 0, map[uint32]string{(1 << 20) - 10: "0123456789"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTest370(t, nil)
			tp := &Tape3420{blocks: []tapeBlock{{data: []byte("0123456789")}}, pos: 1}
			_, err := m.CSS.Attach(0x130, tp)
			if err != nil {
				t.Fatal(err)
			}
			x := m.CSS.bydev[0x130]
			be.PutUint32(m.S.Mem[0x3100:], 0x0c000000|tc.addr)
			m.S.Mem[0x3104] = tc.flags
			be.PutUint16(m.S.Mem[0x3106:], tc.count)
			for i, a := range tc.idaws {
				be.PutUint32(m.S.Mem[0x3000+4*i:], a)
			}
			runNow(m, x, 0x3100, 0)
			if x.schStatus != tc.status {
				t.Fatalf("status=%02x want=%02x", x.schStatus, tc.status)
			}
			if tc.status == 0 && (x.residual != 0 || x.devStatus != usCE|usDE || tp.pos != 0) {
				t.Fatalf("residual=%d device=%02x position=%d", x.residual, x.devStatus, tp.pos)
			}
			// An invalid data address is found when the data is transferred:
			// the drive has accepted the command, the block passes, and the
			// drive's ending status accompanies the program check.
			if tc.status != 0 && (tp.pos != 0 || x.devStatus != usCE|usDE || x.residual != tc.count) {
				t.Fatalf("checked transfer: position=%d device=%02x residual=%d", tp.pos, x.devStatus, x.residual)
			}
			for a, want := range tc.want {
				if got := string(m.S.Mem[a : a+uint32(len(want))]); got != want {
					t.Fatalf("%x=%q want %q", a, got, want)
				}
			}
		})
	}
}

func TestReadBackwardDataChainAndProtection(t *testing.T) {
	m, _ := newTest370(t, nil)
	tp := &Tape3420{blocks: []tapeBlock{{data: []byte("0123456789")}}, pos: 1}
	if _, err := m.CSS.Attach(0x130, tp); err != nil {
		t.Fatal(err)
	}
	x := m.CSS.bydev[0x130]
	// Discard the last three bytes; transfer the remaining seven backwards.
	copy(m.S.Mem[0x3100:], []byte{0x0c, 0, 0, 1, ccwCD | ccwSkip | ccwIDA, 0, 0, 3,
		0, 0, 0x33, 6, ccwSLI, 0, 0, 20})
	runNow(m, x, 0x3100, 0)
	if got := string(m.S.Mem[0x3300:0x3307]); got != "0123456" || x.residual != 13 || x.ccwaddr != 0x3110 || x.schStatus != 0 {
		t.Fatalf("data=%q residual=%d ccw=%x status=%x", got, x.residual, x.ccwaddr, x.schStatus)
	}
	if !bytes.Equal(m.S.Mem[0x3200:0x3203], []byte{0, 0, 0}) {
		t.Fatal("skip stored data")
	}
	// Crossing a storage-key boundary must check in transfer order.
	tp.pos = 1
	x.clearStatus()
	copy(m.S.Mem[0x3100:], []byte{0x0c, 0, 0x38, 2, 0, 0, 0, 10})
	*m.S.key(0x3800) = 0x10
	*m.S.key(0x37ff) = 0x20
	runNow(m, x, 0x3100, 1)
	if x.schStatus != scsProtection || string(m.S.Mem[0x3800:0x3803]) != "789" || m.S.Mem[0x37ff] != 0 {
		t.Fatalf("protection=%x data=%x", x.schStatus, m.S.Mem[0x37ff:0x3803])
	}
	if *m.S.key(0x3800)&(keyRef|keyChg) != keyRef|keyChg || *m.S.key(0x37ff) != 0x20 {
		t.Fatal("incorrect storage reference/change bits")
	}
}

// runNow executes a channel program, advancing the clock through its timed
// transfers.
func runNow(m *Machine, x *Subchannel, addr uint32, key byte) {
	m.CSS.run(x, addr, false, 0, key)
	for m.CSS.next != 0 {
		m.tod = m.CSS.next
		m.CSS.tick370()
	}
}
