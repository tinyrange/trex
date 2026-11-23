package s390

import (
	"bytes"
	"encoding/binary"
	"testing"
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
