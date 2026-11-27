package s390

import (
	"bytes"
	"testing"
	"time"
)

// newTest360 returns a System/360 (optionally 9020) machine running code at
// 0x1000, with disabled-wait new PSWs.
func newTest360(t *testing.T, model9020 bool, code []byte) (*Machine, *CPU) {
	t.Helper()
	m := NewMachine(Config{Memory: 1 << 20, S360: true, Model9020: model9020, Start: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)})
	c := m.CPUs[0]
	copy(m.S.Mem[0x1000:], code)
	for _, a := range []int{pswExtNew, pswSVCNew, pswPgmNew, pswIONew} {
		be.PutUint64(m.S.Mem[a:], 0x00020000_0000DEAD)
	}
	c.Stopped = false
	c.loadPSW(0x00000000_00001000)
	return m, c
}

func Test9020EDisplayStorageRangesAndCheckpoint(t *testing.T) {
	cfg := Config{Model9020E: true, Memory: bytesPer9020SE, DisplayElements9020E: 2}
	m := NewMachine(cfg)
	for _, tc := range []struct {
		address, length uint32
		valid           bool
	}{
		{bytesPer9020SE - 2, 2, true},
		{bytesPer9020SE - 2, 4, false},
		{bytesPer9020SE, 2, false},
		{displayBase9020E, bytesPer9020DE, true},
		{displayBase9020E, bytesPer9020DE + 1, false},
		{displayBase9020E + bytesPer9020DE, 2, false},
		{displayBase9020E + bytesPer9020SE, bytesPer9020DE, true},
		{displayBase9020E + bytesPer9020SE + bytesPer9020DE, 2, false},
	} {
		if got := m.S.valid(tc.address, tc.length); got != tc.valid {
			t.Errorf("range %06X + %X valid = %t, want %t", tc.address, tc.length, got, tc.valid)
		}
	}

	m.Alter(displayBase9020E, []byte{0xab})
	*m.S.key(displayBase9020E) = 0x58
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	matching := NewMachine(cfg)
	if err := matching.Restore(bytes.NewReader(checkpoint.Bytes()), false); err != nil {
		t.Fatal(err)
	}
	if got, key := matching.S.Mem[displayBase9020E], *matching.S.key(displayBase9020E); got != 0xab || key != 0x58 {
		t.Fatalf("restored display byte %02X and key %02X", got, key)
	}
	cfg.Memory *= 2
	if err := NewMachine(cfg).Restore(bytes.NewReader(checkpoint.Bytes()), false); err == nil {
		t.Fatal("accepted checkpoint with different main storage and the same display storage")
	}
}

func TestS360PSWBit12IsASCII(t *testing.T) {
	m, c := newTest360(t, false, []byte{0x82, 0x00, 0x0f, 0x00}) // LPSW X'F00'
	be.PutUint64(m.S.Mem[0xf00:], 0x00080000_00002000)           // bit 12 on
	copy(m.S.Mem[0x2000:], []byte{
		0xf3, 0x21, 0xc1, 0x00, 0xc2, 0x00, // UNPK 256(3,12),512(2,12)
		0xfa, 0x10, 0xc3, 0x00, 0xc4, 0x00, // AP 768(2,12),1024(1,12)
		0x0a, 0x01, // SVC 1
	})
	c.GR[12] = 0x3000
	copy(m.S.Mem[0x3200:], []byte{0x12, 0x3c})
	copy(m.S.Mem[0x3300:], []byte{0x00, 0x5c})
	copy(m.S.Mem[0x3400:], []byte{0x7d})
	m.Run(10)
	if c.PSW.Wait != true || be.Uint16(m.S.Mem[pswSVCOld+2:]) != 1 {
		t.Fatalf("did not reach SVC: %s", c.PSW)
	}
	if old := be.Uint64(m.S.Mem[pswSVCOld:]); old&(1<<51) == 0 {
		t.Fatalf("SVC old PSW lost the ASCII bit: %016X", old)
	}
	// Zones are 0101 in USASCII-8 mode; the sign stays in the last byte.
	if got := m.S.Mem[0x3100:0x3103]; got[0] != 0x51 || got[1] != 0x52 || got[2] != 0xc3 {
		t.Fatalf("UNPK % X", got)
	}
	// 5 - 7 = -2 with the preferred USASCII-8 minus sign 1011.
	if got := m.S.Mem[0x3300:0x3302]; got[0] != 0x00 || got[1] != 0x2b {
		t.Fatalf("AP % X", got)
	}
}

func TestS360RejectsSystem370Instructions(t *testing.T) {
	for _, op := range [][]byte{{0x0e, 0x24}, {0x84, 0, 0, 0}, {0x85, 0, 0, 0}, {0xbf, 0x1f, 0x10, 0x00}, {0xb2, 0x05, 0x10, 0x00}, {0xb7, 0x00, 0x10, 0x00}} {
		m, c := newTest360(t, false, op)
		m.Run(2)
		if code := be.Uint16(m.S.Mem[pswPgmOld+2:]); code != pgmOperation {
			t.Fatalf("op %X: interruption code %04X", op[0], code)
		}
		_ = c
	}
}

func Test9020WriteDirectInvalidIOCE(t *testing.T) {
	for _, immediate := range []byte{0x31, 0x51, 0x61, 0x71} {
		m, _ := newTest360(t, true, []byte{0x84, immediate, 0, 0})
		m.Run(1)
		if code := be.Uint16(m.S.Mem[pswPgmOld+2:]); code != pgmSpecification {
			t.Fatalf("WRD %02X interruption %04X, want specification", immediate, code)
		}
	}
}

func Test9020Delay(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		m, c := newTest360(t, true, []byte{0x0b, 0x01, 0x05, 0x10}) // DLY 0,1; BALR 1,0
		start := m.tod
		c.PSW.CC = 2
		c.PSW.Ext = interrupt
		m.Run(2)
		if c.PSW.IA != 0x1002 || c.Instructions != 1 || c.PSW.CC != 2 || c.PSW.Wait {
			t.Fatalf("DLY did not suspend at the next instruction: %s", c.PSW)
		}
		if interrupt {
			c.InterruptKey()
			m.Run(2)
			if m.tod >= start+256*todMicro || c.maintenance9020.delayUntil != 0 ||
				be.Uint16(m.S.Mem[pswExtOld+2:]) != 0x0040 {
				t.Fatalf("external interrupt did not end DLY early: %s", c.PSW)
			}
			continue
		}
		m.Breakpoints = map[uint32]bool{0x1004: true}
		m.Run(20000)
		if c.PSW.IA != 0x1004 || c.Instructions != 2 || m.tod < start+256*todMicro {
			t.Fatalf("DLY did not wait to its deadline: %s", c.PSW)
		}
	}
}

func Test9020SubsystemRestart(t *testing.T) {
	m, c := newTest360(t, true, nil)
	if err := m.CSS.Attach9020CTC(0x320, 0x420); err != nil {
		t.Fatal(err)
	}
	c.maintenance9020.atr, c.maintenance9020.atrSet = 0x1200000000, true
	m.CSS.ioceATR[0] = channelATR9020{Mask: 0x1200000000, Active: true}
	m.CSS.bydev[0x320].dev.(*ctc9020Side).notReady = 0
	be.PutUint64(m.S.Mem[bytesPer9020SE:], 0x00040000_00082000)
	be.PutUint32(m.S.Mem[bytesPer9020SE+0x1000:], 0xA1B2C3D4)
	if err := m.Restart9020(2); err != nil {
		t.Fatal(err)
	}
	if c.maintenance9020.psb != bytesPer9020SE || c.Prefix != bytesPer9020SE ||
		c.PSW.IA != 0x82000 || c.Stopped || c.atr9020() != 0x1200000000 ||
		!m.CSS.ioceATR[0].Active || be.Uint32(m.S.Mem[bytesPer9020SE+0x1000:]) != 0xA1B2C3D4 {
		t.Fatal("subsystem restart lost its storage selection or configuration")
	}
	if d := m.CSS.bydev[0x320].dev.(*ctc9020Side); d.notReady != 0x40 {
		t.Fatal("subsystem restart did not reset the adapter")
	}
}

func Test9020AAddressTranslatorSecondRegister(t *testing.T) {
	m := NewMachine(Config{Model9020A: true, Memory: 12 * bytesPer9020ASE})
	c := m.CPUs[0]
	if _, err := m.CSS.Attach(0x130, &Tape3420{}); err != nil {
		t.Fatal(err)
	}
	be.PutUint64(m.S.Mem, 0x00000000_00001000)
	copy(m.S.Mem[0x1000:], []byte{
		0x0d, 0x34, // SATR 3,4.
		0x0e, 0x56, // IATR 5,6.
		0x58, 0x20, 0x70, 0x00, // L 2,0(7).
	})
	const lastSlot = 11 * bytesPer9020ASE
	be.PutUint32(m.S.Mem[2*bytesPer9020ASE+0x200:], 0x01234567)
	be.PutUint32(m.S.Mem[lastSlot+0x200:], 0xdeadbeef)
	if err := m.Restart9020(1); err != nil {
		t.Fatal(err)
	}
	// Swap slots 3 and 12 for the CE and IOCE. Slot 12 is in ATR 2.
	c.GR[3], c.GR[4], c.GR[7] = 0x12c45678, 0x9ab30084, lastSlot+0x200
	m.Run(3)
	if c.PSW.CC != 0 || c.GR[2] != 0x01234567 || c.GR[5] != 0x12c45678 || c.GR[6] != 0x9ab30000 {
		t.Fatalf("9020A ATR readback or CE translation: %s, data=%08X, ATR=%08X %08X", c.PSW, c.GR[2], c.GR[5], c.GR[6])
	}
	atr := m.CSS.ioceAddresses(0x130)
	got := m.CSS.channelSegments(atr, []segment{{addr: lastSlot - 4, n: 8}}, false)
	want := []segment{{addr: lastSlot - 4, n: 4}, {addr: 2 * bytesPer9020ASE, n: 4}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("9020A IOCE transfer across the last slot boundary: got %+v, want %+v", got, want)
	}
}

func TestS360StorageOperandsRequireAlignment(t *testing.T) {
	for _, op := range [][]byte{
		{0x4c, 0x00, 0x02, 0x01}, // MH at an odd address
		{0x4f, 0x00, 0x02, 0x04}, // CVB off a doubleword boundary
		{0x90, 0x07, 0x02, 0x02}, // STM off a word boundary
		{0x98, 0x07, 0x02, 0x02}, // LM off a word boundary
	} {
		m, _ := newTest360(t, false, op)
		m.Run(1)
		if code := be.Uint16(m.S.Mem[pswPgmOld+2:]); code != pgmSpecification {
			t.Errorf("instruction %X: interruption %04X, want specification", op, code)
		}
	}
}

func TestIOCEPartialCharacterStore(t *testing.T) {
	for _, op := range []byte{0xd2, 0xd7, 0xdc} { // MVC, XC, TR
		m := NewMachine(Config{Memory: 128 << 10, IOCE: true})
		c := m.CPUs[0]
		copy(m.S.Mem[0x1000:], []byte{op, 7, 0x17, 0xfc, 0x20, 0})
		be.PutUint64(m.S.Mem[pswPgmNew:], 0x00020000_0000dead)
		c.GR[1], c.GR[2] = 0x2000, 0x3000
		c.Stopped = false
		c.loadPSW(0x00200000_00001000)
		*m.S.key(0x2000) = 0x20
		*m.S.key(0x2800) = 0x10
		copy(m.S.Mem[0x3000:], bytes.Repeat([]byte{1}, 8))
		m.Run(1)
		if code := be.Uint16(m.S.Mem[pswPgmOld+2:]); code != pgmProtection {
			t.Errorf("op %X: interruption %04X, want protection", op, code)
		}
		if got := m.S.Mem[0x27fc:0x2804]; !bytes.Equal(got, []byte{1, 1, 1, 1, 0, 0, 0, 0}) {
			t.Errorf("op %X: stores across protection boundary %X", op, got)
		}
	}
}

func TestModel9020SetAddressTranslator(t *testing.T) {
	m, c := newTest360(t, true, []byte{0x0d, 0x01, 0x0e, 0x23}) // SATR 0,1; IATR 2,3
	if _, err := m.CSS.Attach(0x130, &Tape3420{}); err != nil {
		t.Fatal(err)
	}
	c.GR[0], c.GR[1] = 0x11000000, 0x84 // Map both slots to SE 1 from CE 1 and IOCE 1.
	m.Run(2)
	if c.PSW.CC != 0 || c.GR[2] != 0x11000000 || c.GR[3] != 0 {
		t.Fatalf("CC %d, ATR %08X %08X", c.PSW.CC, c.GR[2], c.GR[3])
	}
	if got, err := m.TranslateVirtual(0x82000); err != nil || got != 0x2000 {
		t.Fatalf("CPU translation %X, %v", got, err)
	}
	atr := m.CSS.ioceAddresses(0x130)
	segments := m.CSS.channelSegments(atr, []segment{{addr: 0x7fffc, n: 8}}, false)
	if len(segments) != 2 || segments[0] != (segment{addr: 0x7fffc, n: 4}) || segments[1] != (segment{addr: 0, n: 4}) {
		t.Fatalf("channel segments %+v", segments)
	}
}

func TestModel9020DecimalDataExceptionStoresResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   byte
		dst  []byte
		src  []byte
		want []byte
	}{
		{"invalid digits in sign byte", 0xfa, []byte{0x1c}, []byte{0xcd}, []byte{0xff}},
		{"invalid upper byte", 0xfa, []byte{0x20, 0x1c}, []byte{0x2a, 0x3c}, []byte{0xff, 0x4c}},
		{"multiply short workspace", 0xfc, []byte{0x22, 0x2c}, []byte{0x1c}, []byte{0x00, 0x2c}},
		{"multiply across doublewords", 0xfc, []byte{0x23, 0x23, 0x23, 0x2c}, []byte{0x11, 0x1c}, []byte{0x23, 0x25, 0x75, 0x2c}},
		{"multiply skips zero workspace byte", 0xfc, []byte{0x01, 0x00, 0x99, 0x9d}, []byte{0x99, 0x9c}, []byte{0x09, 0x98, 0x00, 0x1d}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, model9020 := range []bool{true, false} {
				length := byte(len(tc.dst)-1)<<4 | byte(len(tc.src)-1)
				m, c := newTest360(t, model9020, []byte{tc.op, length, 0x10, 0x06, 0x20, 0x00})
				c.GR[1], c.GR[2] = 0x2000, 0x3000
				dst := m.S.Mem[0x2006:][:len(tc.dst)]
				copy(dst, tc.dst)
				copy(m.S.Mem[0x3000:], tc.src)
				m.Run(1)
				if code := be.Uint16(m.S.Mem[pswPgmOld+2:]); code != pgmData {
					t.Fatalf("9020=%v: program interruption %04X, want data exception", model9020, code)
				}
				want := tc.dst
				if model9020 {
					want = tc.want
				}
				if !bytes.Equal(dst, want) {
					t.Fatalf("9020=%v: result %X, want %X", model9020, dst, want)
				}
			}
		})
	}
}

func TestModel9020ChannelProtection(t *testing.T) {
	m, _ := newTest360(t, true, nil)
	*m.S.key(0x2000) = 0x00 // key 0: the 9020 lets channels store
	*m.S.key(0x2800) = 0x50
	if !m.CSS.storeKeyed(0, 0x2000, []byte{1}, 3) {
		t.Fatal("store into key-0 storage refused")
	}
	if m.CSS.storeKeyed(0, 0x2800, []byte{1}, 3) {
		t.Fatal("store into key-5 storage with key 3 allowed")
	}
	m370, _ := newTest370(t, nil)
	if m370.CSS.storeKeyed(0, 0x2000, []byte{1}, 3) {
		t.Fatal("System/370 allowed a key-3 store into key-0 storage")
	}
}

func TestModel9020FetchProtectedCCWStatusByChannel(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const caw = 0x30002000
	*m.S.key(0x2000) = 0x58
	ccw0(m, 0x2000, 0x03, 0, 0, 1)
	for _, tc := range []struct {
		dev    uint16
		status byte
	}{
		{0x00c, scsProgramCheck},
		{0x3f0, scsProgramCheck | scsProtection},
	} {
		if _, err := m.CSS.Attach(tc.dev, &Tape3420{}); err != nil {
			t.Fatal(err)
		}
		if cc := ioInstr(c, 0x9c, tc.dev, caw); cc != 1 || m.S.Mem[0x45] != tc.status {
			t.Fatalf("device %03X: cc=%d channel status=%02X", tc.dev, cc, m.S.Mem[0x45])
		}
	}
}

func TestModel9020InterruptionAfterEnablingSSM(t *testing.T) {
	code := []byte{
		0x80, 0x00, 0x0f, 0x00, // SSM X'F00': enable channel 0
		0x41, 0x10, 0x00, 0x01, // LA 1,1
		0x41, 0x20, 0x00, 0x02, // LA 2,2
	}
	for _, tc := range []struct {
		model9020 bool
		ia        uint32
	}{{false, 0x1004}, {true, 0x1008}} {
		m, c := newTest360(t, tc.model9020, code)
		m.S.Mem[0xf00] = 0x80
		if _, err := m.CSS.Attach(0x00e, &UnitRecord{Type: 0x1403}); err != nil {
			t.Fatal(err)
		}
		m.CSS.Unsolicited(0x00e, usDE)
		m.Run(4)
		if old := uint32(be.Uint64(m.S.Mem[pswIOOld:])) & 0xffffff; old != tc.ia {
			t.Fatalf("9020=%v: I/O old PSW address %06X, want %06X", tc.model9020, old, tc.ia)
		}
		_ = c
	}
}

func TestIntervalTimerDisabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disabled bool
	}{
		{name: "enabled"},
		{name: "disabled", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMachine(Config{Memory: 1 << 20, Model9020: true, NoIntervalTimer: tc.disabled})
			c := m.CPUs[0]
			c.loadPSW(0x01000000_00001000)
			if _, ok := c.intervalDeadline(); ok == tc.disabled {
				t.Fatalf("interval deadline present = %v with timer disabled = %v", ok, tc.disabled)
			}
			m.tod += itDen
			wantTimer, wantInterrupt := uint32(0xfffffffd), uint32(extIntervalTimer)
			if tc.disabled {
				wantTimer, wantInterrupt = 0, 0
			}
			if irq := c.pendingExternal(); irq != wantInterrupt {
				t.Fatalf("external interruption = %X, want %X", irq, wantInterrupt)
			}
			if timer := be.Uint32(m.S.Mem[0x50:]); timer != wantTimer {
				t.Fatalf("interval timer = %08X, want %08X", timer, wantTimer)
			}
			if tc.disabled {
				c.extPending |= extInterruptKey
				if irq := c.pendingExternal(); irq != extInterruptKey {
					t.Fatalf("external interruption = %X, want operator interrupt key", irq)
				}
			}
		})
	}
}

func TestModel65AddDecimalInvalidDigit(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Model65: true})
	c := m.CPUs[0]
	code := []byte{0xfa, 0x00, 0x12, 0xe0, 0x14, 0xaf}
	copy(m.S.Mem[0x1000:], code)
	be.PutUint64(m.S.Mem[pswPgmNew:], 0x00020000_0000DEAD)
	c.Stopped = false
	c.loadPSW(0x00000000_00001000)
	c.GR[1] = 0x8000
	m.S.Mem[0x82e0], m.S.Mem[0x84af] = 0x1c, 0xcd
	m.Run(1)
	if got := be.Uint16(m.S.Mem[pswPgmOld+2:]); got != pgmData {
		t.Fatalf("interruption code %04X, want %04X", got, pgmData)
	}
	if got := m.S.Mem[0x82e0]; got != 0xff {
		t.Fatalf("stored byte %02X, want FF", got)
	}
}

func TestModel65MultiplyDecimalInvalidWorkspace(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Model65: true})
	c := m.CPUs[0]
	copy(m.S.Mem[0x1000:], []byte{0xfc, 0x10, 0x12, 0xf1, 0x12, 0xe4})
	be.PutUint64(m.S.Mem[pswPgmNew:], 0x00020000_0000DEAD)
	c.Stopped = false
	c.loadPSW(0x00000000_00001000)
	c.GR[1] = 0x8000
	m.S.Mem[0x82f1], m.S.Mem[0x82f2], m.S.Mem[0x82e4] = 0x22, 0x2c, 0x1c
	m.Run(1)
	if got := be.Uint16(m.S.Mem[pswPgmOld+2:]); got != pgmData {
		t.Fatalf("interruption code %04X, want %04X", got, pgmData)
	}
	if got := be.Uint16(m.S.Mem[0x82f1:]); got != 0x002c {
		t.Fatalf("stored product %04X, want 002C", got)
	}
}

func TestModel50MultiplyDecimalInvalidWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name        string
		address     uint32
		destination []byte
		multiplier  []byte
		want        []byte
	}{
		{"same-word", 0x82f6, []byte{0x23, 0x23, 0x23, 0x2c}, []byte{0x11, 0x1c}, []byte{0x00, 0x25, 0x75, 0x2c}},
		{"two-words", 0x8300, []byte{0x19, 0x19, 0x19, 0x19, 0x19, 0x4d}, []byte{0, 0, 0, 0, 0x3c}, []byte{0x19, 0x19, 0x19, 0x19, 0x01, 0x2d}},
		{"left-word", 0x8300, []byte{0x19, 0, 0, 0, 0, 0x4d}, []byte{0, 0, 0, 0, 0x3c}, []byte{0, 0, 0, 0, 0x01, 0x2d}},
		{"unaligned", 0x8fff, []byte{0x20, 0x00, 0x11, 0x12, 0x32, 0x32, 0x32, 0x3d}, []byte{0x12, 0x34, 0x5c}, []byte{0x20, 0x15, 0x21, 0x30, 0x30, 0x27, 0x43, 0x5d}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMachine(Config{Memory: 128 << 10, Model50: true})
			c := m.CPUs[0]
			lengths := byte((len(tc.destination)-1)<<4 | (len(tc.multiplier) - 1))
			copy(m.S.Mem[0x1000:], []byte{0xfc, lengths, 0x10, 0x00, 0x20, 0x00})
			be.PutUint64(m.S.Mem[pswPgmNew:], 0x00020000_0000DEAD)
			copy(m.S.Mem[tc.address:], tc.destination)
			copy(m.S.Mem[0xabc7:], tc.multiplier)
			c.Stopped = false
			c.loadPSW(0x00000000_00001000)
			c.GR[1], c.GR[2] = tc.address, 0xabc7
			m.Run(1)
			if got := be.Uint16(m.S.Mem[pswPgmOld+2:]); got != pgmData {
				t.Fatalf("interruption code %04X, want %04X", got, pgmData)
			}
			if got := m.S.Mem[tc.address:][:len(tc.want)]; !bytes.Equal(got, tc.want) {
				t.Fatalf("stored product %X, want %X", got, tc.want)
			}
		})
	}
}
