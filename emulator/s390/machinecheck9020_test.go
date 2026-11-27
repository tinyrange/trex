package s390

import (
	"bytes"
	"testing"
)

func TestReplayMachineCheck9020(t *testing.T) {
	for _, element := range []int{0, 1, 2, 3} {
		m, c := newTest360(t, true, nil)
		c.Prefix = bytesPer9020SE
		psa := m.S.Mem[c.Prefix:]
		const maskedWait = 0x00020000_00001000
		const enabledWait = 0x01060000_00001000
		const handlerWait = 0x00020000_00002000
		c.loadPSW(maskedWait)
		be.PutUint64(psa[pswMCNew:], handlerWait)
		start, size := logoutRange9020(uint16(element))
		logout := bytes.Repeat([]byte{0xa5}, size)
		if err := m.ReplayMachineCheck9020(0, element, logout); err != nil {
			t.Fatal(err)
		}
		clear(logout)
		if got := m.Run(1); got.Kind != "disabled-wait" || psa[start] != 0 {
			t.Fatalf("masked check touched low storage or exited wait: %+v", got)
		}
		var checkpoint bytes.Buffer
		if err := m.Save(&checkpoint); err != nil {
			t.Fatal(err)
		}
		c.maintenance9020.machineCheck = machineCheck9020{}
		if err := m.Restore(&checkpoint, false); err != nil {
			t.Fatal(err)
		}
		c.loadPSW(enabledWait)
		c.InterruptKey()
		if got := m.Run(1); got.Kind != "disabled-wait" || c.PSW.Encode() != handlerWait {
			t.Fatalf("machine-check handler did not take priority: %+v %s", got, c.PSW)
		}
		if old := be.Uint64(psa[pswMCOld:]); old != enabledWait|uint64(element)<<32 {
			t.Fatalf("element %d old PSW %016X", element, old)
		}
		if psa[start-1] != 0 || psa[int(start)+size] != 0 ||
			!bytes.Equal(psa[start:int(start)+size], bytes.Repeat([]byte{0xa5}, size)) ||
			m.S.Mem[start] != 0 {
			t.Fatalf("element %d logout did not stay within the prefixed area", element)
		}
		if c.maintenance9020.machineCheck.Pending || c.extPending&extInterruptKey == 0 {
			t.Fatal("machine check must consume itself and preserve the pending external interruption")
		}
	}
}

func Test9020IOCEStorageCheckTargetsIssuingCE(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2, Model9020: true, NoIntervalTimer: true})
	first, issuing := m.CPUs[0], m.CPUs[1]
	const ccw = bytesPer9020SE + 0x100
	// An error in the second word still produces an SE storage check on the
	// first word cycle. The first word carries sound parity to the IOCE.
	if err := m.SetStorageDataParity9020(ccw+7, true); err != nil {
		t.Fatal(err)
	}
	if !m.CSS.checkIOCEFetch9020(issuing, 0x530, ccw, 0) || !m.storageStopped9020(ccw) {
		t.Fatal("the IOCE did not recognize the storage check and stop SE2")
	}
	check := issuing.pendingMachineCheck9020()
	if first.pendingMachineCheck9020() != nil || check == nil || check.Element != 2 ||
		be.Uint32(check.Logout[ioceSERequest9020:]) != 0x40000000 ||
		check.Logout[ioceStorageCheck9020] != 0x14 || be.Uint16(check.Logout[ioceCheck1Offset9020:]) != 0 {
		t.Fatalf("storage check was not routed to its CE with the correct flags: %+v", check)
	}
	if err := m.ReplayMachineCheck9020(1, 0, make([]byte, ceLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	if issuing.pendingMachineCheck9020().Element != 0 {
		t.Fatal("the local CE check must remain independently pending")
	}
	issuing.maintenance9020.machineCheck = machineCheck9020{}
	if issuing.pendingMachineCheck9020() != check {
		t.Fatal("the pending IOCE check was lost")
	}
	const secondCCW = 0x100
	if err := m.SetStorageDataParity9020(secondCCW, true); err != nil {
		t.Fatal(err)
	}
	if !m.CSS.checkIOCEFetch9020(issuing, 0x930, secondCCW, 0) || issuing.pendingMachineCheck9020().Element != 3 {
		t.Fatal("IOCE 3 did not take priority over the earlier IOCE 2 request")
	}
	*issuing.pendingMachineCheck9020() = machineCheck9020{}
	if issuing.pendingMachineCheck9020() != check {
		t.Fatal("delivering the higher-priority check discarded the IOCE 2 request")
	}
}

func Test9020DiagnoseStorageLogout(t *testing.T) {
	// The SDM-style receiving CE runs in SE1. The MCW selects SE2.
	const mcw = 0x00fd0800_20008000
	diag := []byte{0x83, 0, 0x1f, 0xe8} // DIAG 0,FE8(1)
	m, c := newTest360(t, true, append(bytes.Clone(diag), diag...))
	const operand = 0x1fe8 // The result spans two storage-key blocks.
	c.GR[1] = 0x1000
	be.PutUint64(m.S.Mem[operand:], mcw)
	result := m.S.Mem[operand+8 : operand+8+seLogoutSize9020]
	before := []byte{0x70, 0x17, 0xa5}
	for offset := range result {
		result[offset] = before[offset%len(before)]
	}
	untouched := bytes.Clone(result)
	logout := make([]byte, seLogoutSize9020)
	for i := range logout {
		logout[i] = byte(i + 1)
	}
	if err := m.ReplayStorageLogout9020(2, logout); err != nil {
		t.Fatal(err)
	}
	if err := m.ReplayStorageLogout9020(2, make([]byte, len(logout))); err == nil {
		t.Fatal("accepted an overlapping logout for the same element")
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	// A protection exception must leave the entire result and the SE intact.
	c.PSW.Key = 1
	*m.S.key(0x2000) = 0x20
	if stop := m.Run(1); !bytes.Equal(result, untouched) || !m.storageLogout9020[1].Stopped ||
		be.Uint16(m.S.Mem[pswPgmOld+2:]) != pgmProtection {
		t.Fatalf("protected logout changed state: %v, PSW %s, result %x", stop, c.PSW, result)
	}
	m.storageLogout9020[1] = storageLogout9020{}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if stop := m.Run(1); c.PSW.CC != 0 || c.PSW.IA != 0x1004 || !bytes.Equal(result, logout) || m.storageLogout9020[1].Stopped {
		t.Fatalf("DIAG did not store and release SE2: %v, PSW %s, result %x", stop, c.PSW, result)
	}
	copy(result, untouched)
	be.PutUint64(m.S.Mem[operand:], 0x00fd0800_30008000) // SE3 is absent.
	if stop := m.Run(1); c.PSW.CC != 1 || c.PSW.IA != 0x1008 || !bytes.Equal(result, untouched) {
		t.Fatalf("absent SE did not time out: %v, PSW %s, result %x", stop, c.PSW, result)
	}
}

func Test9020DiagnoseLiveStorageLogout(t *testing.T) {
	m, c := newTest360(t, true, []byte{
		0x58, 0x20, 0x10, 0x00, // L 2,0(1), even.
		0x58, 0x30, 0x10, 0x08, // L 3,8(1), odd.
		0x42, 0x40, 0x10, 0x01, // STC 4,1(1), even.
		0x83, 0, 0x02, 0x80, // DIAG X'280'.
		0x58, 0x50, 0x10, 0x00, // L 5,0(1), after release.
	})
	m.cfg.NoIntervalTimer = true
	const operand = bytesPer9020SE + 0x80
	c.GR[1], c.GR[4] = operand, 0x99
	be.PutUint64(m.S.Mem[0x280:], 0x00fd0800_20008000)
	be.PutUint64(m.S.Mem[operand:], 0x01020304_05060708)
	be.PutUint64(m.S.Mem[operand+8:], 0x10203040_50607080)
	*m.S.key(operand) = 0x98
	m.Run(3)
	if c.GR[2] != 0x01020304 || c.GR[3] != 0x10203040 || c.PSW.IA != 0x100c {
		t.Fatalf("live SE2 control loads did not run: GR2=%08X GR3=%08X PSW=%s", c.GR[2], c.GR[3], c.PSW)
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	m.storageLatches9020[1] = [2]storageCycle9020{}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	// Change storage without issuing a CE cycle. The captured doublewords
	// should still contain the last values that the processor saw or stored.
	be.PutUint32(m.S.Mem[operand:], 0xdeadbeef)
	m.Run(1)
	// A27-2734-2 fig. 12-5: marks, tag/SAR, responder, operation, parity.
	want := [...]uint32{
		0x01990304, 0x05060708, 0x40100080, 0x800080fc, 0x00101002, 0x0000026c,
		0x10203040, 0x50607080, 0x00100080, 0x00008000, 0x804c080a, 0x0200002c,
	}
	if c.PSW.CC != 0 || c.PSW.IA != 0x1010 {
		t.Fatalf("live FD0 did not finish with CC0: %s", c.PSW)
	}
	for i, word := range want {
		if got := be.Uint32(m.S.Mem[0x288+4*i:]); got != word {
			t.Errorf("SE2 logword %d = %08X, want %08X", i, got, word)
		}
	}
	m.Run(1)
	if c.GR[5] != 0xdeadbeef || c.PSW.IA != 0x1014 {
		t.Fatalf("SE2 was inaccessible after live FD0: GR5=%08X PSW=%s", c.GR[5], c.PSW)
	}
}

func Test9020LiveStorageLogoutRejectsLocalResult(t *testing.T) {
	m, c := newTest360(t, true, []byte{0x83, 0, 0x10, 0}) // DIAG 0,0(1).
	c.GR[1] = bytesPer9020SE
	be.PutUint64(m.S.Mem[bytesPer9020SE:], 0x00fd0800_20008000)
	result := m.S.Mem[bytesPer9020SE+8 : bytesPer9020SE+56]
	sentinel := bytes.Repeat([]byte{0x5a}, len(result))
	copy(result, sentinel)
	m.Run(1)
	if code := be.Uint16(m.S.Mem[pswPgmOld+2:]); code != pgmSEStopped9020 || !bytes.Equal(result, sentinel) || m.storageLogout9020[1].Stopped {
		t.Fatalf("FD0 with its result in the target SE: code %04X result %x", code, result)
	}
}

func Test9020AStorageParityLogout(t *testing.T) {
	m := NewMachine(Config{Model9020A: true, Memory: 12 * bytesPer9020ASE, MIPS: 1, NoIntervalTimer: true})
	c := m.CPUs[0]
	const operand = 11*bytesPer9020ASE + 0x104
	be.PutUint64(m.S.Mem, 0x00040000_00001000)
	be.PutUint64(m.S.Mem[pswMCNew:], 0x00000000_00001100)
	be.PutUint64(m.S.Mem[pswPgmNew:], 0x00000000_00001140)
	copy(m.S.Mem[0x1000:], []byte{
		0x58, 0x20, 0x60, 0x00, // L 2,0(6), the sound word.
		0x58, 0x30, 0x60, 0x04, // L 3,4(6), the bad word.
	})
	copy(m.S.Mem[0x1100:], []byte{0x58, 0x40, 0x60, 0x00}) // L 4,0(6), while SE12 is stopped.
	copy(m.S.Mem[0x1140:], []byte{0x83, 0, 0x1f, 0x15})    // DIAG kernel F15.
	result := m.S.Mem[0x1144:0x1160]
	copy(result, bytes.Repeat([]byte{0xa5}, seLogoutSize9020A))
	copy(m.S.Mem[0x1160:], []byte{
		0x50, 0x50, 0x60, 0x04, // ST 5,4(6), regenerate sound parity.
		0x58, 0x30, 0x60, 0x04, // L 3,4(6), retry the faulting load.
	})
	be.PutUint32(m.S.Mem[operand-4:], 0x01234567)
	be.PutUint32(m.S.Mem[operand:], 0x20000004)
	if err := m.Restart9020(1); err != nil {
		t.Fatal(err)
	}
	c.GR[1], c.GR[5], c.GR[6] = 0x000c0000, 0x20000004, operand-4
	if err := m.SetStorageDataParity9020(operand+3, true); err != nil {
		t.Fatal(err)
	}
	m.Run(1)
	if c.PSW.IA != 0x1004 || c.GR[2] != 0x01234567 {
		t.Fatalf("parity from the next word affected the sound word: GR2=%08X, PSW=%s", c.GR[2], c.PSW)
	}
	m.Run(1)
	if c.PSW.IA != 0x1100 || c.GR[3] != 0 || !m.storageStopped9020(operand) {
		t.Fatalf("the faulting word did not stop SE12: GR3=%08X, PSW=%s", c.GR[3], c.PSW)
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	m.storage9020A[11] = storageElement9020A{}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	m.Run(1)
	if c.PSW.IA != 0x1140 || be.Uint16(m.S.Mem[pswPgmOld+2:]) != pgmSEStopped9020 || c.GR[4] != 0 {
		t.Fatalf("the restored stop did not inhibit access: GR4=%08X, PSW=%s", c.GR[4], c.PSW)
	}
	m.Run(1)
	if c.PSW.IA != 0x1160 || c.PSW.CC != 0 || m.storageStopped9020(operand) {
		t.Fatalf("F15 did not skip the captured words and release SE12: %s", c.PSW)
	}
	// CBB9A0 fig. 3-25: SDR and parity, byte marks and SAR, CE1
	// priority and CCR, protection and Accept, then the SDR check bit.
	want := [...]uint32{0x10402010, 0x40, 0x80400020, 0x40, 0x404081fc, 0x80400800, 0x00010000}
	for i, word := range want {
		if got := be.Uint32(result[4*i:]); got != word {
			t.Errorf("9020A word %d = %08X, want %08X", i, got, word)
		}
	}
	m.Run(2)
	if c.PSW.IA != 0x1168 || c.GR[3] != 0x20000004 {
		t.Fatalf("the repaired load did not complete: GR3=%08X, PSW=%s", c.GR[3], c.PSW)
	}
}

func Test9020LiveStorageLogoutIOCEPartialStore(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const devno = 0x530 // IOCE 2.
	tape := &Tape3420{blocks: []tapeBlock{{data: []byte("abcdef"), n: 6}}}
	if _, err := m.CSS.Attach(devno, tape); err != nil {
		t.Fatal(err)
	}
	m.CSS.ioceATR[1] = channelATR9020{Mask: 0x2100000000, Active: true}
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	ccw0(m, 0x2000, 0x02, 0x86, 0, 6)
	const even = bytesPer9020SE + 0x80
	copy(m.S.Mem[even:], bytes.Repeat([]byte{0xaa}, 16))
	if cc := ioInstr(c, 0x9c, devno, bytesPer9020SE+0x2000); cc != 0 || !advance(m) {
		t.Fatalf("mapped IOCE read did not complete: CC=%d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00082008_0c000000 {
		t.Fatalf("mapped IOCE read CSW=%016X", csw)
	}
	c.logoutStorage9020(0x280, 0, 2)
	result := m.S.Mem[0x288:0x2b8]
	if even, odd := be.Uint64(result), be.Uint64(result[24:]); even != 0xaaaaaaaaaaaa6162 || odd != 0x63646566aaaaaaaa {
		t.Fatalf("partial stores did not retain the unmarked bytes: even=%016X odd=%016X", even, odd)
	}
	if even, odd := be.Uint64(result[8:]), be.Uint64(result[32:]); even != 0x03100080_820002fc || odd != 0xf0100080_00000200 {
		t.Fatalf("wrong byte marks or IOCE 2 response: even=%016X odd=%016X", even, odd)
	}
}

func Test9020StoppedStorageAccess(t *testing.T) {
	m, c := newTest360(t, true, []byte{0x58, 0x20, 0x10, 0x00}) // L 2,0(1)
	m.cfg.NoIntervalTimer = true
	c.GR[1], c.GR[2], c.GR[3], c.GR[4] = bytesPer9020SE, 0xdeadbeef, 0x1200, 0x1000
	be.PutUint32(m.S.Mem[bytesPer9020SE:], 0x01234567)
	be.PutUint64(m.S.Mem[pswPgmNew:], 0x00000000_00001100)
	be.PutUint64(m.S.Mem[0x1200:], 0x00fd0800_20008000)
	copy(m.S.Mem[0x1100:], []byte{
		0x83, 0x00, 0x30, 0x00, // DIAG 0,0(3)
		0x07, 0xf4, // BR 4
	})
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	m.Run(1)
	if c.GR[2] != 0x01234567 || c.PSW.IA != 0x1004 {
		t.Fatalf("load from running SE2 failed: GR2=%08X PSW=%s", c.GR[2], c.PSW)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	logout := bytes.Repeat([]byte{0xa9}, seLogoutSize9020)
	if err := m.ReplayStorageLogout9020(2, logout); err != nil {
		t.Fatal(err)
	}
	m.Run(1)
	if old := be.Uint64(m.S.Mem[pswPgmOld:]); old != 0x00000080_80001004 || c.GR[2] != 0xdeadbeef || c.PSW.IA != 0x1100 || c.Prefix != 0 {
		t.Fatalf("stopped load did not interrupt into SE1: old=%016X GR2=%08X PSW=%s prefix=%08X", old, c.GR[2], c.PSW, c.Prefix)
	}
	m.Run(3)
	if c.GR[2] != 0x01234567 || c.PSW.IA != 0x1004 || !bytes.Equal(m.S.Mem[0x1208:0x1238], logout) {
		t.Fatalf("load did not succeed after FD0: GR2=%08X PSW=%s", c.GR[2], c.PSW)
	}
}

func Test9020StoppedPSA(t *testing.T) {
	m := NewMachine(Config{Model9020: true, Memory: 3 * bytesPer9020SE, NoIntervalTimer: true})
	c := m.CPUs[0]
	c.maintenance9020.atr, c.maintenance9020.atrSet = 0x2103000000, true
	const offset = 0x3000
	const alternate = 2*bytesPer9020SE + offset
	c.setPSBase9020(bytesPer9020SE+offset, offset, false)
	c.loadPSW(0x00000000_00001000)
	c.Stopped = false
	c.GR[2] = 0xdeadbeef
	load := []byte{0x58, 0x20, 0x01, 0x00} // L 2,X'100', a prefixed operand.
	copy(m.S.Mem[bytesPer9020SE+0x1000:], load)
	copy(m.S.Mem[bytesPer9020SE+0x1100:], load)
	be.PutUint64(m.S.Mem[alternate+pswPgmNew:], 0x00000000_00001100)
	if err := m.ReplayStorageLogout9020(1, make([]byte, seLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	m.Run(1)
	if old := be.Uint64(m.S.Mem[alternate+pswPgmOld:]); old != 0x00000080_80001004 ||
		be.Uint64(m.S.Mem[offset+pswPgmOld:]) != 0 || c.GR[2] != 0xdeadbeef || c.PSW.IA != 0x1100 ||
		c.Prefix != alternate || c.maintenance9020.psb != 3*bytesPer9020SE+offset {
		t.Fatalf("program interruption did not select logical slot 3 / SE3 at the same offset: old=%016X PSW=%s prefix=%08X", old, c.PSW, c.Prefix)
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	c.maintenance9020.psbAlternate = false
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if err := m.ReplayStorageLogout9020(3, make([]byte, seLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	if stop := m.Run(8); stop.Kind != "check-stop" || c.maintenance9020.checks&(1<<(31-22)) == 0 || c.Prefix != alternate ||
		be.Uint64(m.S.Mem[alternate+pswPgmOld:]) != 0x00000080_80001004 {
		t.Fatalf("stopped alternate PSA did not check-stop: %v, prefix=%08X", stop, c.Prefix)
	}
}

func Test9020StorageDataCheckUsesAlternatePSA(t *testing.T) {
	m, c := newTest360(t, true, []byte{0x58, 0x20, 0x01, 0x80}) // L 2,X'180'.
	c.PSW.MC = true
	c.GR[2] = 0xdeadbeef
	be.PutUint64(m.S.Mem[0x180:], 0x01234567_89abcdef)
	be.PutUint64(m.S.Mem[bytesPer9020SE+pswMCNew:], 0x00000000_00081100)
	if err := m.SetStorageDataParity9020(0x180, true); err != nil {
		t.Fatal(err)
	}
	m.Run(1)
	alternate := m.S.Mem[bytesPer9020SE:]
	if old := be.Uint64(alternate[pswMCOld:]); old != 0x00040000_00001004 ||
		be.Uint16(alternate[168:]) != 0x100a || c.Prefix != bytesPer9020SE ||
		c.PSW.IA != 0x81100 || c.GR[2] != 0xdeadbeef ||
		be.Uint64(m.S.Mem[pswMCOld:]) != 0 || !m.storageStopped9020(0x180) {
		t.Fatalf("data check did not log out into the alternate PSA: old=%016X flags=%04X PSW=%s prefix=%08X",
			old, be.Uint16(alternate[168:]), c.PSW, c.Prefix)
	}
	want := uint32(seDataParityCheck9020 | 0x280)
	if got := be.Uint32(m.storageLogout9020[0].Logout[20:]); got != want {
		t.Fatalf("SE1 parity logword: got %08X want %08X", got, want)
	}
}

func Test9020IOCEPSALockout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		devno      uint16
		code       uint16
		pending    bool
		wantOldPSW uint64
	}{
		{"CAW-fetch", 0x401, 0x20, false, 0x00000020_b0081004},
		{"CSW-store", 0x801, 0x10, true, 0x02000010_00081000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := newTest360(t, true, nil)
			m.cfg.NoIntervalTimer = true
			const alternate = bytesPer9020SE
			be.PutUint32(m.S.Mem[alternate+0x1000:], 0x9c000000|uint32(tc.devno))
			c.loadPSW(0x00000000_00081000)
			tape := &Tape3420{blocks: []tapeBlock{{data: []byte("ABC"), n: 3}}}
			if _, err := m.CSS.Attach(tc.devno, tape); err != nil {
				t.Fatal(err)
			}
			be.PutUint32(m.S.Mem[0x48:], 0x2000)
			ccw0(m, 0x2000, 0x02, 0x2100, 0, 3)
			be.PutUint64(m.S.Mem[alternate+pswPgmNew:], 0x00020000_00001100)
			be.PutUint32(m.S.Mem[alternate+0x90:], 0xdeadbeef) // Byte address 90 is ordinary storage in this model.
			if err := m.ReplayStorageLogout9020(1, make([]byte, seLogoutSize9020)); err != nil {
				t.Fatal(err)
			}
			if tc.pending {
				c.loadPSW(0x02000000_00081000)
				m.CSS.Unsolicited(tc.devno, usDE)
			}
			m.BreakProgram = map[uint16]bool{tc.code: true}
			stop := m.Run(8)
			if old := be.Uint64(m.S.Mem[alternate+pswPgmOld:]); stop.Kind != "program" || c.PSW.IA != 0x1100 || old != tc.wantOldPSW ||
				be.Uint64(m.S.Mem[pswPgmOld:]) != 0 || be.Uint64(m.S.Mem[alternate+pswIOOld:]) != 0 ||
				be.Uint64(m.S.Mem[0x40:]) != 0 || be.Uint64(m.S.Mem[alternate+0x40:]) != 0 ||
				be.Uint32(m.S.Mem[alternate+0x90:]) != 0xdeadbeef {
				t.Fatalf("IOCE lockout did not deliver the expected program PSW in SE2: %v, PSW=%s old=%016X", stop, c.PSW, old)
			}
			x := m.CSS.bydev[tc.devno]
			if x.ccws != 0 || x.working() || x.irq || x.pending || tape.pos != 0 {
				t.Fatal("CAW setup or the lost CSW interruption left the device active")
			}
		})
	}
}

func Test9020StoppedPSAIntervalTimer(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const alternate = bytesPer9020SE
	c.loadPSW(0x00020000_00001000) // Wait with external interruptions masked.
	be.PutUint32(m.S.Mem[0x50:], 100)
	be.PutUint32(m.S.Mem[alternate+0x50:], 200)
	be.PutUint64(m.S.Mem[alternate+pswPgmNew:], 0x00020000_00001100)
	if err := m.ReplayStorageLogout9020(1, make([]byte, seLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	m.BreakProgram = map[uint16]bool{pgmSEStopped9020: true}
	stop := m.Run(10000)
	if old := be.Uint64(m.S.Mem[alternate+pswPgmOld:]); stop.Kind != "program" || old != 0x00020080_00001000 || c.Prefix != alternate ||
		be.Uint32(m.S.Mem[0x50:]) != 100 || be.Uint32(m.S.Mem[alternate+0x50:]) != 200 {
		t.Fatalf("timer cycle did not interrupt into SE2: %v, old=%016X, prefix=%08X", stop, old, c.Prefix)
	}
}
