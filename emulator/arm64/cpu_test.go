package arm64

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestSIMDMemoryFillAndScalarTransfer(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[1] = 0xa5
	c.x[10] = 0x2000
	step(t, c, m, 0x4e010c20)
	step(t, c, m, 0x4ea01c01)
	step(t, c, m, 0x4c9fa140)
	var data [32]byte
	if err := m.ReadMemory(0x2000, data[:], cpu.Read); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:], bytes.Repeat([]byte{0xa5}, 32)) || c.x[10] != 0x2020 {
		t.Fatalf("fill=%x address=%x", data, c.x[10])
	}
	step(t, c, m, 0x9e660001)
	if c.x[1] != 0xa5a5a5a5a5a5a5a5 {
		t.Fatalf("FMOV=%x", c.x[1])
	}
}

func TestStructureStoreLanesAndAcquireRelease(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[10] = 0x2000
	for j := 0; j < 4; j++ {
		c.q[j][0] = byte(0xa0 + j)
		c.q[j][15] = byte(0xb0 + j)
	}
	step(t, c, m, 0x0d002140) // ST3 byte lane 0
	step(t, c, m, 0x4dbf3d40) // ST4 byte lane 15, post increment 4
	var data [4]byte
	if err := m.ReadMemory(0x2000, data[:], cpu.Read); err != nil {
		t.Fatal(err)
	}
	if data != [4]byte{0xb0, 0xb1, 0xb2, 0xb3} || c.x[10] != 0x2004 {
		t.Fatalf("lanes=%x base=%x", data, c.x[10])
	}
	c.x[22] = 0x2000
	c.x[8] = 0x1234
	step(t, c, m, 0x089ffec8) // STLRB W8,[X22]
	step(t, c, m, 0x08dffec9) // LDARB W9,[X22]
	if c.x[9] != 0x34 {
		t.Fatalf("acquire=%x", c.x[9])
	}
}

func TestSIMDWidenAndReduceByteChecksum(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.q[16] = [16]byte{255, 255, 255, 255}
	step(t, c, m, 0x4f000410) // MOVI V16.4S,#0
	c.q[17] = [16]byte{1, 128, 254, 255}
	step(t, c, m, 0x2f08a631) // UXTL V17.8H,V17.8B
	step(t, c, m, 0x2e711210) // UADDW V16.4S,V16.4S,V17.4H
	step(t, c, m, 0x4eb1ba10) // ADDV S16,V16.4S
	step(t, c, m, 0x1e26020b) // FMOV W11,S16
	if c.x[11] != 638 {
		t.Fatalf("checksum=%d", c.x[11])
	}
}

func TestVectorBitInsert(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	for j := 0; j < 16; j++ {
		c.q[0][j] = 0xf0
		c.q[1][j] = 0xa5
		c.q[2][j] = 0x3c
	}
	step(t, c, m, 0x6ea01c22) // BIT V2.16B,V1.16B,V0.16B
	if !bytes.Equal(c.q[2][:], bytes.Repeat([]byte{0xac}, 16)) {
		t.Fatalf("BIT=%x", c.q[2])
	}
	c.q[16][0], c.q[16][1] = 0xfe, 0x80
	step(t, c, m, 0x0e023e08) // UMOV W8,V16.H[0]
	if c.x[8] != 0x80fe {
		t.Fatalf("UMOV=%x", c.x[8])
	}
}

func TestInterleavedDoublewordStructureStore(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[0] = 0x2000
	for j := 0; j < 16; j++ {
		c.q[0][j] = byte(j)
		c.q[1][j] = byte(0x80 + j)
	}
	step(t, c, m, 0x4c008c00) // ST2 {V0.2D,V1.2D},[X0]
	var got [32]byte
	if err := m.ReadMemory(0x2000, got[:], cpu.Read); err != nil {
		t.Fatal(err)
	}
	want := append(append(append(append([]byte{}, c.q[0][:8]...), c.q[1][:8]...), c.q[0][8:]...), c.q[1][8:]...)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("interleaving=%x want=%x", got, want)
	}
}

func TestVectorComparisonAndPairwiseReduction(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.q[5] = [16]byte{0, 127, 128, 255}
	c.q[1] = [16]byte{0, 128, 127, 255}
	step(t, c, m, 0x6e213ca3) // CMHS V3.16B,V5.16B,V1.16B
	if c.q[3][0] != 255 || c.q[3][1] != 0 || c.q[3][2] != 255 || c.q[3][3] != 255 {
		t.Fatalf("CMHS=%x", c.q[3])
	}
	c.q[17] = [16]byte{1, 250, 128, 127}
	step(t, c, m, 0x6e31a631) // UMAXP V17.16B,V17.16B,V17.16B
	if c.q[17][0] != 250 || c.q[17][1] != 128 || c.q[17][8] != 250 {
		t.Fatalf("UMAXP=%x", c.q[17])
	}
	c.q[17] = [16]byte{250, 10, 1, 2}
	c.q[18] = [16]byte{100, 100, 200, 100}
	step(t, c, m, 0x4e32be31) // ADDP V17.16B,V17.16B,V18.16B
	if c.q[17][0] != 4 || c.q[17][1] != 3 || c.q[17][8] != 200 || c.q[17][9] != 44 {
		t.Fatalf("ADDP=%x", c.q[17])
	}
	c.q[16] = [16]byte{0, 0, 0, 0x80, 0xff, 0xff, 0xff, 0x7f}
	step(t, c, m, 0x4ea0aa13) // CMLT V19.4S,V16.4S,#0
	if binary.LittleEndian.Uint32(c.q[19][:4]) != 0xffffffff || binary.LittleEndian.Uint32(c.q[19][4:8]) != 0 {
		t.Fatalf("CMLT=%x", c.q[19])
	}
}

func TestExclusiveStoreAndInvalidation(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[0] = 0x2000
	step(t, c, m, 0x885f7c02) // LDXR W2,[X0]
	c.x[2] = 42
	step(t, c, m, 0x88017c02) // STXR W1,W2,[X0]
	if c.x[1] != 0 {
		t.Fatal("exclusive store failed")
	}
	var data [4]byte
	m.ReadMemory(0x2000, data[:], cpu.Read)
	if binary.LittleEndian.Uint32(data[:]) != 42 {
		t.Fatal("exclusive store missing")
	}
	step(t, c, m, 0x885f7c02)
	c.InvalidateExclusive(0x2000, 4)
	c.x[2] = 99
	step(t, c, m, 0x88017c02)
	if c.x[1] != 1 {
		t.Fatal("invalidated reservation succeeded")
	}
	m.ReadMemory(0x2000, data[:], cpu.Read)
	if binary.LittleEndian.Uint32(data[:]) != 42 {
		t.Fatal("failed exclusive store changed memory")
	}
}
func TestConditionalCompareAndWideningProducts(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.nzcv = 1 << 30
	c.x[0] = 123
	step(t, c, m, 0xfa401804)
	if c.nzcv != 1<<30 {
		t.Fatal("false CCMP condition did not select immediate flags")
	}
	c.nzcv = 0
	c.x[0] = 0
	step(t, c, m, 0xfa401804)
	if c.nzcv != 0x60000000 {
		t.Fatalf("CCMP flags=%x", c.nzcv)
	}
	c.x[8] = ^uint64(0)
	c.x[9] = 2
	step(t, c, m, 0x9b497d09)
	if c.x[9] != ^uint64(0) {
		t.Fatalf("SMULH=%x", c.x[9])
	}
	c.x[8] = 2
	c.x[9] = 0xffffffff
	step(t, c, m, 0x9ba87d28)
	if c.x[8] != 0x1fffffffe {
		t.Fatalf("UMULL=%x", c.x[8])
	}
}

func TestEXTR32IgnoresUpperHalvesOfSourceRegisters(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[1] = 0xaaaaaaaa12345678
	step(t, c, m, 0x13813020) // EXTR W0,W1,W1,#12 (ROR W0,W1,#12)
	if c.x[0] != 0x67812345 {
		t.Fatalf("EXTR W consumed upper X bits: %#x", c.x[0])
	}
}

func TestReverseBytes(t *testing.T) {
	for _, tc := range []struct {
		instruction uint32
		want        uint64
	}{
		{0x5ac00820, 0x67452301},         // REV W0, W1
		{0xdac00c20, 0x67452301efcdab89}, // REV X0, X1
		{0xdac00820, 0xefcdab8967452301}, // REV32 X0, X1
		{0xdac00420, 0xab89efcd23016745}, // REV16 X0, X1
	} {
		m := memory(t)
		c := &CPU{}
		c.x[1] = 0x89abcdef01234567
		step(t, c, m, tc.instruction)
		if c.x[0] != tc.want {
			t.Fatalf("%08x: got %#x want %#x", tc.instruction, c.x[0], tc.want)
		}
	}
}

func step(t *testing.T, c *CPU, m *cpu.AddressSpace, word uint32) cpu.Effect {
	t.Helper()
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	if err := m.WriteMemory(0x1000, code[:]); err != nil {
		t.Fatal(err)
	}
	c.SetPC(0x1000)
	e, err := c.Step(m)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func memory(t *testing.T) *cpu.AddressSpace {
	t.Helper()
	m := cpu.NewAddressSpace(8192)
	if err := m.Map(0x1000, make([]byte, 8192), cpu.Read|cpu.Write|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestArithmeticFlagsAndZeroRegister(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[0] = 0xffffffff
	step(t, c, m, 0x31000401) // ADDS W1,W0,#1
	if c.x[1] != 0 || c.nzcv != 0x60000000 {
		t.Fatalf("sum=%x flags=%x", c.x[1], c.nzcv)
	}
	c.x[0] = 0x7fffffff
	step(t, c, m, 0x31000401)
	if c.x[1] != 0x80000000 || c.nzcv != 0x90000000 {
		t.Fatalf("overflow sum=%x flags=%x", c.x[1], c.nzcv)
	}
	c.sp = 0x2000
	step(t, c, m, 0xd10083ff) // SUB SP,SP,#32
	if c.sp != 0x1fe0 {
		t.Fatalf("SP=%x", c.sp)
	}
	step(t, c, m, 0xeb00001f) // CMP X0,X0; must not write SP
	if c.sp != 0x1fe0 || c.nzcv != 0x60000000 {
		t.Fatalf("SP=%x flags=%x", c.sp, c.nzcv)
	}
}
func TestCallReturnAndCheckpoint(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[0] = 0x1800
	if step(t, c, m, 0xd63f0000) != cpu.Call || c.pc != 0x1800 || c.x[30] != 0x1004 {
		t.Fatal(c)
	}
	saved := c.Clone()
	c.x[30] = 0x1900
	step(t, c, m, 0xd65f03c0)
	if c.pc != 0x1900 {
		t.Fatal(c)
	}
	v, _ := saved.Register("lr")
	if v != 0x1004 {
		t.Fatalf("aliased checkpoint: %x", v)
	}
}
func TestPairWritebackAndMemoryFault(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.sp = 0x2800
	c.x[29] = 0x1122334455667788
	c.x[30] = 0xaabbccddeeff0011
	step(t, c, m, 0xa9bf7bfd) // STP X29,X30,[SP,#-16]!
	if c.sp != 0x27f0 {
		t.Fatal(c.sp)
	}
	c.x[29] = 0
	c.x[30] = 0
	step(t, c, m, 0xa8c17bfd) // LDP X29,X30,[SP],#16
	if c.sp != 0x2800 || c.x[29] != 0x1122334455667788 || c.x[30] != 0xaabbccddeeff0011 {
		t.Fatal(c)
	}
	c.sp = 0x1008
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], 0xa9bf7bfd)
	m.WriteMemory(0x1000, code[:])
	c.pc = 0x1000
	if _, err := c.Step(m); err == nil {
		t.Fatal("expected unmapped pair fault")
	}
	if c.pc != 0x1000 || c.sp != 0x1008 {
		t.Fatal("fault changed PC/SP")
	}
}
func TestBitfieldAndLogicalImmediate(t *testing.T) {
	m := memory(t)
	c := &CPU{}
	c.x[1] = 0xfedcba9876543210
	step(t, c, m, 0xd3483c20) // UBFX X0,X1,#8,#8
	if c.x[0] != 0x32 {
		t.Fatalf("extract=%x", c.x[0])
	}
	step(t, c, m, 0x92401c20) // AND X0,X1,#0xff
	if c.x[0] != 0x10 {
		t.Fatalf("mask=%x", c.x[0])
	}
}
