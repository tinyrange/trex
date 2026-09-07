package amd64

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestEnterLeave(t *testing.T) {
	for _, width := range []int{8, 2} {
		for _, level := range []int{0, 1, 3, 31, 32, 255} {
			t.Run(fmt.Sprintf("width%d/level%d", width, level), func(t *testing.T) {
				prefix := ""
				if width == 2 {
					prefix = "66 "
				}
				c, m := codeMemory(t, fmt.Sprintf("%sc8 21 00 %02x %sc9", prefix, level, prefix))
				const base = 0x600000000
				const sp = base + 512
				const bp = base + 1024
				if err := m.Map(base, bytes.Repeat([]byte{0xaa}, 2048), cpu.Read|cpu.Write); err != nil {
					t.Fatal(err)
				}
				c.registers[4], c.registers[5] = sp, bp
				c.flags = flagCarry | flagDirection | flagZero
				flags := c.flags
				for i := 1; i < 31; i++ {
					if err := writeWord(m, bp-uint64(i*width), width, uint64(0x100+i)); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := c.Step(m); err != nil {
					t.Fatal(err)
				}
				frame := uint64(sp - width)
				pushes := 1
				if level&31 != 0 {
					pushes += level & 31
				}
				if c.registers[4] != sp-uint64(pushes*width)-33 || c.registers[5] != frame || c.flags != flags {
					t.Fatalf("ENTER state: %#v", c)
				}
				check := func(address, want uint64) {
					t.Helper()
					got, err := readWord(m, address, width)
					if err != nil || got != want&mask(width) {
						t.Fatalf("[%#x] = %#x, want %#x: %v", address, got, want&mask(width), err)
					}
				}
				check(frame, bp)
				for i := 1; i < level&31; i++ {
					check(frame-uint64(i*width), uint64(0x100+i))
				}
				if level&31 != 0 {
					check(frame-uint64((level&31)*width), frame)
				}
				check(c.registers[4], 0xaaaaaaaaaaaaaaaa)
				if _, err := c.Step(m); err != nil {
					t.Fatal(err)
				}
				if c.registers[4] != sp || c.registers[5] != bp || c.flags != flags {
					t.Fatalf("LEAVE state: %#v", c)
				}
			})
		}
	}
}

func TestEnterLeaveFaults(t *testing.T) {
	for _, code := range []string{"c8 00 00 00", "c8 ff ff 00", "c8 00 00 02", "c9", "66 c9"} {
		t.Run(code, func(t *testing.T) {
			c, m := codeMemory(t, code)
			if err := m.Map(0x600000000, make([]byte, 16), cpu.Read|cpu.Write); err != nil {
				t.Fatal(err)
			}
			c.registers[4] = 0x600000010
			if code == "c8 00 00 00" {
				c.registers[4] = 0x600000000
			}
			c.registers[5] = 0x700000000
			before := *c
			if _, err := c.Step(m); err == nil {
				t.Fatal("expected stack fault")
			}
			if *c != before {
				t.Fatal("fault changed CPU registers")
			}
		})
	}
}

func TestEnterChecksFinalStackWritePermission(t *testing.T) {
	c, m := codeMemory(t, "c8 10 00 00")
	const base = 0x600000000
	if err := m.Map(base, bytes.Repeat([]byte{0xaa}, 32), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Protect(base, 16, cpu.Read); err != nil {
		t.Fatal(err)
	}
	c.registers[4], c.registers[5] = base+32, base+24
	before := *c
	if _, err := c.Step(m); err == nil || *c != before {
		t.Fatal("ENTER accepted read-only locals or changed faulting registers")
	}
	var locals [16]byte
	if err := m.ReadMemory(base, locals[:], cpu.Read); err != nil || !bytes.Equal(locals[:], bytes.Repeat([]byte{0xaa}, 16)) {
		t.Fatalf("ENTER wrote locals: %x, %v", locals, err)
	}
}

func TestMXCSRStateAndFaults(t *testing.T) {
	c, memory := codeMemory(t, "0f ae 18 0f ae 10")
	const address = 0x600000000
	if err := memory.Map(address, bytes.Repeat([]byte{0xaa}, 8), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	c.registers[0] = address
	if _, err := c.Step(memory); err != nil {
		t.Fatal(err)
	}
	value, err := readWord(memory, address, 8)
	if err != nil || value != 0xaaaaaaaa00001f80 {
		t.Fatalf("stored MXCSR and guard = %#x, error %v", value, err)
	}
	if err := writeWord(memory, address, 4, 0x5f80); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Step(memory); err != nil {
		t.Fatal(err)
	}
	if value, _ := c.Register("mxcsr"); value != 0x5f80 {
		t.Fatalf("loaded MXCSR = %#x", value)
	}
	clone := c.Clone()
	if err := c.SetRegister("mxcsr", 0); err != nil {
		t.Fatal(err)
	}
	if value, _ := clone.Register("mxcsr"); value != 0x5f80 || c.readMXCSR() != 0 {
		t.Fatal("MXCSR clone aliased state or zero reset incorrectly")
	}
	if err := c.SetRegister("mxcsr", 1<<32); err == nil {
		t.Fatal("accepted reserved MXCSR bits")
	}
	c.SetPC(0x180001003)
	if err := writeWord(memory, address, 4, 1<<16); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Step(memory); err == nil || c.PC() != 0x180001003 || c.readMXCSR() != 0 {
		t.Fatal("invalid LDMXCSR did not fault atomically")
	}
	c.SetPC(0x180001000)
	c.registers[0] = address + 8
	if _, err := c.Step(memory); err == nil || c.PC() != 0x180001000 || c.readMXCSR() != 0 {
		t.Fatal("unmapped STMXCSR did not fault atomically")
	}
}

func TestPushFlagsWidthsAndFault(t *testing.T) {
	for _, test := range []struct {
		code  string
		width int
	}{{"9c", 8}, {"66 9c", 2}} {
		c, memory := codeMemory(t, test.code)
		const stack = 0x600000000
		if err := memory.Map(stack, bytes.Repeat([]byte{0xaa}, 16), cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		c.registers[4] = stack + 16
		c.flags = flagCarry | flagZero | flagDirection | (1 << 16) | (1 << 17)
		original := c.flags
		if _, err := c.Step(memory); err != nil {
			t.Fatal(err)
		}
		if c.registers[4] != stack+16-uint64(test.width) || c.flags != original {
			t.Fatal("PUSHF changed live flags or used the wrong stack width")
		}
		value, err := readWord(memory, c.registers[4], test.width)
		if err != nil || value != flagCarry|flagZero|flagDirection|2 {
			t.Fatalf("saved flags = %#x, error %v", value, err)
		}
		guard, err := readWord(memory, stack, 8)
		if err != nil || guard != 0xaaaaaaaaaaaaaaaa {
			t.Fatalf("stack guard = %#x, error %v", guard, err)
		}
		c.SetPC(0x180001000)
		c.registers[4] = stack
		pc := c.PC()
		if _, err := c.Step(memory); err == nil {
			t.Fatal("expected unmapped stack fault")
		}
		if c.PC() != pc || c.registers[4] != stack || c.flags != original {
			t.Fatal("faulting PUSHF changed CPU state")
		}
	}
}

func TestPopFlagsWidthsAndFault(t *testing.T) {
	for _, test := range []struct {
		code  string
		width int
	}{{"9d", 8}, {"66 9d", 2}} {
		for _, iopl := range []uint64{0, 3} {
			c, m := codeMemory(t, test.code)
			const stack = 0x600000000
			if err := m.Map(stack, bytes.Repeat([]byte{0xff}, test.width), cpu.Read); err != nil {
				t.Fatal(err)
			}
			c.registers[4] = stack
			c.flags = iopl<<12 | 1<<16 | 1<<19 | 1<<20
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			want := uint64(1<<0|1<<2|1<<4|1<<6|1<<7|1<<8|1<<10|1<<11|1<<14|1<<19|1<<20) | iopl<<12
			if test.width == 8 {
				want |= 1<<18 | 1<<21
			}
			if iopl == 3 {
				want |= 1 << 9
			}
			if c.flags != want || c.registers[4] != stack+uint64(test.width) {
				t.Fatalf("POPF width%d flags=%#x want%#x", test.width, c.flags, want)
			}
			c.SetPC(0x180001000)
			before := *c
			if _, err := c.Step(m); err == nil || *c != before {
				t.Fatal("faulting POPF changed CPU state")
			}
		}
	}
}

func codeMemory(t *testing.T, text string) (*CPU, *cpu.AddressSpace) {
	t.Helper()
	code, err := hex.DecodeString(strings.ReplaceAll(text, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	memory := cpu.NewAddressSpace(1 << 20)
	const base = 0x180001000
	if err := memory.Map(base, code, cpu.Read|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	c := &CPU{}
	c.SetPC(base)
	return c, memory
}

func runCode(t *testing.T, c *CPU, memory cpu.Memory, limit int) {
	t.Helper()
	for i := 0; i < limit; i++ {
		effect, err := c.Step(memory)
		if err != nil {
			t.Fatal(err)
		}
		if effect == cpu.Halt {
			return
		}
	}
	t.Fatalf("did not halt within %d instructions", limit)
}

func requireRegister(t *testing.T, c *CPU, name string, want uint64) {
	t.Helper()
	got, err := c.Register(name)
	if err != nil || got != want {
		t.Fatalf("%s = %#x, %v; want %#x", name, got, err, want)
	}
}

func TestRegisterAliases(t *testing.T) {
	c := &CPU{}
	for _, group := range [][4]string{
		{"rax", "eax", "ax", "al"}, {"rcx", "ecx", "cx", "cl"}, {"rdx", "edx", "dx", "dl"}, {"rbx", "ebx", "bx", "bl"},
		{"rsp", "esp", "sp", "spl"}, {"rbp", "ebp", "bp", "bpl"}, {"rsi", "esi", "si", "sil"}, {"rdi", "edi", "di", "dil"},
		{"r8", "r8d", "r8w", "r8b"}, {"r9", "r9d", "r9w", "r9b"}, {"r15", "r15d", "r15w", "r15b"},
	} {
		if err := c.SetRegister(group[0], math.MaxUint64); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister(group[3], 0x12); err != nil {
			t.Fatal(err)
		}
		requireRegister(t, c, group[0], 0xffffffffffffff12)
		if err := c.SetRegister(group[2], 0x3456); err != nil {
			t.Fatal(err)
		}
		requireRegister(t, c, group[0], 0xffffffffffff3456)
		if err := c.SetRegister(group[1], 0x789abcde); err != nil {
			t.Fatal(err)
		}
		requireRegister(t, c, group[0], 0x789abcde)
	}
	if err := c.SetRegister("rax", math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("ah", 0x12); err != nil {
		t.Fatal(err)
	}
	requireRegister(t, c, "rax", 0xffffffffffff12ff)
	if err := c.SetRegister("bogus", 1); err == nil {
		t.Fatal("unknown register accepted")
	}
}

func TestRepeatedStoresAreBoundedAndResumeAfterFault(t *testing.T) {
	c, m := codeMemory(t, "f3aa f4") // rep stosb; hlt
	const destination = 0x200000000
	if err := m.Map(destination, []byte{0, 0}, cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	c.SetRegister("rdi", destination)
	c.SetRegister("rcx", 3)
	c.SetRegister("rax", 0x1234)
	c.flags = flagCarry | flagZero
	start := c.PC()
	for range 2 {
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		if c.PC() != start || c.flags != flagCarry|flagZero {
			t.Fatal("repeat advanced RIP or changed flags")
		}
	}
	if _, err := c.Step(m); err == nil {
		t.Fatal("store across unmapped boundary succeeded")
	}
	requireRegister(t, c, "rcx", 1)
	requireRegister(t, c, "rdi", destination+2)
	if err := m.Map(destination+2, []byte{0}, cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 2)
	var got [3]byte
	if err := m.ReadMemory(destination, got[:], cpu.Read); err != nil || got != [3]byte{0x34, 0x34, 0x34} {
		t.Fatalf("stored bytes = %x, %v", got, err)
	}
	requireRegister(t, c, "rcx", 0)
	requireRegister(t, c, "rdi", destination+3)

	c, m = codeMemory(t, "f3 48ab f4") // rep stosq; hlt, backwards
	if err := m.Map(destination, make([]byte, 16), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	c.SetRegister("rdi", destination+8)
	c.SetRegister("rcx", 2)
	c.SetRegister("rax", 0x1122334455667788)
	c.flags = flagDirection
	runCode(t, c, m, 3)
	var words [16]byte
	if err := m.ReadMemory(destination, words[:], cpu.Read); err != nil || !bytes.Equal(words[:8], []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}) || !bytes.Equal(words[:8], words[8:]) {
		t.Fatalf("stored words = %x, %v", words, err)
	}
	requireRegister(t, c, "rdi", destination-8)
}

func TestExecuteRegisterWidths(t *testing.T) {
	// mov rax,-1; mov ax,1234h; mov ah,56h; mov r8,rax;
	// mov eax,89abcdefh; mov r9,rax; hlt
	c, m := codeMemory(t, "48b8ffffffffffffffff 66b83412 b456 4989c0 b8efcdab89 4989c1 f4")
	runCode(t, c, m, 8)
	requireRegister(t, c, "r8", 0xffffffffffff5634)
	requireRegister(t, c, "r9", 0x89abcdef)
}

func TestRIPRelativeAndSegmentAddressing(t *testing.T) {
	// lea rax,[rip+9]; mov rcx,[rax]; mov rdx,[rip+1]; hlt; qword
	c, m := codeMemory(t, "488d050b000000 488b08 488b1501000000 f4 8877665544332211")
	runCode(t, c, m, 5)
	requireRegister(t, c, "rax", 0x180001012)
	requireRegister(t, c, "rcx", 0x1122334455667788)
	requireRegister(t, c, "rdx", 0x1122334455667788)
	c, m = codeMemory(t, "65488b042530000000 f4") // mov rax,gs:[30h]
	if err := m.Map(0x200000030, []byte{8, 7, 6, 5, 4, 3, 2, 1}, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("gs_base", 0x200000000); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 3)
	requireRegister(t, c, "rax", 0x0102030405060708)
}

func TestAddressSizeOverrideZeroExtends(t *testing.T) {
	c, m := codeMemory(t, "67488b00 f4") // mov rax,[eax]
	if err := m.Map(0x2000, []byte{1, 2, 3, 4, 5, 6, 7, 8}, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rax", 0x1234567800002000); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 3)
	requireRegister(t, c, "rax", 0x0807060504030201)
}

func TestNegativeRIPRelativeDisplacement(t *testing.T) {
	// This encoding exercises the backward LEA used by a PE32+ registrar's
	// string references. The decoder exposes disp32 as an unsigned integer.
	c, m := codeMemory(t, "488d3d70bcfeff f4")
	start := c.PC()
	runCode(t, c, m, 2)
	requireRegister(t, c, "rdi", start+7-0x14390)
}

func TestArithmeticCarryAndOverflow(t *testing.T) {
	for _, tt := range []struct {
		name, code             string
		initial, result, flags uint64
	}{
		{"add64 carry", "4883c001", math.MaxUint64, 0, flagCarry | flagZero | flagParity},
		{"add64 overflow", "4883c001", math.MaxInt64, 1 << 63, flagOverflow | flagSign | flagParity},
		{"sub64 borrow", "4883e801", 0, math.MaxUint64, flagCarry | flagSign | flagParity},
		{"sub64 overflow", "4883e801", 1 << 63, math.MaxInt64, flagOverflow | flagParity},
		{"add32 clears high", "83c001", math.MaxUint64, 0, flagCarry | flagZero | flagParity},
		{"adc64 carry", "f94883d000", math.MaxUint64, 0, flagCarry | flagZero | flagParity},
		{"sbb64 full borrow", "f94883d8ff", 0, 0, flagCarry | flagZero | flagParity},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, m := codeMemory(t, tt.code+"f4")
			if err := c.SetRegister("rax", tt.initial); err != nil {
				t.Fatal(err)
			}
			runCode(t, c, m, 4)
			requireRegister(t, c, "rax", tt.result)
			if c.flags != tt.flags {
				t.Fatalf("flags=%#x, want %#x", c.flags, tt.flags)
			}
		})
	}
}

func TestByteSwapWidths(t *testing.T) {
	for _, tt := range []struct {
		code string
		want uint64
	}{
		{"48 0fc8 f4", 0xefcdab8967452301},
		{"0fc8 f4", 0xefcdab89},
	} {
		c, m := codeMemory(t, tt.code)
		c.SetRegister("rax", 0x0123456789abcdef)
		c.flags = flagCarry | flagZero | flagOverflow
		runCode(t, c, m, 2)
		requireRegister(t, c, "rax", tt.want)
		if c.flags != flagCarry|flagZero|flagOverflow {
			t.Fatal("BSWAP changed flags")
		}
	}
}

func TestCompareExchange(t *testing.T) {
	for _, match := range []bool{false, true} {
		c, m := codeMemory(t, "f0 49 0fb11c24 f4") // lock cmpxchg [r12],rbx; hlt
		const address = 0x200000000
		if err := m.Map(address, []byte{7, 0, 0, 0, 0, 0, 0, 0}, cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		c.SetRegister("r12", address)
		c.SetRegister("rbx", 0x123456789abcdef0)
		if match {
			c.SetRegister("rax", 7)
		} else {
			c.SetRegister("rax", 8)
		}
		runCode(t, c, m, 2)
		got, err := readWord(m, address, 8)
		want := uint64(7)
		if match {
			want = 0x123456789abcdef0
		}
		if err != nil || got != want || (c.flags&flagZero != 0) != match {
			t.Fatalf("match %v: memory %#x flags %#x, %v", match, got, c.flags, err)
		}
		requireRegister(t, c, "rax", 7)
	}
	c, m := codeMemory(t, "f0 41 0fb11c24 f4") // cmpxchg [r12],ebx
	if err := m.Map(0x200000000, []byte{7, 0, 0, 0}, cpu.Read); err != nil {
		t.Fatal(err)
	}
	c.SetRegister("r12", 0x200000000)
	c.SetRegister("rax", 0x123400000008)
	if _, err := c.Step(m); err == nil {
		t.Fatal("failed comparison did not check write permission")
	}
	requireRegister(t, c, "rax", 0x123400000008)
	if _, err := m.Protect(0x200000000, 4, cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 2)
	requireRegister(t, c, "rax", 7)
}

func TestRepeatedWordComparison(t *testing.T) {
	c, m := codeMemory(t, "f3 66 a7 f4") // repe cmpsw; hlt
	const left, right = 0x200000000, 0x300000000
	if err := m.Map(left, []byte{1, 0, 2, 0, 3, 0}, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if err := m.Map(right, []byte{1, 0, 9, 0, 3, 0}, cpu.Read); err != nil {
		t.Fatal(err)
	}
	c.SetRegister("rsi", left)
	c.SetRegister("rdi", right)
	c.SetRegister("rcx", 3)
	start := c.PC()
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.PC() != start || c.flags&flagZero == 0 {
		t.Fatal("equal element did not retain repeat")
	}
	requireRegister(t, c, "rcx", 2)
	runCode(t, c, m, 2)
	requireRegister(t, c, "rsi", left+4)
	requireRegister(t, c, "rdi", right+4)
	requireRegister(t, c, "rcx", 1)
	if c.flags&flagZero != 0 || c.flags&flagCarry == 0 {
		t.Fatal("comparison flags are reversed")
	}
}

func TestBranchAndCallReturn(t *testing.T) {
	// xor eax,eax; cmp eax,0; jne failure; call function; hlt;
	// failure: mov eax,1; hlt; function: mov rax,1122334455667788h; ret
	c, m := codeMemory(t, "31c0 83f800 7506 e807000000 f4 b801000000 f4 48b88877665544332211 c3")
	if err := m.Map(0x300000000, make([]byte, 0x1000), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rsp", 0x300001000); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 10)
	requireRegister(t, c, "rax", 0x1122334455667788)
	requireRegister(t, c, "rsp", 0x300001000)
}

func TestUnsupportedAndTruncatedInstructionsStopAtRIP(t *testing.T) {
	for _, code := range []string{"0f0b", "48b8"} {
		c, m := codeMemory(t, code)
		start := c.PC()
		if _, err := c.Step(m); err == nil {
			t.Fatal("unsupported/truncated instruction accepted")
		}
		if c.PC() != start {
			t.Fatal("failed instruction advanced RIP")
		}
	}
}

func TestRepeatScanIsBoundedAndResumable(t *testing.T) {
	c, m := codeMemory(t, "f2ae f4")
	const text = 0x200000000
	if err := m.Map(text, []byte{'a', 'b', 0}, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rdi", text); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rcx", math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	start := c.PC()
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.PC() != start {
		t.Fatal("repeat prematurely advanced RIP")
	}
	requireRegister(t, c, "rcx", math.MaxUint64-1)
	requireRegister(t, c, "rdi", text+1)
	saved := *c
	runCode(t, c, m, 3)
	requireRegister(t, c, "rcx", math.MaxUint64-3)
	requireRegister(t, c, "rdi", text+3)
	if c.flags&flagZero == 0 {
		t.Fatal("terminating byte was not compared")
	}
	*c = saved
	runCode(t, c, m, 3)
	requireRegister(t, c, "rdi", text+3)
}

func TestRepeatScanZeroCountDoesNotReadMemory(t *testing.T) {
	c, m := codeMemory(t, "f2ae f4")
	runCode(t, c, m, 2)
	requireRegister(t, c, "rdi", 0)
	requireRegister(t, c, "rcx", 0)
}

func TestVectorMovePreservesFullRegister(t *testing.T) {
	// movdqa xmm0,[rcx]; movdqa [rdx],xmm0; hlt
	c, m := codeMemory(t, "660f6f01 660f7f02 f4")
	input := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	const source, destination = 0x200000000, 0x300000000
	if err := m.Map(source, input, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if err := m.Map(destination, make([]byte, 16), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rcx", source); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rdx", destination); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 3)
	got := make([]byte, 16)
	if err := m.ReadMemory(destination, got, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("vector=%x", got)
	}
}

func TestAlignedVectorMoveRejectsUnalignedAddress(t *testing.T) {
	c, m := codeMemory(t, "660f6f01")
	if err := m.Map(0x200000001, make([]byte, 16), cpu.Read); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rcx", 0x200000001); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Step(m); err == nil || !strings.Contains(err.Error(), "unaligned") {
		t.Fatalf("unaligned move: %v", err)
	}
}

func TestShiftWidthsAndSignedArithmetic(t *testing.T) {
	for _, tt := range []struct {
		code          string
		input, output uint64
	}{
		{"48c1f903f4", 0xfffffffffffffff0, 0xfffffffffffffffe},
		{"48c1f903f4", 0x800000000, 0x100000000},
		{"48c1e903f4", 0xfffffffffffffff0, 0x1ffffffffffffffe},
		{"48c1e103f4", 0x100000001, 0x800000008},
		{"c1e103f4", 0xffffffff10000001, 0x80000008},
	} {
		c, m := codeMemory(t, tt.code)
		if err := c.SetRegister("rcx", tt.input); err != nil {
			t.Fatal(err)
		}
		runCode(t, c, m, 2)
		requireRegister(t, c, "rcx", tt.output)
	}
}

func TestRotate64PreservesNonArithmeticFlags(t *testing.T) {
	c, m := codeMemory(t, "48c1c110 f4")
	if err := c.SetRegister("rcx", 0x0123456789abcdef); err != nil {
		t.Fatal(err)
	}
	c.flags = flagZero | flagParity | flagSign
	runCode(t, c, m, 2)
	requireRegister(t, c, "rcx", 0x456789abcdef0123)
	if c.flags != flagZero|flagParity|flagSign|flagCarry {
		t.Fatalf("rotate flags=%#x", c.flags)
	}
}

func TestBitTestRegisterAndMemory(t *testing.T) {
	c, m := codeMemory(t, "0fbae21f f4") // bt edx,31
	if err := c.SetRegister("rdx", 0x80000000); err != nil {
		t.Fatal(err)
	}
	c.flags = flagZero
	runCode(t, c, m, 2)
	if c.flags != flagZero|flagCarry {
		t.Fatalf("BT flags=%#x", c.flags)
	}
	for _, index := range []uint64{33, 0xffffffe1} {
		c, m := codeMemory(t, "0fa310 f4") // bt [rax],edx
		if err := m.Map(0x200000000, []byte{2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0}, cpu.Read); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister("rax", 0x200000004); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister("rdx", index); err != nil {
			t.Fatal(err)
		}
		runCode(t, c, m, 2)
		if c.flags&flagCarry == 0 {
			t.Fatalf("memory bit index %#x missed", index)
		}
	}
}

func TestBitComplementRegisterAndMemory(t *testing.T) {
	for _, test := range []struct {
		code          string
		initial, want uint64
	}{
		{"0f ba f8 08", 0xffffffff00000100, 0},
		{"66 0f ba f8 18", 0xffffffff00000000, 0xffffffff00000100},
		{"48 0f ba f8 3f", 0, 1 << 63},
	} {
		c, m := codeMemory(t, test.code)
		c.registers[0], c.flags = test.initial, flagZero
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		if c.registers[0] != test.want || c.flags & ^flagCarry != flagZero {
			t.Fatalf("BTC %s = %#x flags %#x", test.code, c.registers[0], c.flags)
		}
		if (c.flags&flagCarry != 0) != (test.initial&0x100 != 0) {
			t.Fatal("incorrect original bit")
		}
	}
	for _, index := range []uint64{33, 0xffffffe1} {
		for _, writable := range []bool{false, true} {
			c, m := codeMemory(t, "0f bb 10") // btc [rax],edx
			access := cpu.Read
			if writable {
				access |= cpu.Write
			}
			if err := m.Map(0x200000000, []byte{2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0}, access); err != nil {
				t.Fatal(err)
			}
			c.registers[0], c.registers[2], c.flags = 0x200000004, index, flagZero
			before := *c
			_, err := c.Step(m)
			if !writable {
				if err == nil || *c != before {
					t.Fatal("read-only BTC did not fault atomically")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			address := uint64(0x200000008)
			if index != 33 {
				address = 0x200000000
			}
			value, err := readWord(m, address, 4)
			if err != nil || value != 0 || c.flags != flagZero|flagCarry {
				t.Fatalf("BTC memory = %#x flags %#x, %v", value, c.flags, err)
			}
		}
	}
}

func TestSignedDivisionWidthsAndFaults(t *testing.T) {
	for _, instruction := range []struct {
		code  string
		width int
	}{{"f6 f9", 1}, {"66 f7 f9", 2}, {"f7 f9", 4}, {"48 f7 f9", 8}} {
		for _, pair := range [][2]int64{{7, 3}, {-7, 3}, {7, -3}, {-7, -3}, {0, -3}} {
			c, m := codeMemory(t, instruction.code)
			c.registers[0] = uint64(pair[0])
			if pair[0] < 0 {
				c.registers[2] = math.MaxUint64
			}
			c.registers[1] = uint64(pair[1])
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			q, r := c.registers[0]&mask(instruction.width), c.registers[2]&mask(instruction.width)
			if instruction.width == 1 {
				r = (c.registers[0] >> 8) & 0xff
			}
			if q != uint64(pair[0]/pair[1])&mask(instruction.width) || r != uint64(pair[0]%pair[1])&mask(instruction.width) {
				t.Fatalf("width %d: %v quotient/remainder %#x %#x", instruction.width, pair, q, r)
			}
		}
		for _, divisor := range []uint64{0, math.MaxUint64} {
			c, m := codeMemory(t, instruction.code)
			minimum := uint64(1) << (instruction.width*8 - 1)
			c.registers[0] = minimum
			c.registers[2] = math.MaxUint64
			if instruction.width == 1 {
				c.registers[0] |= 0xff00
			}
			c.registers[1] = divisor
			before := *c
			if _, err := c.Step(m); err == nil || *c != before {
				t.Fatal("signed division overflow/zero must fault without changing state")
			}
		}
	}
	// The dividend is a full signed 128-bit pair, not merely a sign-extended RAX.
	c, m := codeMemory(t, "48 f7 f9")
	c.registers[0], c.registers[2], c.registers[1] = 0, 1, 3
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.registers[0] != 0x5555555555555555 || c.registers[2] != 1 {
		t.Fatal("lost high half of signed 128-bit dividend")
	}
}

func TestUnsignedDivisionRetainsHighDividend(t *testing.T) {
	for _, tt := range []struct {
		code     string
		quotient uint64
	}{{"48f7f1f4", 1 << 63}, {"f7f1f4", 1 << 31}} {
		c, m := codeMemory(t, tt.code)
		if err := c.SetRegister("rdx", 1); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister("rcx", 2); err != nil {
			t.Fatal(err)
		}
		runCode(t, c, m, 2)
		requireRegister(t, c, "rax", tt.quotient)
		requireRegister(t, c, "rdx", 0)
	}
	for _, divisor := range []uint64{0, 1} {
		c, m := codeMemory(t, "48f7f1")
		if err := c.SetRegister("rax", 17); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister("rdx", 1); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister("rcx", divisor); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Step(m); err == nil {
			t.Fatal("invalid divide succeeded")
		}
		requireRegister(t, c, "rax", 17)
		requireRegister(t, c, "rdx", 1)
	}
}

func TestMultiplyFullWidthAndOverflow(t *testing.T) {
	for _, tt := range []struct {
		code                string
		left, right, result uint64
		overflow            bool
	}{
		{"480fafc1f4", 0xfffffffffffffffd, 5, 0xfffffffffffffff1, false},
		{"480fafc1f4", math.MaxInt64, 2, math.MaxUint64 - 1, true},
		{"480fafc1f4", 1 << 63, math.MaxUint64, 1 << 63, true},
		{"0fafc1f4", 0xfffffffffffffffd, 5, 0xfffffff1, false},
	} {
		c, m := codeMemory(t, tt.code)
		if err := c.SetRegister("rax", tt.left); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister("rcx", tt.right); err != nil {
			t.Fatal(err)
		}
		runCode(t, c, m, 2)
		requireRegister(t, c, "rax", tt.result)
		if (c.flags&flagOverflow != 0) != tt.overflow || (c.flags&flagCarry != 0) != tt.overflow {
			t.Fatalf("multiply flags=%#x", c.flags)
		}
	}
	c, m := codeMemory(t, "48f7e1f4") // mul rcx
	if err := c.SetRegister("rax", 1<<63); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rcx", 2); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 2)
	requireRegister(t, c, "rax", 0)
	requireRegister(t, c, "rdx", 1)
}

func TestAccumulatorSignExtension(t *testing.T) {
	c, m := codeMemory(t, "4898 4899 f4") // cdqe; cqo
	if err := c.SetRegister("rax", 0x1234567880000001); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 3)
	requireRegister(t, c, "rax", 0xffffffff80000001)
	requireRegister(t, c, "rdx", math.MaxUint64)
	c, m = codeMemory(t, "99f4") // cdq
	if err := c.SetRegister("rax", 0x80000001); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRegister("rdx", math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	runCode(t, c, m, 2)
	requireRegister(t, c, "rdx", math.MaxUint32)
}
