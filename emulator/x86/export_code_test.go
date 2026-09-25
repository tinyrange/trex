package x86

import (
	"encoding/binary"
	"math"
	"testing"

	"go.starlark.net/starlark"
)

func TestAllocationFallsBackToLowUserAddressSpace(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	m.nextAllocation = m.stackLow - 16
	v, err := m.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("size"), starlark.MakeInt(4096)},
		{starlark.String("alignment"), starlark.MakeInt(65536)},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, _ := v.(starlark.Int).Uint64()
	if address != 0x10000 {
		t.Fatalf("fallback address = %#x, want 0x10000", address)
	}
}

func TestFXCHPreservesStackDepth(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\xd9\xc9\xc3"), nil)
	if err := m.x87Push(3); err != nil {
		t.Fatal(err)
	}
	if err := m.x87Push(7); err != nil {
		t.Fatal(err)
	}
	top := m.x87Top
	m.x87StatusWord = 0x4700
	result, err := m.callAddress(&starlark.Thread{Name: "fxch"}, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recordString(t, result.(*starlarkRecord), "reason") != "return" {
		t.Fatalf("FXCH stopped: %v", result)
	}
	first, _ := m.x87Value(0)
	second, _ := m.x87Value(1)
	if first != 3 || second != 7 || m.x87Top != top || m.x87Depth != 2 || m.x87StatusWord != 0x4500 {
		t.Fatalf("FXCH stack = %v,%v top=%d depth=%d status=%x", first, second, m.x87Top, m.x87Depth, m.x87StatusWord)
	}
}

func TestFPTANResultAndRange(t *testing.T) {
	for _, input := range []float64{0, math.Pi / 4, -math.Pi / 4, 0x1p63} {
		m := newRawX86TestMachine(t, starlark.Bytes("\xd9\xf2\xc3"), nil)
		if err := m.x87Push(input); err != nil {
			t.Fatal(err)
		}
		result, err := m.callAddress(&starlark.Thread{Name: "fptan"}, 0x1000, nil)
		if err != nil {
			t.Fatal(err)
		}
		if recordString(t, result.(*starlarkRecord), "reason") != "return" {
			t.Fatalf("FPTAN stopped: %v", result)
		}
		first, _ := m.x87Value(0)
		if input == 0x1p63 {
			if first != input || m.x87Depth != 1 || m.x87StatusWord&0x400 == 0 {
				t.Fatal("out-of-range FPTAN changed its operand or omitted C2")
			}
		} else {
			second, _ := m.x87Value(1)
			if first != 1 || m.x87Depth != 2 || math.Abs(second-math.Tan(input)) > 1e-15 || m.x87StatusWord&0x400 != 0 {
				t.Fatalf("FPTAN(%v) = %v,%v", input, first, second)
			}
		}
	}
}

func TestFCOSResultAndRange(t *testing.T) {
	for _, input := range []float64{0, math.Pi, 0x1p63} {
		m := newRawX86TestMachine(t, starlark.Bytes("\xd9\xff\xc3"), nil)
		if err := m.x87Push(input); err != nil {
			t.Fatal(err)
		}
		result, err := m.callAddress(&starlark.Thread{Name: "fcos"}, 0x1000, nil)
		if err != nil {
			t.Fatal(err)
		}
		value, _ := m.x87Value(0)
		want := math.Cos(input)
		if input == 0x1p63 {
			want = input
		}
		if recordString(t, result.(*starlarkRecord), "reason") != "return" || value != want || m.x87Depth != 1 || (m.x87StatusWord&0x400 != 0) != (input == 0x1p63) {
			t.Fatalf("FCOS(%v) = %v status=%x", input, value, m.x87StatusWord)
		}
	}
}

func TestFSINResult(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\xd9\xfe\xc3"), nil)
	if err := m.x87Push(math.Pi / 2); err != nil {
		t.Fatal(err)
	}
	result, err := m.callAddress(&starlark.Thread{Name: "fsin"}, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := m.x87Value(0)
	if recordString(t, result.(*starlarkRecord), "reason") != "return" || value != 1 || m.x87Depth != 1 {
		t.Fatalf("FSIN(pi/2) = %v", value)
	}
}

func TestFSQRTResult(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\xd9\xfa\xc3"), nil)
	if err := m.x87Push(9); err != nil {
		t.Fatal(err)
	}
	result, err := m.callAddress(&starlark.Thread{Name: "fsqrt"}, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := m.x87Value(0)
	if recordString(t, result.(*starlarkRecord), "reason") != "return" || value != 3 || m.x87Depth != 1 {
		t.Fatalf("FSQRT(9) = %v", value)
	}
}

func TestWordFlagsStackWidth(t *testing.T) {
	// SUB sets carry; XOR clears it. Word PUSHF/POPF must restore it
	// without losing the return address. Return only the carry bit.
	m := newRawX86TestMachine(t, starlark.Bytes("\x31\xc0\x83\xe8\x01\x66\x9c\x31\xc0\x66\x9d\x9c\x58\x83\xe0\x01\xc3"), nil)
	want := uint32(1)
	result, err := m.callAddress(&starlark.Thread{Name: "word flags"}, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recordString(t, result.(*starlarkRecord), "reason") != "return" || recordUint32(t, result.(*starlarkRecord), "value") != want {
		t.Fatalf("word flags result = %v, want %#x", result.(*starlarkRecord).Values, want)
	}
}

func TestWordAllRegistersStackWidth(t *testing.T) {
	// Preserve AX through PUSHA/POPA while retaining a changed upper EAX.
	m := newRawX86TestMachine(t, starlark.Bytes("\xb8\x78\x56\x34\x12\x66\x60\xb8\x00\x00\xcd\xab\x66\x61\xc3"), nil)
	result, err := m.callAddress(&starlark.Thread{Name: "word registers"}, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := result.(*starlarkRecord)
	if recordString(t, r, "reason") != "return" || recordUint32(t, r, "value") != 0xabcd5678 {
		t.Fatalf("word register result = %v", r.Values)
	}
}

func TestUnpackLowPackedSingles(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\x0f\x14\xc1\xc3"), nil)
	for index := range m.xmm[0] {
		m.xmm[0][index] = byte(index)
		m.xmm[1][index] = byte(index + 16)
	}
	result, err := m.run(&starlark.Thread{Name: "unpack singles"})
	if err != nil {
		t.Fatal(err)
	}
	want := [16]byte{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23}
	if recordString(t, result.(*starlarkRecord), "reason") != "return" || m.xmm[0] != want {
		t.Fatalf("unpacked = %v, want %v", m.xmm[0], want)
	}
}

func TestSquareRootScalarSinglePreservesUpperLanes(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\xf3\x0f\x51\xc1\xc3"), nil)
	for index := range m.xmm[0] {
		m.xmm[0][index] = 0xaa
	}
	binary.LittleEndian.PutUint32(m.xmm[1][:], math.Float32bits(9))
	want := m.xmm[0]
	binary.LittleEndian.PutUint32(want[:], math.Float32bits(3))
	result, err := m.run(&starlark.Thread{Name: "sqrtss"})
	if err != nil {
		t.Fatal(err)
	}
	if recordString(t, result.(*starlarkRecord), "reason") != "return" || m.xmm[0] != want {
		t.Fatalf("SQRTSS = %v, want %v", m.xmm[0], want)
	}
}

func TestMXCSRLoadStoreAndExecutionState(t *testing.T) {
	// LDMXCSR [0x2000]; STMXCSR [0x2004]; RET.
	m := newRawX86TestMachine(t, starlark.Bytes("\x0f\xae\x15\x00\x20\x00\x00\x0f\xae\x1d\x04\x20\x00\x00\xc3"), nil)
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data, 0x9fc0)
	if err := m.addMapping("MXCSR", 0x2000, data, true, true, false); err != nil {
		t.Fatal(err)
	}
	result, err := m.run(&starlark.Thread{Name: "mxcsr"})
	if err != nil {
		t.Fatal(err)
	}
	if recordString(t, result.(*starlarkRecord), "reason") != "return" || binary.LittleEndian.Uint32(data[4:]) != 0x9fc0 {
		t.Fatalf("MXCSR result: %v, %x", result, data)
	}
	saved, err := m.captureContext()
	if err != nil {
		t.Fatal(err)
	}
	m.mxcsr = 0x1f80
	if err := m.restoreContext(saved); err != nil {
		t.Fatal(err)
	}
	if m.mxcsr != 0x9fc0 {
		t.Fatalf("MXCSR context = %x", m.mxcsr)
	}
}

func TestSemanticExportCodeCanBePatchedAndRestored(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	th := &starlark.Thread{Name: "export-code"}
	cb := starlark.NewBuiltin("answer", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		e := args[0].(*starlarkRecord)
		a, _ := e.Attr("args")
		return a.(*starlark.List).Index(0).(starlark.Int).Add(starlark.MakeInt(1)), nil
	})
	v, e := m.provideExportBuiltin(th, nil, starlark.Tuple{cb}, []starlark.Tuple{{starlark.String("module"), starlark.String("fixture.dll")}, {starlark.String("name"), starlark.String("Answer")}, {starlark.String("argc"), starlark.MakeInt(1)}})
	if e != nil {
		t.Fatal(e)
	}
	n, _ := v.(starlark.Int).Uint64()
	address := uint32(n)
	original, e := m.readMemory(address, 16, 'r')
	if e != nil {
		t.Fatal(e)
	}
	saved := append([]byte(nil), original...)
	// Copied first five bytes followed by a jump to the original semantic body.
	trampoline := append([]byte{}, saved[:5]...)
	trampoline = append(trampoline, 0xe9, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(trampoline[6:], address+5-(0x2000+10))
	if e = m.addMapping("trampoline", 0x2000, trampoline, true, false, true); e != nil {
		t.Fatal(e)
	}
	call := func(at, want uint32) {
		t.Helper()
		r, e := m.callAddress(th, at, []uint32{41})
		if e != nil {
			t.Fatal(e)
		}
		s := r.(*starlarkRecord)
		if recordString(t, s, "reason") != "return" || recordUint32(t, s, "value") != want {
			t.Fatalf("%s at%x", s, at)
		}
	}
	call(address, 42)
	call(0x2000, 42)
	cp, e := m.checkpointBuiltin(nil, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.protectBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(n), starlark.MakeInt(16)}, []starlark.Tuple{{starlark.String("readable"), starlark.True}, {starlark.String("writable"), starlark.True}, {starlark.String("executable"), starlark.True}}); e != nil {
		t.Fatal(e)
	}
	if e = m.writeMemory(address, []byte{0xb8, 99, 0, 0, 0, 0xc2, 4, 0}); e != nil {
		t.Fatal(e)
	}
	call(address, 99)
	if _, e = m.restoreBuiltin(nil, nil, starlark.Tuple{cp}, nil); e != nil {
		t.Fatal(e)
	}
	call(address, 42)
	call(0x2000, 42)
}
