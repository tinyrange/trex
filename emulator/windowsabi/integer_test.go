package windowsabi

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
)

func TestAMD64IntegerCallAndHook(t *testing.T) {
	m := cpu.NewAddressSpace(0x2000)
	if err := m.Map(0x200000000, make([]byte, 0x1000), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	var c amd64.CPU
	args := []uint64{0x100000001, 0x200000002, 0x300000003, 0x400000004, 0x500000005, 0x600000006}
	const returnAddress = 0x180004000
	if err := PrepareAMD64IntegerCall(&c, m, 0x180001000, 0x200001000, returnAddress, args); err != nil {
		t.Fatal(err)
	}
	sp, _ := c.Register("rsp")
	if sp&15 != 8 {
		t.Fatalf("entry RSP %#x is not caller-aligned", sp)
	}
	got, err := AMD64IntegerArguments(&c, m, len(args))
	if err != nil || !reflect.DeepEqual(got, args) {
		t.Fatalf("arguments=%#v, %v", got, err)
	}
	// All four home slots are writable, even with fewer than four arguments.
	if err := m.WriteMemory(sp+8, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := ReturnAMD64Integer(&c, m, 0x800000009); err != nil {
		t.Fatal(err)
	}
	value, _ := c.Register("rax")
	restoredSP, _ := c.Register("rsp")
	if c.PC() != returnAddress || value != 0x800000009 || restoredSP != sp+8 {
		t.Fatalf("bad return: pc=%#x value=%#x sp=%#x", c.PC(), value, restoredSP)
	}
	if err := PrepareAMD64IntegerCall(&c, m, 0, 0, 0, nil); err == nil {
		t.Fatal("stack underflow accepted")
	}
}

func TestAMD64ExecutesSixArgumentIntegerCall(t *testing.T) {
	m := cpu.NewAddressSpace(0x2000)
	if err := m.Map(0x200000000, make([]byte, 0x1000), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	// mov rax,rcx; add rax,rdx; add rax,r8; add rax,r9;
	// add rax,[rsp+28h]; add rax,[rsp+30h]; ret
	code, _ := hex.DecodeString("4889c84801d04c01c04c01c848034424284803442430c3")
	const entry = 0x180001000
	if err := m.Map(entry, code, cpu.Read|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	var c amd64.CPU
	args := []uint64{0x100000001, 2, 3, 4, 0x200000005, 6}
	if err := PrepareAMD64IntegerCall(&c, m, entry, 0x200001000, 0x180004000, args); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		effect, err := c.Step(m)
		if err != nil {
			t.Fatal(err)
		}
		if i == 6 && effect != cpu.Return {
			t.Fatalf("last effect=%d", effect)
		}
	}
	value, _ := c.Register("rax")
	if value != 0x300000015 || c.PC() != 0x180004000 {
		t.Fatalf("return=%#x, pc=%#x", value, c.PC())
	}
}
