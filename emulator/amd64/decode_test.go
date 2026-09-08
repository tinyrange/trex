package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"reflect"
	"testing"
)

func TestDecodedInstructionRemainsImmutableAcrossExecution(t *testing.T) {
	code := [15]byte{0x48, 0x89, 0xc8} // mov rax,rcx
	decoded, err := decodeInstruction(code, len(code))
	if err != nil {
		t.Fatal(err)
	}
	before := *decoded
	for _, argument := range []uint64{7, 0x123456789abcdef0} {
		memory := cpu.NewAddressSpace(4096)
		if err := memory.Map(0x1000, code[:], cpu.Read|cpu.Execute); err != nil {
			t.Fatal(err)
		}
		processor := &CPU{}
		processor.SetPC(0x1000)
		if err := processor.SetRegister("rcx", argument); err != nil {
			t.Fatal(err)
		}
		if _, err := processor.Step(memory); err != nil {
			t.Fatal(err)
		}
		got, _ := processor.Register("rax")
		if got != argument {
			t.Fatalf("rax=%#x, want %#x", got, argument)
		}
		if !reflect.DeepEqual(*decoded, before) {
			t.Fatal("execution mutated cached decode metadata")
		}
	}
	again, err := decodeInstruction(code, len(code))
	if err != nil || again != decoded {
		t.Fatalf("decode did not reuse immutable entry: %v", err)
	}
}
