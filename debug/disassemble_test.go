package debug

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestDisassembleDirectCallTargetAndCount(t *testing.T) {
	// call +5; nop. Count one must avoid decoding or reporting trailing data.
	value, err := DisassembleBuiltin(nil, nil,
		starlark.Tuple{starlark.Bytes("\xe8\x05\x00\x00\x00\x90")},
		[]starlark.Tuple{
			{starlark.String("address"), starlark.MakeInt64(0x1000)},
			{starlark.String("count"), starlark.MakeInt(1)},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	list := value.(*starlark.List)
	if list.Len() != 1 {
		t.Fatalf("instructions = %d, want 1", list.Len())
	}
	instruction := list.Index(0).(starlark.HasAttrs)
	flow, _ := instruction.Attr("flow")
	target, _ := instruction.Attr("target")
	if flow != starlark.String("call") || target.String() != "4106" {
		t.Fatalf("flow = %s, target = %s", flow, target)
	}
}

func TestDisassemble16BitBootCode(t *testing.T) {
	value, err := DisassembleBuiltin(nil, nil,
		starlark.Tuple{starlark.Bytes("\x66\x8b\x46\x1c\xcd\x13")},
		[]starlark.Tuple{
			{starlark.String("address"), starlark.MakeInt64(0x7c00)},
			{starlark.String("architecture"), starlark.String("x86-16")},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	list := value.(*starlark.List)
	if list.Len() != 2 {
		t.Fatalf("instructions = %d, want 2", list.Len())
	}
	first := list.Index(0).(starlark.HasAttrs)
	text, _ := first.Attr("text")
	if text != starlark.String("mov eax, dword ptr [bp+0x1c]") {
		t.Fatalf("first instruction = %s", text)
	}
}
