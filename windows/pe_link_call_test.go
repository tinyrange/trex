package windows

import (
	"bytes"
	"debug/pe"
	"testing"
)

func TestNativeDLLAndForeignCallValidation(t *testing.T) {
	opts := linkFixtureOptions()
	opts.Subsystem = 1
	opts.NativeDLL = true
	opts.Entry = "Callback"
	opts.ImportABI = map[string]string{"Import": "fastcall"}
	data, err := LinkPE32(linkObjectFixture(), opts)
	if err != nil {
		t.Fatal(err)
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Characteristics&pe.IMAGE_FILE_DLL == 0 || f.OptionalHeader.(*pe.OptionalHeader32).Subsystem != 1 {
		t.Fatal("native DLL characteristics missing")
	}
	opts.ImportABI = map[string]string{"Missing": "fastcall"}
	if _, err := LinkPE32(linkObjectFixture(), opts); err == nil {
		t.Fatal("unknown import ABI accepted")
	}
	opts.ImportABI = map[string]string{"Import": "unknown"}
	if _, err := LinkPE32(linkObjectFixture(), opts); err == nil {
		t.Fatal("unknown ABI accepted")
	}
	opts.ImportABI = nil
	opts.IndirectCalls = map[string]int{"Import": 2}
	if _, err := LinkPE32(linkObjectFixture(), opts); err == nil {
		t.Fatal("conflicting bridge accepted")
	}
	opts.Imports = nil
	if _, err := LinkPE32(linkObjectFixture(), opts); err != nil {
		t.Fatal("indirect call relocation failed", err)
	}
}
