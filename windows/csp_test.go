package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
)

func TestAnalyzeCSPRegistrationCode(t *testing.T) {
	const startRVA = 0x1200
	var code []byte
	for value := uint32(9); value >= 1; value-- {
		code = appendPushImmediate(code, value)
	}
	callOffset := len(code)
	code = append(code, 0xe8, 0, 0, 0, 0)
	target := uint32(0x1800)
	displacement := int32(target) - int32(startRVA) - int32(callOffset+5)
	binary.LittleEndian.PutUint32(code[callOffset+1:], uint32(displacement))
	code = append(code, 0xc3)

	calls, err := analyzeCSPRegistrationCode(code, startRVA)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].target != target || len(calls[0].pushes) != 9 {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestResolveCSPImagePathDirectString(t *testing.T) {
	context := syntheticCSPContext("client.dll", "SERVER.dll", true)
	got, err := resolveCSPImagePath(context, context.optional.ImageBase+0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if got != "client.dll" {
		t.Fatalf("got %q, want direct string", got)
	}
}

func TestResolveCSPImagePathWritableBuffer(t *testing.T) {
	context := syntheticCSPContext("", "SERVER.dll", true)
	got, err := resolveCSPImagePath(context, context.optional.ImageBase+0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if got != "SERVER.dll" {
		t.Fatalf("got %q, want export name", got)
	}
}

func TestResolveCSPImagePathRejectsInvalidFallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		address uint32
		write   bool
	}{
		{name: "read-only", address: 0x10001000, write: false},
		{name: "unmapped", address: 0x10003000, write: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			context := syntheticCSPContext("", "SERVER.dll", test.write)
			if _, err := resolveCSPImagePath(context, test.address); err == nil {
				t.Fatal("expected fallback rejection")
			}
		})
	}
}

func TestResolveCSPImagePathRejectsInvalidExportName(t *testing.T) {
	for _, name := range []string{"", "server", "../server.dll", `dir\server.dll`, "C:server.dll", ".", ".."} {
		if validCSPExportDLLName(name) {
			t.Fatalf("accepted invalid export name %q", name)
		}
		if name != "" {
			context := syntheticCSPContext("", name, true)
			if _, err := resolveCSPImagePath(context, context.optional.ImageBase+0x1000); err == nil {
				t.Fatalf("resolved invalid export name %q", name)
			}
		}
	}
	if !validCSPExportDLLName("Provider.DLL") {
		t.Fatal("rejected valid export DLL basename")
	}
}

func TestCSPRegistrationMaterializesSignature(t *testing.T) {
	const base = uint32(0x20000000)
	data := make([]byte, 256)
	putCString(data, 0, "Provider")
	putCString(data, 32, "provider.dll")
	putCString(data, 64, "Type 007")
	putCString(data, 96, "Synthetic Type")
	copy(data[160:], []byte{1, 2, 3})
	context := &cspPEContext{
		data:     data,
		optional: &pe.OptionalHeader32{ImageBase: base, SizeOfImage: 0x3000},
		sections: []cspPESection{{rvaStart: 0x1000, rvaEnd: 0x1100, rawStart: 0, rawSize: 256}},
	}
	arguments := []uint32{
		base + 0x1000,
		base + 0x1020,
		base + 0x10a0,
		3,
		7,
		base + 0x1040,
		base + 0x1060,
		0,
		1,
	}
	pushes := make([]x86Constant, len(arguments))
	for index := range arguments {
		pushes[len(arguments)-1-index] = x86Constant{value: arguments[index], ok: true}
	}
	registration, err := cspRegistrationFromPushes(pushes, context)
	if err != nil {
		t.Fatal(err)
	}
	if registration.signatureInFile || !bytes.Equal(registration.signatureData, []byte{1, 2, 3}) || !registration.makeDefault {
		t.Fatalf("registration = %#v", registration)
	}
}

func TestValidateCSPRegistrationConflicts(t *testing.T) {
	base := cspRegistration{
		provider: "Provider A", imagePath: "provider.dll", providerType: 1,
		typeKey: "Type 001", typeName: "Type A", signatureInFile: true,
	}
	if err := validateCSPRegistrationConflicts([]cspRegistration{base, base}); err != nil {
		t.Fatalf("equivalent duplicate: %v", err)
	}
	conflictingProvider := base
	conflictingProvider.imagePath = "other.dll"
	if err := validateCSPRegistrationConflicts([]cspRegistration{base, conflictingProvider}); err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("provider conflict = %v", err)
	}
	conflictingType := base
	conflictingType.provider = "Provider B"
	conflictingType.typeName = "Other Type"
	if err := validateCSPRegistrationConflicts([]cspRegistration{base, conflictingType}); err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("type conflict = %v", err)
	}
}

func syntheticCSPContext(directName, exportName string, writable bool) *cspPEContext {
	const base = uint32(0x10000000)
	data := make([]byte, 512)
	bufferRawSize := uint32(0)
	if directName != "" {
		putCString(data, 0, directName)
		bufferRawSize = 64
	}
	binary.LittleEndian.PutUint32(data[128+12:], 0x1180)
	putCString(data, 256, exportName)
	optional := &pe.OptionalHeader32{ImageBase: base, SizeOfImage: 0x3000}
	optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT] = pe.DataDirectory{VirtualAddress: 0x1100, Size: 40}
	return &cspPEContext{
		data:     data,
		optional: optional,
		sections: []cspPESection{
			{rvaStart: 0x1000, rvaEnd: 0x1040, rawStart: 0, rawSize: bufferRawSize, writable: writable},
			{rvaStart: 0x1100, rvaEnd: 0x1300, rawStart: 128, rawSize: 384},
		},
	}
}

func putCString(data []byte, offset int, value string) {
	copy(data[offset:], value)
	data[offset+len(value)] = 0
}

func appendMoveImmediate(code []byte, register byte, value uint32) []byte {
	code = append(code, 0xb8+register, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(code[len(code)-4:], value)
	return code
}

func appendPushImmediate(code []byte, value uint32) []byte {
	code = append(code, 0x68, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(code[len(code)-4:], value)
	return code
}
