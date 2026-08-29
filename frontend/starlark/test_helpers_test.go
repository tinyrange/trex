package starlarkfrontend

import (
	"math"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func testBlockDevice(t *testing.T, size int) *fileBlockDevice {
	t.Helper()
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(index * 31)
	}
	device, err := newFileBlockDevice(&starfile.Bytes{Name: "block-test", Data: data}, 512, 512, false)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func recordString(t *testing.T, record *starlarkRecord, name string) string {
	t.Helper()
	value := record.Values[name]
	result, ok := starlark.AsString(value)
	if !ok {
		t.Fatalf("record field %s is %s, want string", name, value.Type())
	}
	return result
}

func recordUint32(t *testing.T, record *starlarkRecord, name string) uint32 {
	t.Helper()
	value := record.Values[name]
	integer, ok := value.(starlark.Int)
	if !ok {
		t.Fatalf("record field %s is %s, want int", name, value.Type())
	}
	result, ok := integer.Uint64()
	if !ok || result > math.MaxUint32 {
		t.Fatalf("record field %s is not uint32: %s", name, value)
	}
	return uint32(result)
}

func relocatablePE32TestImage(t *testing.T, imageBase uint32) starlark.Bytes {
	t.Helper()
	section := []byte{0xb8, 0, 0, 0, 0, 0xc3, 0}
	labels := starlark.NewDict(2)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	_ = labels.SetKey(starlark.String("target"), starlark.MakeInt(6))
	fixups := starlark.NewList([]starlark.Value{peFixupValue(t, 1, "target")})
	value, err := callWindowsRuntime(t, "pe32_executable", starlark.Tuple{starlark.Bytes(section), labels, fixups}, []starlark.Tuple{{starlark.String("image_base"), starlark.MakeUint(uint(imageBase))}})
	if err != nil {
		t.Fatal(err)
	}
	return value.(starlark.Bytes)
}

func peFixupValue(t *testing.T, offset int, label string) *starlark.Dict {
	t.Helper()
	fixup := starlark.NewDict(2)
	_ = fixup.SetKey(starlark.String("offset"), starlark.MakeInt(offset))
	_ = fixup.SetKey(starlark.String("label"), starlark.String(label))
	return fixup
}

func newRawX86TestMachine(t testing.TB, code starlark.Bytes, extra []starlark.Tuple) *emulatorX86 {
	t.Helper()
	kwargs := append([]starlark.Tuple{{starlark.String("code"), code}}, extra...)
	value, err := emulatorX86Builtin(nil, nil, nil, kwargs)
	if err != nil {
		t.Fatal(err)
	}
	return value.(*emulatorX86)
}
