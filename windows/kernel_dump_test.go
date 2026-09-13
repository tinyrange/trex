package windows

import (
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestKernelDumpHeader(t *testing.T) {
	data := make([]byte, 8192)
	copy(data, "PAGEDU64")
	binary.LittleEndian.PutUint32(data[0x38:], 0x5a)
	binary.LittleEndian.PutUint64(data[0x58:], 0xffffffffc0000034)
	binary.LittleEndian.PutUint64(data[0xfa0:], 8192)
	binary.LittleEndian.PutUint32(data[0x1048:], 0xc0000001)
	read := func(b []byte) (starlark.Value, error) {
		return kernelDumpHeaderBuiltin(nil, nil, starlark.Tuple{&starfile.Bytes{Name: "dump", Data: b}}, nil)
	}
	value, err := read(data)
	if err != nil {
		t.Fatal(err)
	}
	record := value.(starlark.HasAttrs)
	for name, want := range map[string]string{"bugcheck_code": "90", "required_size": "8192", "extent_available": "True", "writer_status": "3221225473", "bugcheck_parameters": "[0, 0, 0, 18446744072635809844]"} {
		got, err := record.Attr(name)
		if err != nil || got.String() != want {
			t.Fatalf("%s=%v, %v; want %s", name, got, err, want)
		}
	}
	for _, size := range []uint64{0, 8191, 8193, ^uint64(0)} {
		binary.LittleEndian.PutUint64(data[0xfa0:], size)
		v, err := read(data)
		if err != nil {
			t.Fatal(err)
		}
		available, _ := v.(starlark.HasAttrs).Attr("extent_available")
		if available != starlark.False {
			t.Fatalf("accepted size %d", size)
		}
	}
	if _, err := read(data[:8191]); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("short header: %v", err)
	}
	data[4] = 'X'
	if _, err := read(data); err == nil {
		t.Fatal("accepted invalid signature")
	}
}
