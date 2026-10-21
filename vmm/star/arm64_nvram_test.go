package star

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/tinyrange/trex/boot/darwin"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestDarwinARM64NVRAMComposition(t *testing.T) {
	// Minimal executable with an ARM64 thread entry and a file-backed segment.
	kernel := make([]byte, 0x8000)
	for offset, value := range map[int]uint32{0: 0xfeedfacf, 4: 0x100000c, 8: 2, 12: 12, 16: 2, 20: 360, 32: 0x19, 36: 72, 104: 5, 108: 288, 112: 6, 116: 68} {
		binary.LittleEndian.PutUint32(kernel[offset:], value)
	}
	copy(kernel[40:], "__TEXT")
	binary.LittleEndian.PutUint64(kernel[56:], 0xfffffe0007004000)
	binary.LittleEndian.PutUint64(kernel[64:], uint64(len(kernel)))
	binary.LittleEndian.PutUint64(kernel[80:], uint64(len(kernel)))
	binary.LittleEndian.PutUint64(kernel[376:], 0xfffffe0007005000)
	firmwareBank, _ := darwin.ARM64NVRAM(8192, map[string]string{"firmware": "preserved"}, nil)
	tree, err := (darwin.Node{Properties: map[string][]byte{"name": darwin.CString("device-tree")}, Children: []darwin.Node{{Properties: map[string][]byte{
		"name": darwin.CString("chosen"), "nvram-proxy-data": firmwareBank,
		"nvram-bank-size": darwin.U32(8192), "nvram-bank-count": darwin.U32(1), "nvram-current-bank": darwin.U32(0),
	}}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	custom := starlark.NewDict(4)
	longName := strings.Repeat("x", 36) + ":literal"
	custom.SetKey(starlark.String(longName), starlark.String("not a GUID"))
	custom.SetKey(starlark.String("name"), starlark.String("common"))
	custom.SetKey(starlark.String("7C436110-AB2A-4BBB-A880-FE41995C9F82:explicit"), starlark.String("common too"))
	custom.SetKey(starlark.String("40a0ddd2-77f8-4392-b4a3-1e7304206516:fixture-config"), starlark.String(`{"token":"a=="}`))
	customBank, _ := darwin.ARM64NVRAM(8192, map[string]string{"name": "common", "explicit": "common too", longName: "not a GUID"}, map[string]string{"fixture-config": `{"token":"a=="}`})
	emptyBank, _ := darwin.EmptyARM64NVRAM(8192)
	for _, tc := range []struct {
		name  string
		value starlark.Value
		want  []byte
	}{{"preserved", starlark.None, firmwareBank}, {"empty", starlark.NewDict(0), emptyBank}, {"custom", custom, customBank}} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := darwinARM64BootBuiltin(nil, nil, starlark.Tuple{
				&starfile.Bytes{Name: "kernel", Data: kernel}, &starfile.Bytes{Name: "tree", Data: tree}, starlark.MakeInt(1536 << 20),
			}, []starlark.Tuple{{starlark.String("memory_base"), starlark.MakeUint64(0x70000000)}, {starlark.String("virtual_base"), starlark.MakeUint64(0xfffffe0000000000)}, {starlark.String("entropy"), starlark.Bytes(strings.Repeat("x", 256))}, {starlark.String("nvram"), tc.value}})
			if err != nil {
				t.Fatal(err)
			}
			boot := result.(*arm64BootValue).boot
			handoff := result.(*arm64BootValue).handoff
			if !bytes.Equal(handoff.NVRAM, tc.want) {
				t.Fatal("Starlark configuration did not reach physical bank seed")
			}
			args := make([]byte, 1152)
			if _, err := boot.Image.ReadAt(args, int64(boot.X[0]-boot.Address)); err != nil {
				t.Fatal(err)
			}
			dt := make([]byte, binary.LittleEndian.Uint32(args[104:]))
			dtAddress := binary.LittleEndian.Uint64(args[96:]) - 0xfffffe0000000000 + boot.MemoryBase
			if _, err := boot.Image.ReadAt(dt, int64(dtAddress-boot.Address)); err != nil {
				t.Fatal(err)
			}
			node, err := darwin.DecodeNode(bytes.NewReader(dt))
			if err != nil || len(node.Children) != 1 || !bytes.Equal(node.Children[0].Properties["nvram-proxy-data"], handoff.NVRAM) {
				t.Fatal("Starlark physical bank and encoded proxy differ", err)
			}
			if err := boot.Validate(1536 << 20); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDarwinARM64NVRAMRejectsInvalidValues(t *testing.T) {
	for _, expression := range []string{
		`[]`, `{"name": 1}`, `{1: "value"}`, `{"": "value"}`, `{"a=b": "value"}`, `{"name": "bad\x00value"}`,
		`{"name": "first", "7c436110-ab2a-4bbb-a880-fe41995c9f82:name": "duplicate"}`,
		`{"40A0DDD2-77F8-4392-B4A3-1E7304206516:": "empty name"}`,
		`{"00000000-0000-0000-0000-000000000000:name": "unsupported namespace"}`,
	} {
		value, err := starlark.Eval(&starlark.Thread{Name: "nvram-test"}, "nvram.star", expression, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := darwinARM64NVRAM(value); err == nil {
			t.Fatalf("invalid nvram expression accepted: %s", expression)
		}
	}
}
