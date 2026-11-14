package szdd

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestInfoRestoresOnlyStoredBasenameCharacter(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement byte
		want        string
	}{
		{"KRNL386.EX_", 'E', "KRNL386.EXE"},
		{"LAYOUT.IN_", 'f', "LAYOUT.INf"},
		{"KEEP.EX_", 0, "KEEP.EX_"},
		{"NOEXT", 'E', "NOEXT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := szddTestFile(1, []byte{1, 'x'})
			f.Data[9] = tc.replacement
			result, err := InfoBuiltin(nil, nil, starlark.Tuple{f, starlark.String(tc.name)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			attrs := result.(starlark.HasAttrs)
			name, err := attrs.Attr("name")
			if err != nil || name != starlark.String(tc.want) {
				t.Fatalf("name=%v err=%v", name, err)
			}
			decoded, err := attrs.Attr("file")
			if err != nil {
				t.Fatal(err)
			}
			data, err := starfile.ReadAll(decoded.(File))
			if err != nil || string(data) != "x" {
				t.Fatalf("data=%q err=%v", data, err)
			}
		})
	}
}

func TestInfoRejectsUnsafeNamesAndBounds(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../X.EX_", `C:\X.EX_`, "a\x00b"} {
		if _, err := InfoBuiltin(nil, nil, starlark.Tuple{szddTestFile(1, []byte{1, 'x'}), starlark.String(name)}, nil); err == nil {
			t.Fatalf("accepted name %q", name)
		}
	}
	for _, c := range []byte{'/', '\\', ':', 0x1f, 0xff} {
		f := szddTestFile(1, []byte{1, 'x'})
		f.Data[9] = c
		if _, err := InfoBuiltin(nil, nil, starlark.Tuple{f, starlark.String("X.EX_")}, nil); err == nil {
			t.Fatalf("accepted replacement %#x", c)
		}
	}
	if _, err := InfoBuiltin(nil, nil, starlark.Tuple{szddTestFile(100, []byte{1, 'x'}), starlark.String("X.EX_"), starlark.MakeInt(32)}, nil); err == nil {
		t.Fatal("accepted oversized decoded stream")
	}
	legacy := &starfile.Bytes{Data: append([]byte{'S', 'Z', ' ', 0x88, 0xf0, 0x27, 0x33, 0xd1, 1, 0, 0, 0}, 1, 'x')}
	result, err := InfoBuiltin(nil, nil, starlark.Tuple{legacy, starlark.String("X.EX_")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := result.(starlark.HasAttrs).Attr("name")
	if name != starlark.String("X.EX_") {
		t.Fatalf("legacy invented a name: %v", name)
	}
}
