package windows

import (
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestRegistry31NativeTreeAndInternedStrings(t *testing.T) {
	data, err := buildRegistry31(map[string]string{`Example\shell\open\command`: `C:\APP\APP.EXE %1`, ".ex": "Example", "Example": "Example"})
	if err != nil {
		t.Fatal(err)
	}
	u16 := func(off int) int { return int(binary.LittleEndian.Uint16(data[off:])) }
	u32 := func(off int) int { return int(binary.LittleEndian.Uint32(data[off:])) }
	if string(data[:8]) != "SHCC3.10" || u32(8) != 32 || u32(12) != 32 || u16(28) != 1 {
		t.Fatal("invalid SHCC header")
	}
	count, textoff := u32(16), u32(20)
	if textoff != 32+8*count || len(data) != textoff+u32(24) {
		t.Fatal("invalid table bounds")
	}
	str := func(index int) string {
		t.Helper()
		if index < 2 || index >= count {
			t.Fatalf("bad string index %d", index)
		}
		off := 32 + 8*index
		start, n := u16(off+6), u16(off+4)
		if start < 2 || textoff+start+n > len(data) || u16(textoff+start-2) != 2*index+1 {
			t.Fatal("invalid string allocation")
		}
		return string(data[textoff+start : textoff+start+n])
	}
	got := map[string]string{}
	var visit func(int, string)
	visit = func(idx int, parent string) {
		for idx != 0 {
			off := 32 + 8*idx
			name := str(u16(off + 4))
			key := name
			if parent != "" {
				key = parent + `\` + name
			}
			if val := u16(off + 6); val != 0 {
				got[key] = str(val)
			}
			visit(u16(off+2), key)
			idx = u16(off)
		}
	}
	visit(u16(34), "")
	if got[`.classes\Example\shell\open\command`] != `C:\APP\APP.EXE %1` || got[`.classes\.ex`] != "Example" {
		t.Fatal(got)
	}
	// The hash bucket is a circular sentinel chain, including shared strings.
	seen := map[int]bool{}
	for idx := u16(40); idx != 1; idx = u16(32 + 8*idx) {
		if seen[idx] || idx >= count {
			t.Fatal("invalid hash chain")
		}
		seen[idx] = true
		str(idx)
	}
}

func TestRegistry31SourceCommentsAndOverride(t *testing.T) {
	source := &starfile.Bytes{Data: []byte("REGEDIT\nALL LINES NOT STARTING WITH HKEY_CLASSES_ROOT ARE COMMENTS\nHKEY_CLASSES_ROOT\\Example = old\n")}
	entries := starlark.NewDict(1)
	entries.SetKey(starlark.String("Example"), starlark.String("new"))
	value, err := registry31Builtin(nil, nil, starlark.Tuple{entries}, []starlark.Tuple{{starlark.String("sources"), starlark.NewList([]starlark.Value{source})}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := starfile.ReadAll(value.(starfile.File))
	if !strings.Contains(string(b), "new") || strings.Contains(string(b), "old") {
		t.Fatal("source override lost")
	}
}

func TestRegistry31RejectsUnrepresentableData(t *testing.T) {
	for _, values := range []map[string]string{{"": "x"}, {`bad\\path`: "x"}, {"x": strings.Repeat("x", 65536)}, {"x": "\x00"}} {
		if _, err := buildRegistry31(values); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
