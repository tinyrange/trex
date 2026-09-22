package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestPatchINIMergesCaseInsensitiveSectionsAndPreservesLiterals(t *testing.T) {
	source := &starfile.Bytes{Data: []byte("; keep\r\n[Extensions]\r\ntxt=notepad.exe ^.txt\r\ndoc=old\r\n[Fonts]\r\nArial=ARIAL.FOT\r\n[extensions]\r\nDOC=duplicate\r\n")}
	settings := starlark.NewDict(1)
	settings.SetKey(starlark.String("doc"), starlark.String(`C:\WORD\WINWORD.EXE ^.doc`))
	settings.SetKey(starlark.String("quoted"), starlark.String(`"one,two",three`))
	changes := starlark.NewDict(1)
	changes.SetKey(starlark.String("EXTENSIONS"), settings)
	result, err := patchINIBuiltin(nil, nil, starlark.Tuple{source, changes}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := starfile.ReadAll(result.(starfile.File))
	s := string(b)
	for _, want := range []string{"; keep\r\n", "txt=notepad.exe ^.txt", `doc=C:\WORD\WINWORD.EXE ^.doc`, `quoted="one,two",three`, "Arial=ARIAL.FOT"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %q", want, s)
		}
	}
	if strings.Contains(s, "old") || strings.Contains(s, "duplicate") || strings.Count(s, "doc=") != 1 {
		t.Fatal(s)
	}
}
