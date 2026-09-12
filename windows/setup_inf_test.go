package windows

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestSetupCatalogueJoinsFloppyFragments(t *testing.T) {
	input := "[data]\ndefdir=C:\\PPT\n[help]\ndestination=Help\n1,help.pp$,4\n[option]*W\n#help\n"
	v, err := setupInfBuiltin(nil, nil, starlark.Tuple{&starfile.Bytes{Data: []byte(input)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 14)
	copy(header, []byte{'K', 'W', 'A', 'J', 0x88, 0xf0, 0x27, 0xd1})
	binary.LittleEndian.PutUint16(header[10:], 14)
	media := starlark.NewDict(2)
	_ = media.SetKey(starlark.String("1/HELP.PP0"), &starfile.Bytes{Data: append(header, 'a', 'b')})
	_ = media.SetKey(starlark.String("2/HELP.PP1"), &starfile.Bytes{Data: []byte("cd")})
	p, err := v.(*setupINF).cataloguePlan(nil, nil, starlark.Tuple{media}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := p.(*starlark.Dict)
	if acmeGet(d, "unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(d)
	}
	file := acmeGet(acmeGet(d, "files").(*starlark.List).Index(0).(*starlark.Dict), "file").(starfile.File)
	data, err := starfile.ReadAll(file)
	if err != nil || string(data) != "abcd" {
		t.Fatal(string(data), err)
	}
	if _, found := v.(*setupINF).sections["option*w"]; !found {
		t.Fatal("OS-specific declaration lost")
	}
}

func TestSetupINFStaticBranchesAndRuntimeDependencies(t *testing.T) {
	input := "[Install]\nifstr(i) $(QUERY) == yes\nAddSectionFilesToCopyList files media C:\\Yes\nelse\nAddSectionFilesToCopyList FILES media $(TARGET)\nendif\nLibraryProcedure TARGET, dll, FindPath\nForListDo $(LIST)\nDo Other\nEndForListDo\n[Files]\n1,a.txt,NOLOG\n"
	v, err := setupInfBuiltin(nil, nil, starlark.Tuple{&starfile.Bytes{Data: []byte(input)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	media := starlark.NewDict(1)
	_ = media.SetKey(starlark.String("media/a.txt"), &starfile.Bytes{Data: []byte("a")})
	p, err := v.(*setupINF).plan(nil, nil, starlark.Tuple{starlark.String("INSTALL"), media}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := p.(*starlark.Dict)
	if acmeGet(d, "files").(*starlark.List).Len() != 2 {
		t.Fatal(d)
	}
	if acmeGet(d, "runtime_dependencies").(*starlark.List).Len() != 3 {
		t.Fatal(d)
	}
	if acmeGet(d, "unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(d)
	}
	if acmeGet(d, "script") != v {
		t.Fatal("missing deferred loop body")
	}
}

func TestSetupINFMissingPayloadIsNotRuntimeDependency(t *testing.T) {
	s := &setupINF{sections: map[string][]setupLine{
		"install": {{text: "AddSectionFilesToCopyList Files media C:\\App", line: 1}},
		"files":   {{text: "1,missing.txt,NOLOG", line: 2}},
	}}
	v, err := s.plan(nil, nil, starlark.Tuple{starlark.String("Install"), starlark.NewDict(0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if acmeGet(v.(*starlark.Dict), "unresolved").(*starlark.List).Len() != 1 {
		t.Fatal(v)
	}
}

func TestSetupINFMatchesISOExtensionlessNames(t *testing.T) {
	s := &setupINF{sections: map[string][]setupLine{"install": {{text: `AddSectionFilesToCopyList Files media C:\App`}}, "files": {{text: "1,MAKEFILE,NOLOG"}}}}
	media := starlark.NewDict(1)
	_ = media.SetKey(starlark.String("media/MAKEFILE."), &starfile.Bytes{Data: []byte("all:")})
	v, err := s.plan(nil, nil, starlark.Tuple{starlark.String("Install"), media}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := v.(*starlark.Dict)
	if acmeGet(p, "unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(p)
	}
	if acmeText(acmeGet(p, "files").(*starlark.List).Index(0).(*starlark.Dict), "destination") != `C:\App\MAKEFILE` {
		t.Fatal(p)
	}
}
