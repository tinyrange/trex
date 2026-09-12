package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestBatchPlanPreservesFlowAndRuntimeSources(t *testing.T) {
	media := starlark.NewDict(1)
	_ = media.SetKey(starlark.String("1/DATA.TXT"), &starfile.Bytes{Data: []byte("data")})
	script := &starfile.Bytes{Data: []byte("if exist %TARGET% goto done\ncopy a:\\DATA.TXT %TARGET%\ncopy %GENERATED% %TARGET%\n:done\n")}
	v, err := batchPlanBuiltin(nil, nil, starlark.Tuple{script, media}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := v.(*starlark.Dict)
	if acmeGet(p, "files").(*starlark.List).Len() != 1 || acmeGet(p, "actions").(*starlark.List).Len() != 4 || acmeGet(p, "runtime_dependencies").(*starlark.List).Len() != 3 || acmeGet(p, "unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(p)
	}
	if expandBatch("%System%\\x %1", map[string]string{"system": `C:\Windows\System`, "1": "arg"}) != `C:\Windows\System\x arg` {
		t.Fatal("batch variable expansion")
	}
}

func TestPressPlanRetainsCommandFileConstructionFailure(t *testing.T) {
	parsed, err := parseINF("[Setup]\nCodeDir=Files\nDestDir=C:\\Book\nFilesCompressed=No\nCommandFile=setup.cmd\n")
	if err != nil {
		t.Fatal(err)
	}
	media := starlark.NewDict(2)
	_ = media.SetKey(starlark.String("Files/Chapter1/example.txt"), &starfile.Bytes{Data: []byte("example")})
	_ = media.SetKey(starlark.String("setup.cmd"), &starfile.Bytes{Data: []byte("Copy %startdir%missing.dll %System%\\missing.dll")})
	v, err := pressSetupPlanBuiltin(nil, nil, starlark.Tuple{&infFile{json: parsed}, media}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := v.(*starlark.Dict)
	if acmeGet(p, "unresolved").(*starlark.List).Len() != 1 {
		t.Fatal(p)
	}
	row := acmeGet(p, "files").(*starlark.List).Index(0).(*starlark.Dict)
	if acmeText(row, "destination") != `C:\Book\Chapter1\example.txt` {
		t.Fatal(row)
	}
}
