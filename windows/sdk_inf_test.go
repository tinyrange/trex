package windows

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestSDKInfDecodesNumberedFloppySource(t *testing.T) {
	parsed, err := parseINF("[data]\ndefsdkdir=C:\\SDK\ndefincdir=INCLUDE\n[inc]\n1:inc/example.h\n")
	if err != nil {
		t.Fatal(err)
	}
	compressed := make([]byte, 14)
	copy(compressed, []byte{'S', 'Z', 'D', 'D', 0x88, 0xf0, 0x27, 0x33, 'A', 'h'})
	binary.LittleEndian.PutUint32(compressed[10:], 3)
	compressed = append(compressed, 7, 'a', 'b', 'c')
	media := starlark.NewDict(1)
	_ = media.SetKey(starlark.String("1/INC/EXAMPLE.H_"), &starfile.Bytes{Data: compressed})
	result, err := sdkInfPlanBuiltin(nil, nil, starlark.Tuple{&infFile{json: parsed}, media}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := result.(*starlark.Dict)
	if acmeGet(plan, "unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(plan)
	}
	files := acmeGet(plan, "files").(*starlark.List)
	if files.Len() != 1 {
		t.Fatal(files)
	}
	row := files.Index(0).(*starlark.Dict)
	if acmeText(row, "destination") != `C:\SDK\INCLUDE\example.h` {
		t.Fatal(row)
	}
	bytes, err := starfile.ReadAll(acmeGet(row, "file").(starfile.File))
	if err != nil || string(bytes) != "abc" {
		t.Fatal(string(bytes), err)
	}
}
func TestSDKInfRejectsSectionCycle(t *testing.T) {
	parsed, err := parseINF("[data]\ndefsdkdir=C:\\SDK\ndefsamplesdir=SAMPLES\n[samples]\n0:samples\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = sdkInfPlanBuiltin(nil, nil, starlark.Tuple{&infFile{json: parsed}, starlark.NewDict(0)}, nil)
	if err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Fatal(err)
	}
}

func TestSDKLogicalDiskDirectoryAndNestedSample(t *testing.T) {
	parsed, err := parseINF("[data]\ndefrestoolsdir=C:\\WINDEV\ndefincdir=INCLUDE\ndefsamplesdir=SAMPLES\n[disks]\nA=.\\inc,Development,\\inc\\marker.h\nE=.,Samples,\\demo\\sample.c\n[inc]\nA:marker.h\n[samples]\nE:demo\n[demo]\nE:demo/sample.c\n")
	if err != nil {
		t.Fatal(err)
	}
	media := starlark.NewDict(2)
	_ = media.SetKey(starlark.String("3/INC/MARKER.H"), &starfile.Bytes{Data: []byte("header")})
	_ = media.SetKey(starlark.String("5/DEMO/SAMPLE.C"), &starfile.Bytes{Data: []byte("sample")})
	v, err := sdkInfPlanBuiltin(nil, nil, starlark.Tuple{&infFile{json: parsed}, media}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := v.(*starlark.Dict)
	if acmeGet(p, "unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(p)
	}
	files := acmeGet(p, "files").(*starlark.List)
	if files.Len() != 2 {
		t.Fatal(files)
	}
	if acmeText(files.Index(1).(*starlark.Dict), "destination") != `C:\WINDEV\SAMPLES\demo\sample.c` {
		t.Fatal(files)
	}
}
