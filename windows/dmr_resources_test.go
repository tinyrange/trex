package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
	"testing"
)

func TestDMRResourceBuiltins(t *testing.T) {
	globals := Builtins()
	globals["empty"] = &starfile.Bytes{}
	v, err := starlark.Eval(&starlark.Thread{Name: "missing-file"}, "test.star", `mrm_missing_file_reference("C:/Package", "http://microsoft.com")`, globals)
	if err != nil {
		t.Fatal(err)
	}
	name, err := dmr.ParseLiteralResourceReference(v.(*starfile.Bytes).Data)
	if err != nil || name != `C:\Package\http:\\microsoft.com` {
		t.Fatalf("missing file: %q, %v", name, err)
	}
	for _, description := range []string{"", ", description=mrm_literal_reference('')"} {
		expr := "dmr_package_resources(display_name=mrm_literal_reference('WinUI'), publisher_display_name=mrm_literal_reference('Microsoft'), logo=mrm_index_reference(4)" + description + ")"
		v, err := starlark.Eval(&starlark.Thread{Name: "dmr"}, "test.star", expr, globals)
		if err != nil {
			t.Fatal(err)
		}
		r, err := dmr.ParseResources(v.(*starfile.Bytes).Data)
		want := 3
		if description != "" {
			want = 4
		}
		if err != nil || len(r.Entries) != want || r.Index != 0 {
			t.Fatalf("resources: %+v %v", r, err)
		}
	}
	for _, expr := range []string{
		`mrm_missing_file_reference("C:/Package", "")`,
		"mrm_index_reference(-1)", "mrm_index_reference(2147483648)",
		"dmr_package_resources('raw', 'raw', 'raw')",
		"dmr_package_resources(mrm_literal_reference('a'), mrm_literal_reference('b'), None)",
		"dmr_package_resources(mrm_literal_reference('a'), mrm_literal_reference('b'), mrm_literal_reference('c'), description=empty)",
	} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-dmr"}, "test.star", expr, globals); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
}

func TestDMRTargetPlatformBuiltin(t *testing.T) {
	v, err := starlark.Eval(&starlark.Thread{Name: "platform"}, "test.star", "dmr_target_platform(target_device_family_name=3, minimum_version=123, maximum_version_tested=456)", Builtins())
	if err != nil {
		t.Fatal(err)
	}
	p, err := dmr.ParseTargetPlatform(v.(*starfile.Bytes).Data)
	if err != nil || p.Platform != 3 || p.Value16 != 123 || p.Value24 != 456 {
		t.Fatalf("platform: %+v %v", p, err)
	}
	for _, expr := range []string{"dmr_target_platform(-2,0,0)", "dmr_target_platform(2147483648,0,0)", "dmr_target_platform(0,-1,0)", "dmr_target_platform(target_device_family=3,minimum_version=0,maximum_version_tested=0)"} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-platform"}, "test.star", expr, Builtins()); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
	for _, family := range []int64{-1, 0, 3} {
		v, err := starlark.Call(&starlark.Thread{Name: "platform-enum"}, Builtins()["dmr_target_platform"], starlark.Tuple{starlark.MakeInt64(family), starlark.MakeInt(0), starlark.MakeInt(0)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		p, err := dmr.ParseTargetPlatform(v.(*starfile.Bytes).Data)
		if err != nil || p.Platform != uint32(family) {
			t.Fatalf("enum %d: %+v %v", family, p, err)
		}
	}
}
