package windows

import (
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
	"testing"
)

func TestCDFBuiltinContract(t *testing.T) {
	// Exercise registration as well as type/range checks at the language boundary.
	env := Builtins()
	source := `d = {"flags":0,"format":b"0123456789abcdef","root":0xffffffff,
 "auxiliary_root":0xffffffff,"strings":[0],"identities":[],"appids":[],
 "guids":[],"blobs":[(2,b"name")]}
encoded = cdf_encode(d)
decoded = cdf_decode(encoded)
if decoded != d:
 fail("CDF fields did not survive language boundary")
decoded["blobs"][0] = (2,b"other")
if cdf_decode(cdf_encode(decoded))["blobs"][0][1] != b"other":
 fail("CDF edit lost")
`
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{TopLevelControl: true}, &starlark.Thread{Name: "cdf-contract"}, "cdf.star", source, env)
	if err != nil {
		t.Fatal(err)
	}
	d := starlark.NewDict(9)
	for _, item := range globals["decoded"].(*starlark.Dict).Items() {
		if err := d.SetKey(item[0], item[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []starlark.Value{starlark.MakeInt(-1), starlark.MakeUint64(1 << 32), starlark.String("0")} {
		if err := d.SetKey(starlark.String("root"), bad); err != nil {
			t.Fatal(err)
		}
		if _, err := starlark.Call(&starlark.Thread{}, env["cdf_encode"], starlark.Tuple{d}, nil); err == nil {
			t.Fatal("accepted invalid root", bad)
		}
	}
}
