package star

import (
	"bytes"
	"testing"

	"github.com/tinyrange/trex/boot/darwin"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestAppleTreeStarlarkEncodeRecordsAndDictionaries(t *testing.T) {
	original := darwin.Node{Properties: map[string][]byte{"name": darwin.CString("root"), "template": []byte("binding")}, PropertyFlags: map[string]uint32{"template": 1 << 31}, Children: []darwin.Node{{Properties: map[string][]byte{"name": darwin.CString("child")}}}}
	b, _ := original.Encode()
	decoded, err := appleDeviceTreeBuiltin(nil, nil, starlark.Tuple{starfile.NewReader("DT", bytes.NewReader(b))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mapping := range []bool{false, true} {
		node := decoded
		if mapping {
			d := starlark.NewDict(3)
			for _, key := range []string{"properties", "property_flags", "children"} {
				v, _ := decoded.(starlark.HasAttrs).Attr(key)
				d.SetKey(starlark.String(key), v)
			}
			node = d
		}
		encoded, err := encodeAppleDeviceTreeBuiltin(nil, nil, starlark.Tuple{node}, nil)
		if err != nil {
			t.Fatal(err)
		}
		r := encoded.(storage.Reader)
		got := make([]byte, r.Size())
		r.ReadAt(got, 0)
		if !bytes.Equal(got, b) {
			t.Fatal("tree changed")
		}
	}
}
