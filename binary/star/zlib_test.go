package star

import (
	"bytes"
	"compress/zlib"
	"testing"

	"go.starlark.net/starlark"
)

func TestZlibBoundaries(t *testing.T) {
	var packed bytes.Buffer
	w := zlib.NewWriter(&packed)
	w.Write([]byte("manifest"))
	w.Close()
	valid := packed.Bytes()
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-1] ^= 1
	for _, tc := range []struct {
		name    string
		data    []byte
		maximum int
		ok      bool
	}{
		{"exact", valid, 8, true},
		{"short limit", valid, 7, false},
		{"checksum", corrupt, 8, false},
		{"truncated", valid[:len(valid)-1], 8, false},
		{"trailing", append(bytes.Clone(valid), 0), 8, false},
		{"negative", valid, -1, false},
		{"excessive", valid, 513 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := binaryZlibBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(tc.data), starlark.MakeInt(tc.maximum)}, nil)
			if (err == nil) != tc.ok {
				t.Fatalf("value=%v err=%v", v, err)
			}
			if tc.ok && v != starlark.Bytes("manifest") {
				t.Fatalf("got %v", v)
			}
		})
	}
}
