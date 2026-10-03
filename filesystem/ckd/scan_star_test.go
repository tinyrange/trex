package ckd

import (
	"github.com/tinyrange/trex/auto/adapter"
	"go.starlark.net/starlark"
	"testing"
)

func TestScanBuiltinBoundsAndEOF(t *testing.T) {
	good := image([][]Record{{r(1, nil, []byte("hello"))}, {}})
	for _, tc := range []struct {
		name    string
		data    []byte
		limit   int
		wantErr bool
	}{
		{"complete", good, 2, false}, {"track budget", good, 1, true},
		{"partial cylinder", good[:512+testTrackSize], 2, true},
		{"short track", good[:len(good)-1], 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ScanBuiltin(nil, nil, starlark.Tuple{adapter.File(raw(tc.data)), starlark.MakeInt(tc.limit)}, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("value=%v err=%v", v, err)
			}
			if err == nil {
				n, err := v.(starlark.HasAttrs).Attr("records")
				if err != nil || n.String() != "1" {
					t.Fatal(n, err)
				}
			}
		})
	}
}
