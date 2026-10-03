package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSedSpacesAndBlocks(t *testing.T) {
	for _, tc := range []struct{ script, input, want string }{
		{`sed 'h;s/a/b/;G'`, "a\n", "b\na\n"},
		{`sed -n 'h;s/a/b/;p;g;p'`, "a\n", "b\na\n"},
		{`sed '/^a/{N;s/\n/:/;}'`, "a\nb\nc\n", "a:b\nc\n"},
		{`sed -n 'n;p'`, "a\nb\nc\nd\n", "b\nd\n"},
		{`sed 'N;s/\n/:/'`, "a\nb\nc", "a:b\nc"},
		{`sed '/a/{/b/{s/a/x/;};}'`, "a\nab\nc\n", "a\nxb\nc\n"},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.script), "test", Config{FS: testFS(t), Stdin: strings.NewReader(tc.input), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != tc.want {
			t.Fatalf("%s: %+v %v %q", tc.script, r, e, out.String())
		}
	}
}
