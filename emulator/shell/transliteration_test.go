package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSedTransliteration(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`printf 'sys/types.h\n' | sed 'y%abcdefghijklmnopqrstuvwxyz./%ABCDEFGHIJKLMNOPQRSTUVWXYZ__%'`, "SYS_TYPES_H\n"},
		{`printf 'ab\ncd\n' | sed '1y/ab/ba/;2y/cd/XY/'`, "ba\nXY\n"},
		{`printf 'a/b' | sed 'y/a\/b/XYZ/'`, "XYZ"},
		{`printf 'a' | sed 'y/a/\n/'`, "\n"},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.source), "test", Config{FS: testFS(t), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != tc.want {
			t.Fatalf("%s: %+v %v %q", tc.source, r, e, out.String())
		}
	}
	for _, source := range []string{`sed 'y/a/bc/'`, `sed 'y/a/b'`} {
		_, e := Run(context.Background(), strings.NewReader(source), "test", Config{FS: testFS(t)})
		if e == nil {
			t.Fatal(source)
		}
	}
}
