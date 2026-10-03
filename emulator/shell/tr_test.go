package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestTRByteTransforms(t *testing.T) {
	for _, tc := range []struct{ source, input, want string }{
		{`tr 'abcdefghijklmnopqrstuvwxyz ' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_'`, "unsigned long\n", "UNSIGNED_LONG\n"},
		{`tr '[:lower:]' '[:upper:]'`, "aZ09\n", "AZ09\n"},
		{`tr -d '\000\015'`, "a\x00b\rc\n", "abc\n"},
		{`tr -cs 'a-z' '_'`, "a01!!b---c", "a_b_c"},
		{`tr -ds '0-9' 'a-z'`, "a12aab34bb", "ab"},
		{`tr -s a`, strings.Repeat("a", 32770) + "b", "ab"},
		{`tr ab X`, "abc", "XXc"},
		{`tr X '\015'`, "X", "\r"},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.source), "test", Config{FS: testFS(t), Stdin: strings.NewReader(tc.input), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != tc.want {
			t.Fatalf("%s: %+v %v %q", tc.source, r, e, out.String())
		}
	}
}
