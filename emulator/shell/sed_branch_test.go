package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSedBranches(t *testing.T) {
	for _, tc := range []struct{ script, input, want string }{
		{`sed ':loop;s/aa/a/;t loop'`, "aaaa\nbb\n", "a\nbb\n"},
		{`sed 's/x/x/;t next;b;:next;s/x/y/;t end;s/y/z/;:end'`, "x\na\n", "y\na\n"},
		{`sed 's/x/x/;t clear;:clear;t bad;b;:bad;s/x/bad/'`, "x\n", "x\n"},
		{`sed '/^skip/b end;s/a/z/;:end'`, "skip a\na\n", "skip a\nz\n"},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.script), "test", Config{FS: testFS(t), Stdin: strings.NewReader(tc.input), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != tc.want {
			t.Fatalf("%s: %+v %v %q", tc.script, r, e, out.String())
		}
	}
}
func TestSedBranchBudget(t *testing.T) {
	_, e := Run(context.Background(), strings.NewReader(`printf x | sed ':again;b again'`), "test", Config{FS: testFS(t), MaxSteps: 100})
	if e == nil {
		t.Fatal("unbounded branch")
	}
}
