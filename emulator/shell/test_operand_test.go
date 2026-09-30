package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestTestMissingExpandedOperand(t *testing.T) {
	var out, errout bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader(`unset x; test $x != none; printf '%s:' "$?"; if test $x = yes; then exit 99; fi; printf continued`), "test", Config{FS: testFS(t), Stdout: &out, Stderr: &errout})
	if e != nil || r.Status != 0 || out.String() != "2:continued" || !strings.Contains(errout.String(), "missing operand") {
		t.Fatalf("%+v %v %q %q", r, e, out.String(), errout.String())
	}
}
