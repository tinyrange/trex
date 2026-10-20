package starlarkfrontend

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIInternetCapability(t *testing.T) {
	for _, allowed := range []bool{false, true, false} {
		args := []string{"trex"}
		if allowed {
			args = append(args, "-allow-internet")
		}
		args = append(args, "-")
		var out, errs bytes.Buffer
		code := RunCLI(args, strings.NewReader("def main(args):\n    vmm.switch(internet = True)\n"), &out, &errs)
		if allowed && code != 0 {
			t.Fatal(errs.String())
		}
		if !allowed && (code == 0 || !strings.Contains(errs.String(), "requires trex -allow-internet")) {
			t.Fatalf("missing capability guard: %d %s", code, errs.String())
		}
	}
}
