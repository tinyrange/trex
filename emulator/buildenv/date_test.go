package buildenv

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/shell"
	"testing"
	"time"
)

func TestVirtualDate(t *testing.T) {
	env := &Environment{Now: func() time.Time { return time.Date(2024, 2, 29, 23, 7, 9, 0, time.FixedZone("other", 3600)) }}
	var out bytes.Buffer
	status, e := env.date(shell.Invocation{Args: []string{"date", "+%Y %j %H %M %S %F %u %%"}, Env: map[string]string{"TZ": "GMT"}, Stdout: &out})
	if e != nil || status != 0 || out.String() != "2024 060 22 07 09 2024-02-29 4 %\n" {
		t.Fatalf("%d %v %q", status, e, out.String())
	}
	if _, e = env.date(shell.Invocation{Args: []string{"date", "+%Q"}, Stdout: &out}); e == nil {
		t.Fatal("unsupported directive accepted")
	}
	if _, e = env.date(shell.Invocation{Args: []string{"date"}, Env: map[string]string{"TZ": "unknown"}, Stdout: &out}); e == nil {
		t.Fatal("unknown timezone accepted")
	}
}
