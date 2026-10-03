package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestAWKVirtualIO(t *testing.T) {
	m := testFS(t)
	m.WriteFile("/input", []byte("a:2\nb:3\n"), 0644)
	m.WriteFile("/program", []byte(`{sum += $2} END { print prefix sum > "result"; close("result"); getline line < "result"; print line; print ENVIRON["VIRTUAL"] }`), 0644)
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader(`umask 077; awk -F: -v prefix=total: -f /program /input`), "test", Config{FS: m, Env: map[string]string{"VIRTUAL": "only"}, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "total:5\nonly\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
	st, e := m.Stat("/result")
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("%v %v", st, e)
	}
}
func TestAWKCannotExecuteHostCommands(t *testing.T) {
	for _, program := range []string{`BEGIN { system("not-a-host-command") }`, `BEGIN { "not-a-host-command" | getline }`, `BEGIN { print "x" | "not-a-host-command" }`} {
		_, e := Run(context.Background(), strings.NewReader("awk '"+program+"'"), "test", Config{FS: testFS(t)})
		if e == nil || !strings.Contains(e.Error(), "NoExec") {
			t.Fatalf("%s: %v", program, e)
		}
	}
}
func TestAWKTimeout(t *testing.T) {
	_, e := Run(context.Background(), strings.NewReader(`awk 'BEGIN { for (;;) {} }'`), "test", Config{FS: testFS(t), MaxAWKTime: time.Millisecond})
	if e == nil || !strings.Contains(e.Error(), "deadline exceeded") {
		t.Fatal(e)
	}
}
