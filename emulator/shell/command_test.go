package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCommandDiscoveryAndBypass(t *testing.T) {
	m := testFS(t)
	if err := m.WriteFile("/tool", []byte("#!/bin/sh\nprintf external"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteFile("/data", []byte("not executable"), 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	script := `tool() { printf function; }
 command -v tool
 tool
 command tool
 command -v printf
 command -v /tool
 if command -v data absent; then exit 99; fi
 unset -f tool
 command -v tool
 command false
 printf ':%s' "$?"
 `
	r, e := Run(context.Background(), strings.NewReader(script), "test", Config{FS: m, Env: map[string]string{"PATH": "/"}, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "tool\nfunctionexternalprintf\n/tool\n/tool\n:1" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
}
