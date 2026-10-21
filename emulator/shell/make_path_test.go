package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestMakeLeadingDotTargetIdentity(t *testing.T) {
	m := testFS(t)
	source := ".PHONY: ./all ./force\nall: ./result result force\n./result: ./input\n\t@cat $< > $@\ninput:\n\t@echo data > $@\nforce:\n\t@echo force\n"
	if err := m.WriteFile("/Makefile", []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader("make ./all && make all"), "test", Config{FS: m, Stdout: &out, Stderr: &out})
	if e != nil || r.Status != 0 || out.String() != "force\nforce\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
	data, e := m.ReadFile("/result")
	if e != nil || string(data) != "data\n" {
		t.Fatalf("%q %v", data, e)
	}
}
