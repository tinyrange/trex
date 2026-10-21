package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestMakeIncrementalPatternAndOrderOnly(t *testing.T) {
	m := testFS(t)
	for name, contents := range map[string]string{
		"/Makefile": "include vars.mk\n.PHONY: all\nall: result\nresult: a.out b.out | stamp\n\t@cat $^ > $@\n%.out: %.in\n\t@printf '%s:' '$(PREFIX)' > $@; cat $< >> $@\nstamp:\n\t@touch $@\n",
		"/vars.mk":  "PREFIX = $(LATER)\nLATER = built\n", "/a.in": "a\n", "/b.in": "b\n",
	} {
		if e := m.WriteFile(name, []byte(contents), 0644); e != nil {
			t.Fatal(e)
		}
	}
	var out, diagnostic bytes.Buffer
	run := func(source string) {
		t.Helper()
		r, e := Run(context.Background(), strings.NewReader(source), "test", Config{FS: m, Stdout: &out, Stderr: &diagnostic})
		if e != nil || r.Status != 0 {
			t.Fatalf("%+v %v %s", r, e, diagnostic.String())
		}
	}
	run("make")
	data, _ := m.ReadFile("/result")
	if string(data) != "built:a\nbuilt:b\n" {
		t.Fatal(string(data))
	}
	first, _ := m.Stat("/result")
	run("touch stamp; make")
	second, _ := m.Stat("/result")
	if !second.ModTime().Equal(first.ModTime()) {
		t.Fatal("order-only prerequisite rebuilt result")
	}
	run("printf 'new\\n' > a.in; make PREFIX=override")
	data, _ = m.ReadFile("/result")
	if string(data) != "override:new\nbuilt:b\n" {
		t.Fatal(string(data))
	}
}

func TestMakeRecipeIsolationAndFailure(t *testing.T) {
	m := testFS(t)
	m.WriteFile("/Makefile", []byte("all:\n\t@x=local\n\t@test -z \"$$x\"\n\t@false\n\t@echo wrong > result\n"), 0644)
	r, e := Run(context.Background(), strings.NewReader("make"), "test", Config{FS: m})
	if e != nil || r.Status != 2 {
		t.Fatalf("%+v %v", r, e)
	}
	if _, e = m.Stat("/result"); !errorsIsNotExist(e) {
		t.Fatal("executed after failure", e)
	}
}
func TestMakeRecursiveVariableBudget(t *testing.T) {
	m := testFS(t)
	m.WriteFile("/Makefile", []byte("x = $(x)\nall:\n\t@echo $(x)\n"), 0644)
	_, e := Run(context.Background(), strings.NewReader("make"), "test", Config{FS: m})
	if e == nil || !strings.Contains(e.Error(), "nesting budget") {
		t.Fatal(e)
	}
}
func TestMakeAutomaticNestedVariablesAndStdin(t *testing.T) {
	m := testFS(t)
	source := "printf '%s\\n' 'V = 0' 'quiet_0 = quiet' 'quiet_ = loud' 'all:' '\t@echo $(quiet_$(V)) $@; echo $$HOME' | make -f - V=0"
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader(source), "test", Config{FS: m, Env: map[string]string{"HOME": "/virtual"}, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "quiet all\n/virtual\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
}
