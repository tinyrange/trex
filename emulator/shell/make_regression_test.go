package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestMakeStampRecipeDoesNotForceDependents(t *testing.T) {
	m := testFS(t)
	for _, name := range []string{"stamp", "version", "manual"} {
		m.WriteFile("/"+name, []byte(name), 0644)
	}
	m.Touch("/stamp")
	m.WriteFile("/Makefile", []byte("all: manual\nmanual: version\n\t@echo wrong > manual\nversion: stamp\n\t@test -f version || touch version\n"), 0644)
	r, e := Run(context.Background(), strings.NewReader("make"), "test", Config{FS: m})
	data, _ := m.ReadFile("/manual")
	if e != nil || r.Status != 0 || string(data) != "manual" {
		t.Fatalf("%+v %v %q", r, e, data)
	}
}
func TestMakeDefineStaticAndNestedConditional(t *testing.T) {
	m := testFS(t)
	m.WriteFile("/Makefile", []byte("EMPTY =\nEMPTY ?= wrong\nifeq ($(word 2,a b),b)\ndefine message\n$(EMPTY)$(NAME)\nendef\nendif\nNAME = ok\nall: dir/one\ndir/one: dir/%: %.in\n\t@mkdir -p $(@D); printf '%s:%s:%s' '$(message)' '$(@F)' '$<' > $@\ninline: ; @echo $@\n"), 0644)
	m.WriteFile("/one.in", nil, 0644)
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader("make; make inline"), "test", Config{FS: m, Stdout: &out})
	data, _ := m.ReadFile("/dir/one")
	if e != nil || r.Status != 0 || string(data) != "ok:one:one.in" || out.String() != "inline\n" {
		t.Fatalf("%+v %v %q %q", r, e, data, out.String())
	}
}
func TestMakeShellCaptureDescendantsAndLimit(t *testing.T) {
	m := testFS(t)
	m.WriteFile("/Makefile", []byte("X := $(shell { printf captured; } &)\nall:\n\t@echo $(X)\n"), 0644)
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader("make"), "test", Config{FS: m, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "captured\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
	m.WriteFile("/Makefile", []byte("X := $(shell cat data)\nall:\n\t@echo $(X)\n"), 0644)
	m.WriteFile("/data", []byte(strings.Repeat("x", 512)), 0644)
	_, e = Run(context.Background(), strings.NewReader("make"), "test", Config{FS: m, MaxSubstitutionBytes: 256})
	if e == nil || !strings.Contains(e.Error(), "budget") {
		t.Fatal(e)
	}
}
func TestImportedModTimeAdvancesLogicalClock(t *testing.T) {
	m := testFS(t)
	m.WriteFile("/imported", nil, 0644)
	stamp := time.Unix(1650000000, 0).UTC()
	if e := m.SetModTime("/imported", stamp); e != nil {
		t.Fatal(e)
	}
	m.WriteFile("/generated", nil, 0644)
	old, _ := m.Stat("/imported")
	newer, _ := m.Stat("/generated")
	if !old.ModTime().Equal(stamp) || !newer.ModTime().After(stamp) {
		t.Fatal(old.ModTime(), newer.ModTime())
	}
}
func TestInstallDirectoryModeAndLongListing(t *testing.T) {
	m := testFS(t)
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader("umask 077; mkdir -m0755 -p a/b; mkdir -m0700 -p a/b; ls -ld a/b"), "test", Config{FS: m, Stdout: &out})
	a, _ := m.Stat("/a")
	b, _ := m.Stat("/a/b")
	if e != nil || r.Status != 0 || a.Mode().Perm() != 0700 || b.Mode().Perm() != 0755 || !strings.HasPrefix(out.String(), "drwxr-xr-x ") {
		t.Fatalf("%+v %v %q %o %o", r, e, out.String(), a.Mode(), b.Mode())
	}
}
func TestSedReadFileOrdering(t *testing.T) {
	m := testFS(t)
	m.WriteFile("/insert", []byte("added\n"), 0644)
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader("printf 'one\\ntwo\\n' | sed -e '1r insert' -e '1d'"), "test", Config{FS: m, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "added\ntwo\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
}
