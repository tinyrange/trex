package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestMetadataUtilities(t *testing.T) {
	m := testFS(t)
	if e := m.WriteFile("/old", []byte("keep"), 0644); e != nil {
		t.Fatal(e)
	}
	before, _ := m.Stat("/old")
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader(`umask 077; touch old new; chmod +x old; chmod g=u,o= new; touch -c absent; mkdir dir; chmod a=rx dir; printf 'b\na\nb\n' | sort -ur`), "test", Config{FS: m, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "b\na\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
	after, _ := m.Stat("/old")
	data, _ := m.ReadFile("/old")
	if !after.ModTime().After(before.ModTime()) || after.Mode().Perm() != 0744 || string(data) != "keep" {
		t.Fatalf("%v %q", after, data)
	}
	info, _ := m.Stat("/new")
	if info.Mode().Perm() != 0660 {
		t.Fatal(info.Mode())
	}
	info, _ = m.Stat("/dir")
	if !info.IsDir() || info.Mode().Perm() != 0555 {
		t.Fatal(info)
	}
	if _, e := m.Stat("/absent"); e == nil {
		t.Fatal("touch -c created file")
	}
}
