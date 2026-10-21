package shell

import (
	"bytes"
	"context"
	"io/fs"
	"strings"
	"testing"
)

func TestUmaskCreationAndIsolation(t *testing.T) {
	m := testFS(t)
	if err := m.WriteFile("/executable", []byte("data"), 0755); err != nil {
		t.Fatal(err)
	}
	source := `umask; umask 077; : >private; mkdir secure; cp executable copy; (umask 002; : >child); sh -c ': >inherited'; { umask 027; : >background; } & wait; : >parent; umask 000; : >private; cp executable copy; : >public; mkdir shared; umask -S`
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader(source), "test", Config{FS: m, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "0022\nu=rwx,g=rwx,o=rwx\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
	for name, want := range map[string]fs.FileMode{"private": 0600, "secure": 0700, "copy": 0700, "child": 0664, "inherited": 0600, "background": 0640, "parent": 0600, "public": 0666, "shared": 0777} {
		st, e := m.Stat("/" + name)
		if e != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: %v %v want %o", name, st, e, want)
		}
	}
}
func TestSymbolicUmask(t *testing.T) {
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader(`umask u=rwx,g=rx,o=; umask; umask g+w,o=g; umask -S; umask 888; printf '%s:' "$?"; umask; umask u=rw,o=z; printf '%s:' "$?"; umask`), "test", Config{FS: testFS(t), Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "0027\nu=rwx,g=rwx,o=rwx\n1:0000\n1:0000\n" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
}
func TestInitialZeroMask(t *testing.T) {
	mask := fs.FileMode(0)
	m := testFS(t)
	r, e := Run(context.Background(), strings.NewReader(": >file"), "test", Config{FS: m, Umask: &mask})
	if e != nil || r.Status != 0 {
		t.Fatalf("%+v %v", r, e)
	}
	st, e := m.Stat("/file")
	if e != nil || st.Mode().Perm() != 0666 {
		t.Fatalf("%v %v", st, e)
	}
}
