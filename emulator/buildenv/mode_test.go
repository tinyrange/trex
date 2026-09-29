//go:build renvo_bundle

package buildenv

import (
	"bytes"
	"context"
	"github.com/tinyrange/trex/emulator/shell"
	"io/fs"
	"strings"
	"testing"
)

func TestCreationMaskThroughCompilerAndGuest(t *testing.T) {
	m, e := shell.NewMemoryFS(16 << 20)
	if e != nil {
		t.Fatal(e)
	}
	env, e := New(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.WriteFile("/main.c", []byte(`#include <stdio.h>
int main(void){FILE *f=fopen("guest","w");if(!f)return 1;return fclose(f)!=0;}`), 0644); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	r, e := shell.Run(context.Background(), strings.NewReader(`umask 077; cc main.c -o app && ./app; umask 000; cc -c main.c -o public.o; : >shell-file`), "test", shell.Config{FS: m, Env: map[string]string{"PATH": "/bin"}, Command: env.Command, Stdout: &out, Stderr: &out})
	if e != nil || r.Status != 0 {
		t.Fatalf("%+v %v %s", r, e, out.String())
	}
	for name, want := range map[string]fs.FileMode{"app": 0700, "guest": 0600, "public.o": 0666, "shell-file": 0666} {
		st, e := m.Stat("/" + name)
		if e != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: %v %v want%o", name, st, e, want)
		}
	}
}
