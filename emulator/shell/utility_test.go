package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestVirtualUnixSemantics(t *testing.T) {
	cases := []struct {
		name, source, want string
		status             int
	}{
		{"shell identity", `eval 'printf "%s\n" "$0"'; printf 'printf "%%s\\n" "$0"' >source; . ./source`, "test.sh\ntest.sh\n", 0},
		{"special assignments", `x=before; x=after :; printf '%s' "$x"`, "after", 0},
		{"exit trap", `trap 'printf "exit:%s" "$?"' 0; exit 7`, "exit:7", 7},
		{"trap override", `trap 'exit 9' EXIT; exit 7`, "", 9},
		{"subshell trap", `trap 'printf parent' EXIT; (trap 'printf child' EXIT; :); printf done`, "childdoneparent", 0},
		{"substitution trap", `x=$(trap 'printf exit' EXIT; printf body); printf %s "$x"`, "bodyexit", 0},
		{"fd lifetime", `exec 3>file; { printf one >&3; }; exec 4>&3; exec 3>&-; (printf two >&4); printf three >&4; exec 4>&-; cat file`, "onetwothree", 0},
		{"read offsets", `printf 'one\ntwo\n' >file; exec 3<file; read -r a <&3; read -r b <&3; printf '%s:%s' "$a" "$b"`, "one:two", 0},
		{"read whitespace", `printf '  first second   third  \n' | { read -r a b; printf '<%s><%s>' "$a" "$b"; }`, "<first><second   third>", 0},
		{"redirection failure", `if cat <missing 2>/dev/null; then printf wrong; else printf missing; fi`, "missing", 0},
		{"not found", `not-a-program 2>/dev/null; printf '%s' "$?"`, "127", 0},
		{"expr", `expr 2 + 3 '*' 4; expr file.tar : '\(.*\)\.tar'; expr 12 '>' 9; expr abc : z`, "14\nfile\n1\n0\n", 1},
		{"sed captures", `printf 'one two\none\n' | sed -n 's/\(one\)/[\1]/gp'`, "[one] two\n[one]\n", 0},
		{"sed range", `printf 'one\ntwo\nthree\nfour\n' | sed -n '2,3p'`, "two\nthree\n", 0},
		{"sed no newline", `printf hello | sed 's/hello/world/'`, "world", 0},
		{"sed quit", `while :; do printf 'line\n'; done | sed 1q`, "line\n", 0},
		{"sed append", "printf 'one\ntwo\n' | sed '1a\\\nadded\n1q'", "one\nadded\n", 0},
		{"sed nth", `printf 'aaa\n' | sed 's/a/x/2g'`, "axx\n", 0},
		{"timestamp order", `printf old >z; printf new >a; ls -t z a; printf newer >z; ls -t z a`, "a\nz\nz\na\n", 0},
		{"grep basic", `printf 'alpha\nbeta\nalphabet\n' | grep -n '^alpha'`, "1:alpha\n3:alphabet\n", 0},
		{"grep fixed", `printf 'a.b\naxb\n' | grep -F 'a.b'`, "a.b\n", 0},
		{"grep inverse", `printf 'A\nb\na\n' | grep -iv a`, "b\n", 0},
		{"grep quiet", `printf 'one\ntwo\n' >f; grep -q two f; printf '%s' "$?"; grep -q missing f`, "0", 1},
		{"grep error", `grep -s a missing`, "", 2},
		{"grep extended", `printf 'a\naa\nb\n' | grep -Ec '^a+$'`, "2\n", 0},
		{"copy move", `printf data >a; cp a b; mv b c; cat a c; test -f b`, "datadata", 1},
		{"rename open identity", `printf old >a; printf new >b; exec 3<a; mv b a; cat <&3; cat a`, "oldnew", 0},
		{"recursive removal", `mkdir -p a/b; printf data >a/b/file; rm -rf a; test -d a`, "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			result, err := Run(context.Background(), strings.NewReader(tc.source), "test.sh", Config{FS: testFS(t), Stdout: &out, Stderr: &diagnostic, MaxSteps: 10000})
			if err != nil || result.Status != tc.status || out.String() != tc.want {
				t.Fatalf("%+v err=%v output=%q expected=%q stderr=%q", result, err, out.String(), tc.want, diagnostic.String())
			}
		})
	}
}
func TestRedirectionDoesNotExhaustFileBudget(t *testing.T) {
	m, err := NewMemoryFS(4)
	if err != nil {
		t.Fatal(err)
	}
	source := `for n in 1 2 3 4 5 6 7 8; do printf data >file; rm file; done`
	result, err := Run(context.Background(), strings.NewReader(source), "files.sh", Config{FS: m})
	if err != nil || result.Status != 0 {
		t.Fatalf("%+v %v", result, err)
	}
	if m.used != 0 {
		t.Fatalf("leaked %d bytes", m.used)
	}
}
func TestOpenUnlinkedFile(t *testing.T) {
	m, err := NewMemoryFS(4)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.WriteFile("/f", []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := m.Open("/f", Read)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Remove("/f"); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if n, err := f.Read(b); err != nil || n != 4 || string(b) != "data" {
		t.Fatalf("%d %v %q", n, err, b)
	}
	if err = m.WriteFile("/g", []byte("more"), 0644); err == nil {
		t.Fatal("unlinked open data escaped budget")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = m.WriteFile("/g", []byte("more"), 0644); err != nil {
		t.Fatal(err)
	}
}
