package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func testFS(t *testing.T) *MemoryFS {
	t.Helper()
	m, err := NewMemoryFS(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestShellSemantics(t *testing.T) {
	cases := []struct {
		name, source, want string
		status             int
	}{
		{"quoting", `x='a b'; printf '<%s>\n' "$x" $x ''`, "<a b>\n<a>\n<b>\n<>\n", 0},
		{"parameters", `set -- 'a b' '' c; printf '<%s>\n' "$@"; shift 2; printf '%s:%s\n' "$#" "$1"`, "<a b>\n<>\n<c>\n1:c\n", 0},
		{"substitution", `x=parent; y=$(x=child; printf '%s\n\n' "$x"); printf '%s:%s\n' "$x" "$y"`, "parent:child\n", 0},
		{"substitution status", `x=$(exit 7); printf '%s\n' "$?"; false; x=$?; printf '%s\n' "$x"`, "7\n1\n", 0},
		{"redirection", `printf abc >f; printf def >>f; cat <f`, "abcdef", 0},
		{"persistent descriptors", `exec 3>log; printf one >&3; printf two >&3; exec 3>&-; cat log`, "onetwo", 0},
		{"redirection ordering", `{ printf out; printf err >&2; } 2>&1 >file; cat file`, "errout", 0},
		{"heredocs", "x=expanded\ncat <<'EOF'\n$x\nEOF\ncat <<EOF\n$x\nEOF\n", "$x\nexpanded\n", 0},
		{"tab heredoc", "x='\ttab'\ncat <<-EOF\n\t$x\n\tEOF\n", "\ttab\n", 0},
		{"pipeline state", `x=before; printf 'line\n' | { read x; printf '%s\n' "$x"; }; printf '%s\n' "$x"`, "line\nbefore\n", 0},
		{"pipeline early reader", `while :; do printf line; done | { read -r x; :; }`, "", 0},
		{"pipeline status", `false | true; printf '%s\n' "$?"; true | false`, "0\n", 1},
		{"function state", `f() { x=$1; printf '%s:%s\n' "$#" "$1"; return 9; }; set -- outer; f inner extra; printf '%s:%s:%s\n' "$?" "$1" "$x"`, "2:inner\n9:outer:inner\n", 0},
		{"conditionals", `if false; then printf bad; elif true; then printf good; fi; false && printf bad; false || printf ok; ! true`, "goodok", 1},
		{"loops", `n=0; while test "$n" -lt 3; do n=$((n+1)); case $n in 2) continue;; esac; printf '%s' "$n"; done; for x in a b c; do [ "$x" = c ] && break; printf %s "$x"; done`, "13ab", 0},
		{"nested break", `for a in 1 2; do for b in 1 2; do printf '%s:%s' "$a" "$b"; break 2; done; printf bad; done; printf done`, "1:1done", 0},
		{"case quotes", `x='a*'; case ab in "$x") printf bad;; a*) printf good;; esac`, "good", 0},
		{"glob", `mkdir sub; printf '' >sub/b.c; printf '' >sub/a.c; printf '' >sub/.hidden.c; printf '%s\n' sub/*.c`, "sub/a.c\nsub/b.c\n", 0},
		{"subshell cwd", `mkdir sub; (cd sub; pwd); pwd`, "/sub\n/\n", 0},
		{"eval", `x=one; eval 'x=two; printf "%s" "$x"'; printf %s "$x"`, "twotwo", 0},
		{"export", `x=secret; y=public; export y; sh -c 'printf "%s:%s:%s" "${x-unset}" "$y" "$1"' child arg`, "unset:public:arg", 0},
		{"temporary assignment", `x=before; x=during sh -c 'printf %s "$x"'; printf %s "$x"`, "duringbefore", 0},
		{"errexit conditions", `set -e; false && printf bad; if false; then printf bad; fi; ! true; printf good`, "good", 0},
		{"errexit function", `f() { false; printf survived; }; set -e; if f; then printf good; fi; false; printf bad`, "survivedgood", 1},
		{"errexit", `set -e; false; printf bad`, "", 1},
		{"source", `printf 'x=changed; return 3; printf bad' >vars; x=old; . ./vars; printf '%s:%s' "$?" "$x"`, "3:changed", 0},
		{"printf", `printf '%04d:%s\n' 12 hello 3 world; printf '%b' 'a\nb\cignored'`, "0012:hello\n0003:world\na\nb", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "pipeline early reader" {
				tc.source = `while :; do printf 'line\n'; done | { read -r x; :; }`
			}
			var out, diagnostic bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := Run(ctx, strings.NewReader(tc.source), "test.sh", Config{FS: testFS(t), Stdout: &out, Stderr: &diagnostic, MaxSteps: 1000})
			if err != nil {
				t.Fatalf("%v; output %q, stderr %q", err, out.String(), diagnostic.String())
			}
			if result.Status != tc.status || out.String() != tc.want {
				t.Fatalf("got status %d, output %q; want status %d, output %q; stderr %q", result.Status, out.String(), tc.status, tc.want, diagnostic.String())
			}
		})
	}
}
func TestEmulatorErrorsAreNotFeatureResults(t *testing.T) {
	for _, source := range []string{`cat --unsupported`, `if cat --unsupported; then :; fi`, `! cat --unsupported`, `cat --unsupported || true`, `x=$(cat --unsupported)`, `cat --unsupported | cat`, `printf x | cat --unsupported`} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := Run(ctx, strings.NewReader(source), "gap.sh", Config{FS: testFS(t)})
		cancel()
		var gap *UnsupportedError
		if !errors.As(err, &gap) {
			t.Fatalf("%s: want unsupported error, got %v", source, err)
		}
	}
}
func TestExplicitCommandBoundary(t *testing.T) {
	var out bytes.Buffer
	handler := func(ctx context.Context, in Invocation) (int, error) {
		if in.Args[0] != "probe" {
			return 0, fmt.Errorf("unexpected command")
		}
		if _, ok := in.Env["secret"]; ok {
			return 0, fmt.Errorf("unexported variable leaked")
		}
		if in.Env["PUBLIC"] != "yes" || in.Env["TEMP"] != "value" || in.Dir != "/build" {
			return 0, fmt.Errorf("wrong command environment: %+v", in)
		}
		_, err := io.Copy(in.Stdout, in.Stdin)
		return 7, err
	}
	source := `mkdir build; cd build; secret=hidden; PUBLIC=yes; export PUBLIC; printf input >data; TEMP=value probe arg <data; printf ':%s:%s' "$?" "${TEMP-unset}"`
	result, err := Run(context.Background(), strings.NewReader(source), "probe.sh", Config{FS: testFS(t), Stdout: &out, Command: handler})
	if err != nil || result.Status != 0 || out.String() != "input:7:unset" {
		t.Fatalf("%+v %v %q", result, err, out.String())
	}
}
func TestBudgetsAndCancellation(t *testing.T) {
	for _, source := range []string{`while :; do :; done`, `f() { f; }; f`, `eval 'eval "while :; do :; done"'`, `x=$(printf '%100s' x)`} {
		_, err := Run(context.Background(), strings.NewReader(source), "budget.sh", Config{FS: testFS(t), MaxSteps: 50, MaxDepth: 8, MaxSubstitutionBytes: 16})
		if err == nil || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("%s: %v", source, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, strings.NewReader(":"), "cancel.sh", Config{FS: testFS(t)})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestNoHostEnvironmentOrFilesystem(t *testing.T) {
	t.Setenv("TREX_SHELL_HOST_SECRET", "should-not-leak")
	var out bytes.Buffer
	result, err := Run(context.Background(), strings.NewReader(`printf '%s:%s' "${TREX_SHELL_HOST_SECRET-unset}" ~root; test -f /etc/passwd`), "isolation.sh", Config{FS: testFS(t), Stdout: &out})
	if err != nil || result.Status != 1 || out.String() != "unset:~root" {
		t.Fatalf("%+v %v %q", result, err, out.String())
	}
}
