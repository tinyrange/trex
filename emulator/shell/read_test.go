package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestReadIFS(t *testing.T) {
	for _, tc := range []struct {
		input, source, want string
		status              int
	}{
		{"x86_64-pc-linux-gnu\n", `IFS=- read -r a b c d; printf '%s:%s:%s:%s' "$a" "$b" "$c" "$d"`, "x86_64:pc:linux:gnu", 0},
		{":a::b:\n", `IFS=: read a b c d e; printf '<%s><%s><%s><%s><%s>' "$a" "$b" "$c" "$d" "$e"`, "<><a><><b><>", 0},
		{" a : b:c: \n", `IFS=' :' read a b; printf '<%s><%s>' "$a" "$b"`, "<a><b:c:>", 0},
		{"a:b:\n", `IFS=: read a b; printf '<%s><%s>' "$a" "$b"`, "<a><b>", 0},
		{" a \t b  c \n", `read a b; printf '<%s><%s>' "$a" "$b"`, "<a><b  c>", 0},
		{" a : b \n", `IFS= read a; printf '<%s>' "$a"`, "< a : b >", 0},
		{"a\\:b:c\n", `IFS=: read a b; printf '<%s><%s>' "$a" "$b"`, "<a:b><c>", 0},
		{"a\\\nb\n", `read a; printf '<%s>' "$a"`, "<ab>", 0},
		{"last", `read a; r=$?; printf '<%s>' "$a"; exit "$r"`, "<last>", 1},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.source), "test", Config{FS: testFS(t), Stdin: strings.NewReader(tc.input), Stdout: &out})
		if e != nil || r.Status != tc.status || out.String() != tc.want {
			t.Fatalf("%q: %+v %v %q", tc.input, r, e, out.String())
		}
	}
}
