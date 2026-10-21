package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDiff(t *testing.T) {
	for _, tc := range []struct {
		name, a, b, want string
		status           int
	}{
		{"same", "same\n", "same\n", "", 0},
		{"insert", "a\nc\n", "a\nb\nc\n", "1a2\n> b\n", 1},
		{"delete", "a\nb\nc\n", "a\nc\n", "2d1\n< b\n", 1},
		{"replace", "a\nb\nc\n", "a\nx\ny\nc\n", "2c2,3\n< b\n---\n> x\n> y\n", 1},
		{"newline", "a", "a\n", "1c1\n< a\n\\ No newline at end of file\n---\n> a\n", 1},
		{"empty", "", "b\n", "0a1\n> b\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testFS(t)
			m.WriteFile("/a", []byte(tc.a), 0644)
			m.WriteFile("/b", []byte(tc.b), 0644)
			var out bytes.Buffer
			r, e := Run(context.Background(), strings.NewReader("diff a b"), "test", Config{FS: m, Stdout: &out})
			if e != nil || r.Status != tc.status || out.String() != tc.want {
				t.Fatalf("%+v %v %q", r, e, out.String())
			}
		})
	}
}
func TestGrepLongLineComparison(t *testing.T) {
	m := testFS(t)
	line := strings.Repeat("0123456789", 2048) + "GREP\n"
	m.WriteFile("/input", []byte(line), 0644)
	r, e := Run(context.Background(), strings.NewReader(`grep -e 'GREP$' -e '-(cannot match)-' <input >output && diff input output`), "test", Config{FS: m})
	if e != nil || r.Status != 0 {
		t.Fatalf("%+v %v", r, e)
	}
}
