package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestLazyParameterBranches(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`x=set; printf '%s:%s:%s' "${x:-$(printf bad >marker)}" "${missing:+$((1/0))}" "${x:=bad}"; test ! -f marker`, "set::set"},
		{`unset x; printf '%s:%s' "${x:=$((2+3))}" "$x"`, "5:5"},
		{`x=''; printf '%s:%s' "${x-$((1/0))}" "${x:-ok}"`, ":ok"},
		{"printf '<%s>' \"${x:-a\nb\n}\"", "<a\nb\n>"},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.source), "test", Config{FS: testFS(t), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != tc.want {
			t.Fatalf("%s: %+v %v %q", tc.source, r, e, out.String())
		}
	}
}
