package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestArithmeticExpandedExpression(t *testing.T) {
	var out bytes.Buffer
	r, e := Run(context.Background(), strings.NewReader(`f() { answer=$(( $* )); }; n=0; f $n + 1 && n=$answer; printf '%s:%s' "$n" "$answer"; f 10 + 1; printf ':%s' "$answer"`), "test", Config{FS: testFS(t), Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "1:1:11" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
}

func TestArithmeticSemantics(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`x='1 + 2'; printf '%s:%s' "$(( $x * 3 ))" "$(( ($x) * 3 ))"`, "7:9"},
		{`x=4; printf '%s:%s' "$((x+=3))" "$x"`, "7:7"},
		{`printf '%s:%s:%s' "$((0 && 1/0))" "$((2 || 1/0))" "$((2 ? 7 : 1/0))"`, "0:1:7"},
		{`printf '%s:%s' "$((010 + 0x10))" "$((1 << 5))"`, "24:32"},
		{`x=yes; printf '%s' "${x:-$((1/0))}"`, "yes"},
		{`false; x=$((1+1)); printf '%s:%s' "$?" "$x"`, "0:2"},
		{`printf '%s' "$(( 3 + $((2*4)) ))"`, "11"},
		{`cat <<EOF
$((1+2))
EOF`, "3\n"},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.source), "test", Config{FS: testFS(t), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != tc.want {
			t.Fatalf("%s: %+v %v %q", tc.source, r, e, out.String())
		}
	}
	for _, source := range []string{`echo $((1/0))`, `x=x; echo $((x))`, `echo $((08))`, `readonly x=1; echo $((x=2))`, `echo $((1 << -1))`} {
		_, e := Run(context.Background(), strings.NewReader(source), "test", Config{FS: testFS(t)})
		if e == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}
