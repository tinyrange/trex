package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestQuotedHeredocBackslashes(t *testing.T) {
	for _, delimiter := range []string{"'END'", `\END`, `"END"`} {
		var out bytes.Buffer
		source := "cat <<" + delimiter + "\n" + `do eval test x\${$as_var+set} = xset` + "\nEND\n"
		r, e := Run(context.Background(), strings.NewReader(source), "test", Config{FS: testFS(t), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != `do eval test x\${$as_var+set} = xset`+"\n" {
			t.Fatalf("%s: %v %q", delimiter, e, out.String())
		}
	}
}
