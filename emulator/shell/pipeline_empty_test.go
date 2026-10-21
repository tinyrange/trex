package shell

import (
	"context"
	"strings"
	"testing"
)

func TestPipelineIgnoresEmptyWrites(t *testing.T) {
	m := testFS(t)
	if e := m.WriteFile("/many", []byte(strings.Repeat("nothing\n", 300)), 0644); e != nil {
		t.Fatal(e)
	}
	r, e := Run(context.Background(), strings.NewReader(`sed -n '/match/p' /many | grep X`), "test", Config{FS: m})
	if e != nil || r.Status != 1 {
		t.Fatalf("%+v %v", r, e)
	}
}
