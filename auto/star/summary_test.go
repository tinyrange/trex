package star

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"go.starlark.net/starlark"
	"testing"
)

type unreadableSummarySource struct{ reads int }

func (r *unreadableSummarySource) Size() int64 { return 4096 }
func (r *unreadableSummarySource) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return 0, fmt.Errorf("content detection not allowed")
}
func TestSummaryDoesNotDetectFileContents(t *testing.T) {
	r := &unreadableSummarySource{}
	tree, err := auto.Tree([]auto.Entry{{Name: "payload", Kind: "file", Reader: r, Attributes: map[string]any{"inode": 17}}}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := auto.FromView(tree, "", auto.Options{}).Resolve("payload")
	if err != nil {
		t.Fatal(err)
	}
	summary, err := (&Value{n}).Attr("summary")
	if err != nil || r.reads != 0 {
		t.Fatal(summary, err, r.reads)
	}
	d := summary.(*starlark.Dict)
	kind, _, _ := d.Get(starlark.String("kind"))
	if kind != starlark.String("file") {
		t.Fatal(kind)
	}
	attrs, _, _ := d.Get(starlark.String("attributes"))
	inode, _, _ := attrs.(*starlark.Dict).Get(starlark.String("inode"))
	if inode.String() != "17" {
		t.Fatal(inode)
	}
	if _, err := (&Value{n}).Attr("metadata"); err == nil || r.reads == 0 {
		t.Fatal("metadata did not detect contents", err)
	}
}
