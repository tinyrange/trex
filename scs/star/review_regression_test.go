package script

import (
	"context"
	"errors"
	"github.com/tinyrange/trex/scs/repo"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"testing"
	"time"
)

func TestTwoWorkspaceQueriesRejectCancelledOperand(t *testing.T) {
	r, e := repo.CreateOptimized(storage.NewMemoryStore(4 << 20))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	before := &Value{w: r.Empty(), ctx: context.Background()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	after := &Value{w: r.Empty(), ctx: ctx}
	if _, e = before.call("diff", starlark.Tuple{after}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	dict := starlark.NewDict(0)
	if _, e = before.call("affected_targets", starlark.Tuple{after, dict}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestTwoWorkspaceQueryObservesOtherCancellation(t *testing.T) {
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	second, cancelSecond := context.WithCancel(context.Background())
	defer cancelSecond()
	before, after := &Value{ctx: first}, &Value{ctx: second}
	ctx, close, e := before.queryContext(after)
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	cancelSecond()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("other workspace lifetime ignored")
	}
}
