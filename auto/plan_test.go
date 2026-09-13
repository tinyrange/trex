package auto

import (
	"errors"
	"io/fs"
	"sync/atomic"
	"testing"
)

var planBuilds atomic.Int32

func init() {
	RegisterPlan("test-plan", func(listing []Entry, source View, o Options) ([]*Plan, error) {
		if len(listing) != 1 || listing[0].Name != "plan-input" {
			return nil, nil
		}
		return []*Plan{{ID: "combined", Title: "Combine", Build: func() (View, error) {
			planBuilds.Add(1)
			return ViewFunc(func() ([]Entry, error) {
				return []Entry{{Name: "result", Kind: "file", Reader: sourceBytes("combined")}}, nil
			}), nil
		}}}, nil
	})
}

func TestPlanIsOptInAndDeferred(t *testing.T) {
	planBuilds.Store(0)
	raw := FromView(ViewFunc(func() ([]Entry, error) {
		return []Entry{{Name: "plan-input", Kind: "file", Reader: sourceBytes("raw")}}, nil
	}), "", Options{})
	if p, err := raw.Plans(); err != nil || len(p) != 0 {
		t.Fatal(p, err)
	}
	if _, err := raw.Resolve("$plans/combined/result"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	root, err := raw.WithPlans()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		plans, err := root.Plans()
		if err != nil || len(plans) != 1 {
			t.Fatal(plans, err)
		}
	}
	if planBuilds.Load() != 0 {
		t.Fatal("proposal built contents")
	}
	for range 2 {
		result, err := root.Resolve("$plans/combined/result")
		if err != nil {
			t.Fatal(err)
		}
		if result.Reader().Size() != 8 {
			t.Fatal("wrong output")
		}
	}
	if planBuilds.Load() != 1 {
		t.Fatal("build not cached")
	}
	if _, err := root.Resolve("plan-input"); err != nil {
		t.Fatal("original input inaccessible", err)
	}
	if p, err := raw.Plans(); err != nil || len(p) != 0 {
		t.Fatal("modified original", p, err)
	}
}

func TestPlanDoesNotHideRealPlansDirectory(t *testing.T) {
	raw := FromView(ViewFunc(func() ([]Entry, error) {
		return []Entry{{Name: "$plans", Kind: "directory", View: ViewFunc(func() ([]Entry, error) {
			return []Entry{{Name: "original", Kind: "file", Reader: sourceBytes("x")}}, nil
		})}}, nil
	}), "", Options{})
	root, err := raw.WithPlans()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Resolve("$plans/original"); err != nil {
		t.Fatal(err)
	}
	if p, err := root.Plans(); err != nil || len(p) != 0 {
		t.Fatal(p, err)
	}
}
