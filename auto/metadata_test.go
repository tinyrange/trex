package auto

import (
	"errors"
	"testing"
)

type testMetadataView struct {
	calls int
	err   error
}

func (v *testMetadataView) Entries() ([]Entry, error) { return nil, nil }
func (v *testMetadataView) Metadata() (string, map[string]any, error) {
	v.calls++
	return "structure", map[string]any{"field": uint64(0xffffffffffffffff)}, v.err
}

func TestDirectoryMetadataIsLazy(t *testing.T) {
	view := &testMetadataView{}
	root := FromView(ViewFunc(func() ([]Entry, error) {
		return []Entry{{Name: "object", Kind: "directory", View: view, Attributes: map[string]any{"source": "input"}}}, nil
	}), "", Options{})
	children, err := root.Children()
	if err != nil {
		t.Fatal(err)
	}
	children[0].Summary()
	if view.calls != 0 {
		t.Fatal("listing decoded metadata")
	}
	m, err := children[0].Metadata()
	if err != nil || m.Format != "structure" || m.Attributes["source"] != "input" || m.Attributes["field"] != uint64(0xffffffffffffffff) {
		t.Fatal(m, err)
	}
	view.err = errors.New("invalid structure")
	if _, err := children[0].Metadata(); err == nil {
		t.Fatal("lost metadata error")
	}
}
