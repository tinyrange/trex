package repo

import (
	"errors"
	"testing"
)

func TestDiscardAndRecoverSnapshot(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("base")))
	id, err := w.Publish("main")
	must(t, err)
	child, err := r.Fork(id)
	must(t, err)
	must(t, child.WriteFile("f", []byte("child")))
	childID, err := child.Publish("child")
	must(t, err)
	if err := r.Drop("child", id); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale drop: %v", err)
	}
	must(t, r.Drop("child", childID))
	must(t, r.Close())
	r, err = openTest(name)
	must(t, err)
	defer r.Close()
	if _, ok := r.Refs()["child"]; ok {
		t.Fatal("discarded root remains")
	}
	if r.Refs()["main"] != id {
		t.Fatal("discard changed another workspace")
	}
	recovered, err := r.Fork(childID)
	must(t, err)
	readEquals(t, recovered, "f", []byte("child"))
}
