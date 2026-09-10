package update

import "testing"

func TestResolveBundleClosureOrdersChildrenAndValidatesPrerequisites(t *testing.T) {
	prerequisite := Offer{ID: "prerequisite", Revision: 1, ServerID: "1"}
	child := Offer{ID: "child", Revision: 2, ServerID: "2", Prerequisites: []RelationshipClause{{Alternatives: []UpdateIdentity{{ID: "prerequisite", Revision: 1}}}}}
	root := Offer{ID: "root", Revision: 3, ServerID: "3", IsLeaf: true, BundledUpdates: []RelationshipClause{{Alternatives: []UpdateIdentity{{ID: "child", Revision: 2}}}}}
	catalog := &Catalog{Revisions: []Offer{root, prerequisite, child}}
	closure, err := catalog.ResolveBundleClosure(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(closure) != 2 || closure[0].ID != "child" || closure[1].ID != "root" {
		t.Fatalf("closure = %#v", closure)
	}
}

func TestResolveBundleClosureRejectsUnresolvedClause(t *testing.T) {
	root := Offer{ID: "root", Revision: 1, ServerID: "1", BundledUpdates: []RelationshipClause{{Alternatives: []UpdateIdentity{{ID: "missing", Revision: 1}}}}}
	if _, err := (&Catalog{Revisions: []Offer{root}}).ResolveBundleClosure(root); err == nil {
		t.Fatal("expected unresolved bundle rejection")
	}
}
