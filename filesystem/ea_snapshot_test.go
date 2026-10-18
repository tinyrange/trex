package filesystem

import "testing"

func TestSnapshotCopiesExtendedAttributes(t *testing.T) {
	d := New()
	d.PutFile("/file", FileRecord{})
	d.SetMetadata("/file", Metadata{ExtendedAttributes: []ExtendedAttribute{{Name: "hint", Value: []byte{1, 2}}}})
	a := d.Snapshot()
	a.Metadata["/file"].ExtendedAttributes[0].Name = "changed"
	a.Metadata["/file"].ExtendedAttributes[0].Value[0] = 9
	b := d.Snapshot().Metadata["/file"].ExtendedAttributes[0]
	if b.Name != "hint" || b.Value[0] != 1 {
		t.Fatal("snapshot aliases mutable EA state")
	}
}
