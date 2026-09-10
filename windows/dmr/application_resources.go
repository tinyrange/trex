package dmr

import "fmt"

// ApplicationResourceReferences contains already-resolved MRM references.
// Required empty properties still need a valid empty-literal reference. Only
// StartPage is optional: nil omits ID6, while a present reference retains it.
// Input strings and URI/PRI lookup policy do not belong to this serializer.
type ApplicationResourceReferences struct {
	DisplayName, Description, Square150x150Logo, Square44x44Logo, StartPage []byte
}

// EncodeApplicationResources emits one RESA for an APPS array index, not a
// repository Application ID or dependency-node index. Resource selectors follow
// OneCore's native order 1,3,4,5[,6], with string type 0 and file type 1.
func EncodeApplicationResources(index uint16, refs ApplicationResourceReferences) ([]byte, error) {
	r := Resources{Application: true, Index: index}
	for i, data := range [][]byte{refs.DisplayName, refs.Description, refs.Square150x150Logo, refs.Square44x44Logo, refs.StartPage} {
		if i == 4 && data == nil {
			continue
		}
		id := [...]uint16{1, 3, 4, 5, 6}[i]
		if _, err := ParseLiteralResourceReference(data); err != nil {
			if _, indexErr := ParseIndexResourceReference(data); indexErr != nil {
				return nil, fmt.Errorf("dmr: application resource %d requires a valid resolved reference", id)
			}
		}
		kind := uint16(0)
		if i >= 2 {
			kind = 1
		}
		r.Entries = append(r.Entries, NamedResource{Value4: id, Value6: kind, Data: data})
	}
	return EncodeResources(r)
}
