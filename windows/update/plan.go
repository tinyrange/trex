package update

import (
	"fmt"
	"sort"
	"strings"
)

// ResolveBundleClosure validates every prerequisite clause reachable from
// root and returns applicable bundle members before their parents. All cached
// alternatives in a bundle clause are retained: bundle alternatives are
// independently applicable revisions, not a license to choose an arbitrary
// first match.
func (catalog *Catalog) ResolveBundleClosure(root Offer) ([]Offer, error) {
	if catalog == nil {
		return nil, fmt.Errorf("windows update: catalog is required")
	}
	byExact := make(map[string]Offer, len(catalog.Revisions))
	byID := make(map[string][]Offer)
	for _, revision := range catalog.Revisions {
		if revision.ID == "" || revision.Revision <= 0 {
			continue
		}
		key := updateIdentityKey(revision.ID, revision.Revision)
		if previous, exists := byExact[key]; exists && previous.ServerID != revision.ServerID {
			return nil, fmt.Errorf("windows update: identity %s revision %d has duplicate server revisions", revision.ID, revision.Revision)
		}
		byExact[key] = revision
		id := strings.ToLower(revision.ID)
		byID[id] = append(byID[id], revision)
	}
	for id := range byID {
		sort.Slice(byID[id], func(i, j int) bool { return byID[id][i].Revision > byID[id][j].Revision })
	}
	resolve := func(identity UpdateIdentity) (Offer, bool) {
		if identity.Revision > 0 {
			value, found := byExact[updateIdentityKey(identity.ID, identity.Revision)]
			return value, found
		}
		values := byID[strings.ToLower(identity.ID)]
		if len(values) == 0 {
			return Offer{}, false
		}
		return values[0], true
	}
	if root.ID == "" || root.Revision <= 0 {
		return nil, fmt.Errorf("windows update: root identity and revision are required")
	}
	if cached, found := byExact[updateIdentityKey(root.ID, root.Revision)]; found {
		root = mergeOffer(cached, root)
	}
	state := make(map[string]uint8)
	var result []Offer
	var visit func(Offer) error
	visit = func(revision Offer) error {
		key := updateIdentityKey(revision.ID, revision.Revision)
		switch state[key] {
		case 1:
			return fmt.Errorf("windows update: bundle cycle at %s revision %d", revision.ID, revision.Revision)
		case 2:
			return nil
		}
		state[key] = 1
		for clauseIndex, clause := range revision.Prerequisites {
			satisfied := false
			for _, identity := range clause.Alternatives {
				if _, found := resolve(identity); found {
					satisfied = true
					break
				}
			}
			if !satisfied {
				return fmt.Errorf("windows update: %s revision %d has unresolved prerequisite clause %d", revision.ID, revision.Revision, clauseIndex)
			}
		}
		for clauseIndex, clause := range revision.BundledUpdates {
			found := false
			for _, identity := range clause.Alternatives {
				child, present := resolve(identity)
				if !present {
					continue
				}
				found = true
				if err := visit(child); err != nil {
					return err
				}
			}
			if !found {
				return fmt.Errorf("windows update: %s revision %d has unresolved bundle clause %d", revision.ID, revision.Revision, clauseIndex)
			}
		}
		state[key] = 2
		result = append(result, revision)
		return nil
	}
	if err := visit(root); err != nil {
		return nil, err
	}
	return result, nil
}

func updateIdentityKey(id string, revision int) string {
	return strings.ToLower(id) + "\x00" + fmt.Sprint(revision)
}
