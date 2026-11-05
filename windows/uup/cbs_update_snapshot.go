package uup

import (
	"fmt"
	"strings"
)

// CBSUpdateIntentChange replaces one package target in an update snapshot.
// It does not change parent resolution, edition policy or explicit choices.
type CBSUpdateIntentChange struct {
	Identity      AssemblyIdentity
	IntendedState uint32
}

// WithIntendedStates creates an independent snapshot without reparsing manifests.
// All dependency memo entries are invalidated, including transitive detections.
// The old snapshot is unchanged, even when validation fails. Rebuild the index
// instead if parent scopes or selection/edition policy have changed.
func (index *CBSUpdateStateIndex) WithIntendedStates(changes []CBSUpdateIntentChange) (*CBSUpdateStateIndex, error) {
	if index == nil {
		return nil, fmt.Errorf("nil CBS update state index")
	}
	if len(changes) > 1<<16 {
		return nil, fmt.Errorf("CBS update state changes exceed bound")
	}
	replacements := make(map[string]uint32, len(changes))
	for _, change := range changes {
		key := index.graph.packages.keyForIdentity(change.Identity)
		if index.graph.packages.get(key) == nil {
			return nil, fmt.Errorf("CBS update change has no package context: %q", change.Identity.Name)
		}
		if !resolvedCBSParentState(change.IntendedState) {
			return nil, fmt.Errorf("unresolved CBS update change state %#x", change.IntendedState)
		}
		if _, exists := replacements[key]; exists {
			return nil, fmt.Errorf("duplicate CBS update change: %q", change.Identity.Name)
		}
		replacements[key] = change.IntendedState
	}
	contexts := make(map[string]*cbsUpdateContext, len(replacements))
	for key, state := range replacements {
		copy := *index.graph.packages.get(key)
		copy.input.IntendedState = state
		contexts[key] = &copy
	}
	return index.withContexts(contexts), nil
}

// WithPublishedUpdates replaces explicit per-session update targets in one
// package. Native GetInstallState prefers these values to metadata evaluation;
// they may already include an earlier containing-package cap. The unspecified
// sentinel removes an override and restores metadata fallback. Package targets
// and previously published updates are otherwise preserved. All derived memo
// entries are invalidated; no native applicability-cache policy is inferred.
func (index *CBSUpdateStateIndex) WithPublishedUpdates(identity AssemblyIdentity, updates map[string]uint32) (*CBSUpdateStateIndex, error) {
	if index == nil {
		return nil, fmt.Errorf("nil CBS update state index")
	}
	key := index.graph.packages.keyForIdentity(identity)
	ctx := index.graph.packages.get(key)
	if ctx == nil {
		return nil, fmt.Errorf("CBS published update has no package context: %q", identity.Name)
	}
	if len(updates) > 1<<16 {
		return nil, fmt.Errorf("CBS published updates exceed bound")
	}
	changes := make(map[string]uint32, len(updates))
	var deletes []string
	seen := make(map[string]bool, len(updates))
	for name, state := range updates {
		name = strings.ToLower(name)
		if seen[name] {
			return nil, fmt.Errorf("duplicate CBS published update %q", name)
		}
		seen[name] = true
		if _, ok := ctx.updates[name]; !ok {
			return nil, fmt.Errorf("unknown CBS published update %q", name)
		}
		if state == CBSStateUnspecified {
			deletes = append(deletes, name)
		} else {
			if !resolvedCBSParentState(state) {
				return nil, fmt.Errorf("unresolved CBS published update state %#x", state)
			}
			changes[name] = state
		}
	}
	copy := *ctx
	copy.published = ctx.published.changed(changes, deletes)
	return index.withContexts(map[string]*cbsUpdateContext{key: &copy}), nil
}

// ApplicableUpdateState evaluates this update's metadata rather than returning
// its published target. Detectors still use published dependency targets, just
// as GetApplicableSelectableState calls GetInstallState on dependencies. This
// is not the native applicability-result cache (classification/detected state),
// nor does this query publish its result. Scheduling/publication is explicit.
func (index *CBSUpdateStateIndex) ApplicableUpdateState(identity AssemblyIdentity, update string) (CBSUpdateState, error) {
	if index == nil {
		return CBSUpdateState{}, fmt.Errorf("nil CBS update state index")
	}
	ctx := index.graph.packages.get(index.graph.packages.keyForIdentity(identity))
	if ctx == nil {
		return CBSUpdateState{}, fmt.Errorf("CBS update package context is absent: %q", identity.Name)
	}
	state, err := index.graph.applicable(cbsUpdateQuery{index.graph.packages.keyForIdentity(identity), strings.ToLower(update)}, 0)
	if err != nil {
		return CBSUpdateState{}, err
	}
	return CBSUpdateState{RawState: state, IntendedState: min(state, ctx.input.IntendedState)}, nil
}

// withContexts shares immutable buckets and metadata, but never evaluation memo.
func (index *CBSUpdateStateIndex) withContexts(changes map[string]*cbsUpdateContext) *CBSUpdateStateIndex {
	return &CBSUpdateStateIndex{names: index.names, graph: cbsUpdateIntents{
		components: index.graph.components,
		packages:   index.graph.packages.with(changes),
		memo:       map[cbsUpdateQuery]uint32{},
		visiting:   map[cbsUpdateQuery]bool{},
	}}
}
