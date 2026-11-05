package uup

import "fmt"

// PackageIntendedStates returns an independently owned map from canonical CBS
// package name to resolved target. It includes unadmitted inventory contexts,
// not just execution items. Targets are neither committed CurrentState nor
// authorization to persist owner or package values.
func (index *CBSUpdateStateIndex) PackageIntendedStates() map[string]uint32 {
	states := map[string]uint32{}
	if index != nil {
		for _, ctx := range index.graph.packages.all() {
			states[ctx.name] = ctx.input.IntendedState
		}
	}
	return states
}

// PackageIntendedState queries one exact package without copying the complete
// inventory. Absence is an error, not an inferred absent state. Like the bulk
// query, this observes the receiver's immutable snapshot, not committed state.
func (index *CBSUpdateStateIndex) PackageIntendedState(identity AssemblyIdentity) (uint32, error) {
	if index != nil {
		if context := index.graph.packages.get(identity.ExactKey()); context != nil {
			return context.input.IntendedState, nil
		}
	}
	return 0, fmt.Errorf("CBS package context is absent: %q", identity.Name)
}
