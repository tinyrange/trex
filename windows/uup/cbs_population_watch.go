package uup

import "maps"

// CBSOrdinaryUpdateStart supplies the already-resolved native GetStartState
// result and whether the update has any deployments. A deployment-free update
// is initially dirty even when its start and target states are equal.
type CBSOrdinaryUpdateStart struct {
	State          uint32
	HasDeployments bool
}

// CBSOrdinaryWatchPolicy enables ordinary watch-list scheduling after roots and
// deferred MUM requests drain. All three callbacks are required and must be pure.
// InitialUpdate resolves start state at first execution-update creation; neither
// the original package target nor a fresh applicability query is a substitute.
// Dependents supplies an ordered, deduplicated result of the native package and
// update watch indexes. Satellites supplies ordered recursive admissions AFTER
// each dependent/satellite admission has drained, using the same notifier.
//
// These callbacks resolve store enumeration, child predicates, effective pending
// states, and per-session satellite requests. The scheduler does not guess them.
// A skipped execution item, multiple execution items per package, unsupported
// flags, and deferred MUM work generated during watching are outside this path.
type CBSOrdinaryWatchPolicy struct {
	InitialUpdate func(AssemblyIdentity, string, uint32, *CBSUpdateStateIndex) (CBSOrdinaryUpdateStart, error)
	Dependents    func(CBSOrdinaryExecution, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error)
	Satellites    func(CBSOrdinaryExecution, AssemblyIdentity, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error)
}

func cloneCBSOrdinaryExecution(e CBSOrdinaryExecution) CBSOrdinaryExecution {
	e.Identity.Attributes = append([]ManifestAttribute(nil), e.Identity.Attributes...)
	e.Owners = append([]CBSPackageOwnerIntent(nil), e.Owners...)
	e.Updates = maps.Clone(e.Updates)
	e.DirtyUpdates = maps.Clone(e.DirtyUpdates)
	e.UpdateStarts = maps.Clone(e.UpdateStarts)
	return e
}
