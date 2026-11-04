package uup

import (
	"fmt"
	"strings"
)

// CBSOrdinaryRequest is one already-resolved ordinary AddPackage request.
// Roots have already passed root-owner policy. A missing owner is not a self
// owner. Force-state, CBSBLR owner clearing, capability wrappers, pending state,
// session overrides of absent-start/absent-target skipping, execution items
// that prohibit raising their target, and feature-controlled
// staged-to-staged restaging are outside this path.
type CBSOrdinaryRequest struct {
	Identity                                  AssemblyIdentity
	Owner                                     string
	State, Integration, Ceiling               uint32
	PreserveStoreOwner, BypassOwners, SkipMUM bool
	// StageOnly models AddPackage flag 0x40: preserve the named resident
	// owner and cap newly staged updates, propagating to package children.
	StageOnly bool
}

// CBSOrdinaryMUMRequests supplies the explicit result of MUM/supersedence policy.
// BeforeUpdates is processed depth first before this package's updates; Deferred
// is processed in insertion order after every root and immediate child drains.
// This callback does not execute component/driver actions or change component
// owners. It must not perform external effects: planning can subsequently fail.
type CBSOrdinaryMUMRequests struct {
	BeforeUpdates, Deferred []CBSOrdinaryRequest
}

// CBSOrdinaryPopulationPolicy resolves policy not encoded by ordinary owner
// aggregation. Callbacks receive immutable snapshots and must be side-effect
// free. Applicability must return a resolved state, not the no-parent sentinel.
// PopulateMUM is required even if the selected policy produces no requests.
// Its action argument distinguishes supersedence (2/3) from lower-version
// reinstallation (4/5/6); silently treating both as supersedence is incorrect.
// OmittedReferences explicitly allows unavailable package references to be
// skipped. Apart from the explicit native optional-resolution policies below,
// missing references are errors, not silent feature removal.
// WorkLimit bounds admissions, update evaluations and queued events together.
type CBSOrdinaryPopulationPolicy struct {
	Applicability     func(AssemblyIdentity, *CBSUpdateStateIndex) (uint32, error)
	PopulateMUM       func(AssemblyIdentity, *CBSUpdateStateIndex, CBSExecutionAction) (CBSOrdinaryMUMRequests, error)
	OmittedReferences []AssemblyIdentity
	// AllowAbsentReferences enables the native optional resolve path only when
	// the containing update target is absent. Nonzero unavailable targets fail.
	AllowAbsentReferences bool
	// StoreLoadedPackages names contexts resolved from the installed package
	// store (native per-session source kind -1), not merely matching metadata
	// filenames. Their ordinary deployment references permit not-found results;
	// roots and MUM requests must still resolve. New source packages do not gain
	// this permission from a nonzero target or an old package of the same family.
	StoreLoadedPackages []AssemblyIdentity
	// LCUSession models session task flags established by AddPackageTask for
	// an explicit Package_for_RollupFix install/stage task (0x10/0x10000).
	// It requires a matching root at state installed/staged, and permits only
	// not-found deployment children, never missing roots or MUM requests.
	LCUSession bool
	WorkLimit  int
	Watch      *CBSOrdinaryWatchPolicy
}

// CBSOrdinaryExecution retains only execution-owner overlays, in first-insertion
// order (after MUM recursion and update publication, before child admissions),
// not a copy of every store owner. A repeated named request replaces its
// state while preserving its first execution integration. Dirty normalizes only
// superseded (0x50) to staged (0x40); it is NOT the action-state normalization.
// These values do not authorize persistence, permanence, removals or commit.
type CBSOrdinaryExecution struct {
	Identity            AssemblyIdentity
	IntendedState       uint32
	Owners              []CBSPackageOwnerIntent
	Updates             map[string]uint32
	MUMPopulated, Dirty bool
	// MUMProcessed is the current execution flag; unlike MUMPopulated (ever),
	// it is cleared by a subsequent merge. MUMPasses counts completed callbacks.
	MUMProcessed bool
	MUMPasses    int
	Action       CBSExecutionAction
	// DirtyUpdates and WatchProcessed are meaningful only when Watch is enabled.
	// Dirty is sticky; DirtyUpdates clear only after a notification drains.
	DirtyUpdates   map[string]bool
	WatchProcessed bool
	// UpdateStarts retains the first resolved callback result, before publication.
	// Merges and notifications never replace it. Populated only with Watch;
	// these are population-time inputs, not post-stage CSI current states.
	UpdateStarts map[string]CBSOrdinaryUpdateStart
}

// CBSUnresolvedPackageReference records an optional not-found lookup. It is
// not a package admission or proof of installed content. Available identities
// are always processed, and parse/corruption errors never become these records.
type CBSUnresolvedPackageReference struct {
	Parent, Package AssemblyIdentity
	UpdateName      string
	IntendedState   uint32
	Reason          string
}

type CBSOrdinaryPopulation struct {
	Index                *CBSUpdateStateIndex
	Executions           []CBSOrdinaryExecution
	Admissions           int
	UnresolvedReferences []CBSUnresolvedPackageReference
}

// PlanCBSOrdinaryPopulation evaluates an explicitly selected ordinary population
// prefix, not a complete CBS transaction. All updates of a package are published
// in manifest order before any child reference is admitted. Each child then
// drains depth first, preserving manifest reference order. MUM policy runs for
// each eligible action, including installed-downward lower-version reinstallation.
//
// Optional explicit watch policy schedules dependent/satellite admissions.
// No component actions, finalized applicability
// cache, permanence, CSI writes or final CurrentState is inferred. Callers must
// establish that ordinary admission applies; this function must never be used
// as a fallback for unsupported transaction policy. Inputs and retained callback
// snapshots are unchanged on both success and failure; errors return no plan.
func PlanCBSOrdinaryPopulation(index *CBSUpdateStateIndex, storeOwners []CBSPackageOwnerIntent, roots []CBSOrdinaryRequest, policy CBSOrdinaryPopulationPolicy) (*CBSOrdinaryPopulation, error) {
	if index == nil || policy.Applicability == nil || policy.PopulateMUM == nil {
		return nil, fmt.Errorf("CBS ordinary population requires index and explicit applicability/MUM policy")
	}
	if policy.WorkLimit < 1 || policy.WorkLimit > 1<<22 || len(storeOwners) > 1<<20 || len(roots) > policy.WorkLimit || len(policy.OmittedReferences) > 1<<16 || len(policy.StoreLoadedPackages) > 1<<16 {
		return nil, fmt.Errorf("CBS ordinary population bounds exceeded")
	}
	if policy.Watch != nil && (policy.Watch.InitialUpdate == nil || policy.Watch.Dependents == nil || policy.Watch.Satellites == nil) {
		return nil, fmt.Errorf("CBS ordinary watch requires explicit initial-update, dependent and satellite policy")
	}
	// Clone memo state as well as package targets: even a failed planner must not
	// leave a caller's index with memo entries derived during this prefix.
	current, err := index.WithIntendedStates(nil)
	if err != nil {
		return nil, err
	}
	validOwners := make(map[string]bool)
	validateOwner := func(name string) error {
		if validOwners[name] {
			return nil
		}
		if err := validateCBSAdmissionOwnerName(name); err != nil {
			return err
		}
		validOwners[name] = true
		return nil
	}
	names := make(map[string]string, index.graph.packages.count)
	stores := make(map[string][]CBSPackageOwnerIntent)
	for key, ctx := range index.graph.packages.all() {
		names[strings.ToLower(ctx.name)] = key
	}
	for _, owner := range storeOwners {
		key, ok := names[strings.ToLower(owner.Package)]
		if !ok {
			return nil, fmt.Errorf("CBS store owner package has no context: %q", owner.Package)
		}
		stores[key] = append(stores[key], owner)
	}
	for key, owners := range stores {
		_, err := resolveCBSPackageAdmission(CBSPackageAdmission{Identity: index.graph.packages.get(key).input.Manifest.Identity, StoreOwners: owners, RequestedState: CBSStateUnspecified, Ceiling: CBSStateUnspecified, ApplicableState: CBSStateInstalled}, index.graph.packages.get(key).name, validateOwner)
		if err != nil {
			return nil, err
		}
	}
	if policy.LCUSession {
		valid := false
		for _, root := range roots {
			valid = valid || (strings.EqualFold(root.Identity.Name, "Package_for_RollupFix") &&
				(root.State == CBSStateInstalled || root.State == CBSStateStaged))
		}
		if !valid {
			return nil, fmt.Errorf("CBS LCU session requires an explicit RollupFix install/stage root")
		}
	}
	storeLoaded := make(map[string]bool, len(policy.StoreLoadedPackages))
	for _, id := range policy.StoreLoadedPackages {
		key := id.ExactKey()
		if storeLoaded[key] || index.graph.packages.get(key) == nil {
			return nil, fmt.Errorf("duplicate or unknown CBS store-loaded package %q", id.Name)
		}
		storeLoaded[key] = true
	}
	omitted := make(map[string]bool, len(policy.OmittedReferences))
	for _, id := range policy.OmittedReferences {
		if _, err := cbsPackageName(id); err != nil {
			return nil, err
		}
		key := id.ExactKey()
		if omitted[key] || index.graph.packages.get(key) != nil {
			return nil, fmt.Errorf("duplicate or available omitted CBS reference %q", id.Name)
		}
		omitted[key] = true
	}
	type event struct {
		request       CBSOrdinaryRequest
		updates       bool
		mumDone       bool
		mumAfterStage bool
		watchDone     bool
		satellites    bool
		notifier      int
	}
	queue := make([]event, 0, len(roots))
	deferred := []CBSOrdinaryRequest{}
	work := 0
	watchStarted := false
	result := &CBSOrdinaryPopulation{}
	activePackage, activePhase := "", "roots"
	workLimitError := func() error {
		return fmt.Errorf("CBS ordinary population work limit exceeded: phase=%s package=%q work=%d admissions=%d executions=%d queued=%d deferred=%d watching=%t", activePhase, activePackage, work, result.Admissions, len(result.Executions), len(queue), len(deferred), watchStarted)
	}
	// Charge when enqueuing, not only when popping, to bound fan-out/cycles before
	// a potentially unbounded queue can be constructed.
	enqueue := func(requests []CBSOrdinaryRequest) error {
		if len(requests) > policy.WorkLimit-work {
			return workLimitError()
		}
		work += len(requests)
		for i := len(requests) - 1; i >= 0; i-- {
			queue = append(queue, event{request: requests[i]})
		}
		return nil
	}
	if err := enqueue(roots); err != nil {
		return nil, err
	}
	enqueueMUM := func(request CBSOrdinaryRequest, more CBSOrdinaryMUMRequests, afterStage bool) error {
		if watchStarted && len(more.Deferred) != 0 {
			return fmt.Errorf("deferred CBS MUM work during watching requires transaction policy")
		}
		if len(more.Deferred) >= policy.WorkLimit-work {
			return workLimitError()
		}
		work += len(more.Deferred) + 1
		deferred = append(deferred, more.Deferred...)
		// Complete only after immediate recursion, before this package's updates.
		queue = append(queue, event{request: request, mumDone: !afterStage, mumAfterStage: afterStage})
		return enqueue(more.BeforeUpdates)
	}
	// A satellite scan is a continuation of each admission, not a sibling scan
	// computed from stale state before the preceding admission has completed.
	enqueueWatched := func(requests []CBSOrdinaryRequest, notifier int) error {
		if len(requests) > (policy.WorkLimit-work)/2 {
			return workLimitError()
		}
		work += 2 * len(requests)
		for i := len(requests) - 1; i >= 0; i-- {
			queue = append(queue, event{request: requests[i], satellites: true, notifier: notifier}, event{request: requests[i]})
		}
		return nil
	}
	positions := map[string]int{}
	registered := map[string]bool{}
	executionOrder := []int{}
	references := map[string]map[string][]AssemblyReference{}
	seenUpdates := map[string]map[string]bool{}
	watchPosition := 0
	watchAdmitted := false
	for {
		if len(queue) == 0 && len(deferred) != 0 {
			// Deferred requests were charged when collected.
			for i := len(deferred) - 1; i >= 0; i-- {
				queue = append(queue, event{request: deferred[i]})
			}
			deferred = nil
		}
		if len(queue) == 0 {
			if policy.Watch == nil {
				break
			}
			activePhase = "watch"
			watchStarted = true
			if watchPosition == len(executionOrder) {
				if !watchAdmitted {
					break
				}
				watchPosition, watchAdmitted = 0, false
			}
			if work == policy.WorkLimit {
				return nil, workLimitError()
			}
			work++
			position := executionOrder[watchPosition]
			watchPosition++
			entry := &result.Executions[position]
			if entry.WatchProcessed || (!entry.Dirty && len(entry.DirtyUpdates) == 0) {
				continue
			}
			more, err := policy.Watch.Dependents(cloneCBSOrdinaryExecution(*entry), current)
			if err != nil {
				return nil, err
			}
			// The notifier is marked processed and update-dirty bits cleared only
			// after all dependent admissions and recursive satellite work return.
			queue = append(queue, event{request: CBSOrdinaryRequest{Identity: entry.Identity}, watchDone: true})
			if len(more) != 0 {
				watchAdmitted = true
			}
			if err := enqueueWatched(more, position); err != nil {
				return nil, err
			}
		}
		task := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		request := task.request
		key := current.graph.packages.keyForIdentity(request.Identity)
		ctx := current.graph.packages.get(key)
		if ctx == nil {
			return nil, fmt.Errorf("CBS admission package has no context: %q", request.Identity.Name)
		}
		activePackage = ctx.name
		activePhase = "admit"
		if task.watchDone {
			entry := &result.Executions[positions[key]]
			entry.WatchProcessed = true
			entry.DirtyUpdates = make(map[string]bool)
			continue
		}
		if task.satellites {
			more, err := policy.Watch.Satellites(cloneCBSOrdinaryExecution(result.Executions[task.notifier]), request.Identity, current)
			if err != nil {
				return nil, err
			}
			if err := enqueueWatched(more, task.notifier); err != nil {
				return nil, err
			}
			continue
		}
		if task.mumAfterStage {
			entry := &result.Executions[positions[key]]
			// Native rechecks after supersedence recursion. A nested admission
			// can change both the action and the processed flag before this point.
			if !entry.MUMProcessed && entry.Action >= CBSActionUninstall && entry.Action <= CBSActionUninstallUnstageUnresolve {
				more, err := policy.PopulateMUM(request.Identity, current, entry.Action)
				if err != nil {
					return nil, err
				}
				entry.MUMPasses++
				if err := enqueueMUM(request, more, false); err != nil {
					return nil, err
				}
				continue
			}
		}
		if task.mumDone || task.mumAfterStage {
			entry := &result.Executions[positions[key]]
			entry.MUMProcessed = true
			entry.MUMPopulated = true
			entry.MUMPasses++
			continue
		}
		if task.updates {
			activePhase = "updates"
			position := positions[key]
			refs, ready := references[key]
			if !ready {
				if len(ctx.input.Manifest.References) > maximumManifestReferences {
					return nil, fmt.Errorf("CBS package references exceed bound")
				}
				refs = map[string][]AssemblyReference{}
				for _, ref := range ctx.input.Manifest.References {
					if ref.Kind != "package" {
						continue
					}
					name := strings.ToLower(ref.UpdateName)
					if _, ok := ctx.updates[name]; !ok {
						return nil, fmt.Errorf("CBS package reference has unknown update %q", ref.UpdateName)
					}
					refs[name] = append(refs[name], ref)
				}
				references[key] = refs
			}
			// Child requests are collected, not admitted inside the update loop.
			// Otherwise later publications in this package are invisible to the first
			// child's parent detectors (including transitive memoized detections).
			children := []CBSOrdinaryRequest{}
			for _, update := range ctx.input.Manifest.PackageUpdates {
				if work == policy.WorkLimit {
					return nil, workLimitError()
				}
				work++
				// PopulateExecutionUpdates (cbscore 26100.9441, 0x9a720)
				// bypasses applicability entirely for an absent containing target.
				// Do not recurse into irrelevant (possibly self-referential) metadata.
				value := CBSUpdateState{}
				if ctx.input.IntendedState != CBSStateAbsent {
					value, err = current.ApplicableUpdateState(request.Identity, update.Name)
					if err != nil {
						return nil, err
					}
				}
				name := strings.ToLower(update.Name)
				previous, exists := result.Executions[position].Updates[name]
				if policy.Watch != nil {
					entry := &result.Executions[position]
					if seenUpdates[key] == nil {
						seenUpdates[key] = make(map[string]bool)
					}
					if !seenUpdates[key][name] {
						start, err := policy.Watch.InitialUpdate(request.Identity, update.Name, value.IntendedState, current)
						if err != nil {
							return nil, err
						}
						if !resolvedCBSParentState(start.State) {
							return nil, fmt.Errorf("unresolved CBS watch update start state %#x", start.State)
						}
						if entry.UpdateStarts == nil {
							entry.UpdateStarts = make(map[string]CBSOrdinaryUpdateStart)
						}
						entry.UpdateStarts[name] = start
						entry.DirtyUpdates[name] = !start.HasDeployments || cbsDirtyState(start.State) != cbsDirtyState(value.IntendedState)
						if !entry.DirtyUpdates[name] {
							delete(entry.DirtyUpdates, name)
						}
						seenUpdates[key][name] = true
					} else if cbsDirtyState(previous) != cbsDirtyState(value.IntendedState) {
						entry.DirtyUpdates[name] = true
					}
				}
				// CBS 26100.9703 PopulateExecutionUpdates 0x9a912..0x9a924:
				// flag 0x40 caps only updates whose retained start is <= Staged.
				// Already installed updates are not lowered by a staging request.
				if request.StageOnly && value.IntendedState > CBSStateStaged && result.Executions[position].UpdateStarts[name].State <= CBSStateStaged {
					value.IntendedState = CBSStateStaged
				}
				if !exists || previous != value.IntendedState {
					current, err = current.WithPublishedUpdates(request.Identity, map[string]uint32{name: value.IntendedState})
					if err != nil {
						return nil, err
					}
					result.Executions[position].Updates[name] = value.IntendedState
				}
				for _, ref := range refs[name] {
					target := current.graph.packages.get(current.graph.packages.keyForIdentity(ref.Identity))
					if target == nil {
						// Native AddPackage 0x97795..0x977a0 also allows
						// a not-found deployment child when its parent source
						// kind is -1 (loaded from the installed store).
						reason := ""
						switch {
						case policy.AllowAbsentReferences && value.IntendedState == CBSStateAbsent:
							reason = "absent-target"
						case storeLoaded[key]:
							reason = "store-parent"
						case policy.LCUSession:
							reason = "lcu-session"
						case omitted[current.graph.packages.keyForIdentity(ref.Identity)]:
							reason = "explicit-omission"
						}
						if reason != "" {
							if len(result.UnresolvedReferences) >= policy.WorkLimit {
								return nil, fmt.Errorf("CBS unresolved reference bound exceeded")
							}
							parent, child := request.Identity, ref.Identity
							parent.Attributes = append([]ManifestAttribute(nil), parent.Attributes...)
							child.Attributes = append([]ManifestAttribute(nil), child.Attributes...)
							result.UnresolvedReferences = append(result.UnresolvedReferences, CBSUnresolvedPackageReference{Parent: parent, Package: child, UpdateName: update.Name, IntendedState: value.IntendedState, Reason: reason})
							continue
						}
						return nil, fmt.Errorf("CBS package %q update %q references unavailable package %q version %q at target %#x", ctx.name, name, ref.Identity.Name, ref.Identity.Version, value.IntendedState)
					}
					integration := uint32(2)
					owner := ctx.name
					switch ref.Integrate {
					case "", "visible":
					case "hidden":
						integration = 3
					case "liberate":
						integration = 4
						for _, a := range target.input.Manifest.Package.Attributes {
							if a.Namespace == "" && a.Name == "releaseType" && a.Value == "Product" {
								owner = target.name
							}
						}
					default:
						return nil, fmt.Errorf("unsupported CBS reference integration %q", ref.Integrate)
					}
					if len(children) >= policy.WorkLimit-work {
						return nil, workLimitError()
					}
					children = append(children, CBSOrdinaryRequest{Identity: ref.Identity, Owner: owner, State: value.IntendedState, Integration: integration, Ceiling: CBSStateUnspecified, StageOnly: request.StageOnly})
				}
			}
			// Native AddPackage publishes the session target before MUM, but
			// inserts the execution into its array/map only after updates finish.
			// Immediate MUM admissions therefore precede this entry in watch order;
			// ordinary package-reference children follow it.
			if !registered[key] {
				registered[key] = true
				executionOrder = append(executionOrder, position)
			}
			if err := enqueue(children); err != nil {
				return nil, err
			}
			continue
		}
		if request.StageOnly && (policy.Watch == nil || policy.Watch.InitialUpdate == nil) {
			return nil, fmt.Errorf("CBS stage-only admission requires resolved update start states")
		}
		if request.Integration < 2 || request.Integration > 4 {
			return nil, fmt.Errorf("unsupported CBS admission integration %d", request.Integration)
		}
		position, exists := positions[key]
		if exists && !registered[key] {
			// Such a native admission creates another execution object, rather
			// than merging the not-yet-registered one. This ordinary single-object
			// path must not silently conflate those lifetimes.
			return nil, fmt.Errorf("CBS admission before execution registration requires multiple-object policy: %q", ctx.name)
		}
		var executionOwners []CBSPackageOwnerIntent
		if exists {
			executionOwners = result.Executions[position].Owners
		}
		applicable, err := policy.Applicability(request.Identity, current)
		if err != nil {
			return nil, err
		}
		admission, err := resolveCBSPackageAdmission(CBSPackageAdmission{Identity: request.Identity, StoreOwners: stores[key], ExecutionOwners: executionOwners, Owner: request.Owner, RequestedState: request.State, Ceiling: request.Ceiling, ApplicableState: applicable, PreserveStoreOwner: request.PreserveStoreOwner || request.StageOnly, BypassOwners: request.BypassOwners}, ctx.name, validateOwner)
		if err != nil {
			return nil, err
		}
		target := admission.IntendedState
		original := index.graph.packages.get(key).input.IntendedState
		// CBS 26100.9703 AddPackage 0x9677a..0x96866 skips an
		// absent-start/absent-target package before execution initialization
		// or merge and therefore before visiting any deployment children.
		// Use the retained start, not the mutable session target. Pending
		// states and the session override at +0x6dc are outside this ordinary
		// path. An absent request alone is not sufficient: other owners may
		// retain a nonzero target, and nonzero starts still require removal.
		if original == CBSStateAbsent && target == CBSStateAbsent {
			continue
		}
		if !exists {
			position = len(result.Executions)
			positions[key] = position
			published := make(map[string]uint32, ctx.published.count)
			for name, state := range ctx.published.all() {
				published[name] = state
			}
			result.Executions = append(result.Executions, CBSOrdinaryExecution{Identity: ctx.input.Manifest.Identity, IntendedState: ctx.input.IntendedState, Updates: published, DirtyUpdates: make(map[string]bool)})
		}
		entry := &result.Executions[position]
		if request.Owner != "" {
			found := false
			for i := range entry.Owners {
				if strings.EqualFold(entry.Owners[i].Owner, request.Owner) {
					entry.Owners[i].State = admission.EffectiveRequest
					found = true
					break
				}
			}
			if !found {
				entry.Owners = append(entry.Owners, CBSPackageOwnerIntent{Package: ctx.name, Owner: request.Owner, State: admission.EffectiveRequest, Integration: request.Integration})
			}
		}
		previous := entry.IntendedState
		actionFrom := original
		if exists && entry.MUMProcessed {
			actionFrom = previous
		}
		entry.Action = cbsOrdinaryAction(actionFrom, target)
		// Initialize differs from Merge: unchanged installed packages initially
		// select install servicing. Later equal-state merges select no action.
		if !exists && cbsDirtyState(original) == cbsDirtyState(target) && original >= CBSStateInstalled && target >= CBSStateInstalled {
			entry.Action = CBSActionInstall
		}
		entry.MUMProcessed = false
		entry.WatchProcessed = false
		entry.Dirty = entry.Dirty || cbsDirtyState(previous) != cbsDirtyState(target)
		entry.IntendedState = target
		result.Admissions++
		if ctx.input.IntendedState != target {
			current, err = current.WithIntendedStates([]CBSUpdateIntentChange{{Identity: request.Identity, IntendedState: target}})
			if err != nil {
				return nil, err
			}
		}
		if work == policy.WorkLimit {
			return nil, workLimitError()
		}
		work++
		queue = append(queue, event{request: request, updates: true})
		// ProcessMumServicing dispatches stage/install to supersedence and
		// installed-downward actions to lower-version reinstallation. It is not
		// a once-per-package hook. A merge consumes the preceding processed flag
		// when selecting its action, then clears the flag even for a skipped MUM.
		if !request.SkipMUM && entry.Action >= CBSActionStage && entry.Action <= CBSActionUninstallUnstageUnresolve {
			more, err := policy.PopulateMUM(request.Identity, current, entry.Action)
			if err != nil {
				return nil, err
			}
			if err := enqueueMUM(request, more, entry.Action <= CBSActionInstall); err != nil {
				return nil, err
			}
		}
	}
	ordered := make([]CBSOrdinaryExecution, 0, len(executionOrder))
	for _, position := range executionOrder {
		ordered = append(ordered, result.Executions[position])
	}
	result.Executions = ordered
	result.Index = current
	return result, nil
}
