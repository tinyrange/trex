package windows

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func cbsPopulationRequests(index *uup.CBSUpdateStateIndex, values *starlark.List) ([]uup.CBSOrdinaryRequest, error) {
	if values == nil {
		return nil, nil
	}
	if values.Len() > 1<<20 {
		return nil, fmt.Errorf("CBS population requests exceed bound")
	}
	result := make([]uup.CBSOrdinaryRequest, 0, values.Len())
	for value := range values.Elements() {
		entry, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("CBS population request must be a dict")
		}
		var name, owner string
		var state, integration, ceiling uint32
		var preserve, bypass, skip, stageOnly bool
		if err := starlark.UnpackArgs("CBS ordinary request", nil, entry.Items(), "package", &name, "owner", &owner, "state", &state, "integration", &integration, "ceiling", &ceiling, "preserve_store_owner?", &preserve, "bypass_owners?", &bypass, "skip_mum?", &skip, "stage_only?", &stageOnly); err != nil {
			return nil, err
		}
		id, err := index.PackageIdentity(name)
		if err != nil {
			return nil, err
		}
		result = append(result, uup.CBSOrdinaryRequest{Identity: id, Owner: owner, State: state, Integration: integration, Ceiling: ceiling, PreserveStoreOwner: preserve, BypassOwners: bypass, SkipMUM: skip, StageOnly: stageOnly})
	}
	return result, nil
}

func cbsPopulationBuiltin(index *uup.CBSUpdateStateIndex) *starlark.Builtin {
	return starlark.NewBuiltin("cbs_update_index.ordinary_population", func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var roots, stores, omitted, storeLoaded *starlark.List
		var watch *starlark.Dict
		var applicable, mum starlark.Callable
		var limit int
		var allowAbsent, lcuSession bool
		if err := starlark.UnpackArgs("cbs_update_index.ordinary_population", args, kwargs, "roots", &roots, "store_owners", &stores, "applicability", &applicable, "populate_mum", &mum, "work_limit", &limit, "omitted_references?", &omitted, "watch?", &watch, "allow_absent_references?", &allowAbsent, "store_loaded_packages?", &storeLoaded, "lcu_session?", &lcuSession); err != nil {
			return nil, err
		}
		requests, err := cbsPopulationRequests(index, roots)
		if err != nil {
			return nil, err
		}
		if stores.Len() > 1<<20 {
			return nil, fmt.Errorf("CBS population store owners exceed bound")
		}
		owners := make([]uup.CBSPackageOwnerIntent, 0, stores.Len())
		for value := range stores.Elements() {
			entry, ok := value.(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("CBS store owner must be a dict")
			}
			var o uup.CBSPackageOwnerIntent
			if err := starlark.UnpackArgs("CBS store owner", nil, entry.Items(), "package", &o.Package, "owner", &o.Owner, "state", &o.State, "integration", &o.Integration); err != nil {
				return nil, err
			}
			owners = append(owners, o)
		}
		omittedIDs, err := cbsPackageNames(omitted)
		if err != nil {
			return nil, err
		}
		storeLoadedIDs, err := cbsPackageNames(storeLoaded)
		if err != nil {
			return nil, err
		}
		names := map[string]string{}
		for name := range index.PackageIntendedStates() {
			id, err := index.PackageIdentity(name)
			if err != nil {
				return nil, err
			}
			names[id.ExactKey()] = name
		}
		policy := uup.CBSOrdinaryPopulationPolicy{WorkLimit: limit, OmittedReferences: omittedIDs, AllowAbsentReferences: allowAbsent, StoreLoadedPackages: storeLoadedIDs, LCUSession: lcuSession}
		policy.Applicability = func(id uup.AssemblyIdentity, snapshot *uup.CBSUpdateStateIndex) (uint32, error) {
			value, err := starlark.Call(thread, applicable, starlark.Tuple{starlark.String(names[id.ExactKey()]), cbsUpdateIndexRecord(snapshot)}, nil)
			if err != nil {
				return 0, err
			}
			var state uint32
			if err := starlark.AsInt(value, &state); err != nil {
				return 0, err
			}
			return state, nil
		}
		policy.PopulateMUM = func(id uup.AssemblyIdentity, snapshot *uup.CBSUpdateStateIndex, action uup.CBSExecutionAction) (uup.CBSOrdinaryMUMRequests, error) {
			value, err := starlark.Call(thread, mum, starlark.Tuple{starlark.String(names[id.ExactKey()]), cbsUpdateIndexRecord(snapshot), starlark.MakeUint64(uint64(action))}, nil)
			if err != nil {
				return uup.CBSOrdinaryMUMRequests{}, err
			}
			entry, ok := value.(*starlark.Dict)
			if !ok {
				return uup.CBSOrdinaryMUMRequests{}, fmt.Errorf("CBS populate_mum must return a dict with before_updates and deferred")
			}
			var before, later *starlark.List
			if err := starlark.UnpackArgs("CBS MUM requests", nil, entry.Items(), "before_updates", &before, "deferred", &later); err != nil {
				return uup.CBSOrdinaryMUMRequests{}, err
			}
			immediate, err := cbsPopulationRequests(index, before)
			if err != nil {
				return uup.CBSOrdinaryMUMRequests{}, err
			}
			deferred, err := cbsPopulationRequests(index, later)
			return uup.CBSOrdinaryMUMRequests{BeforeUpdates: immediate, Deferred: deferred}, err
		}
		if watch != nil {
			var initial, dependents, satellites starlark.Callable
			if err := starlark.UnpackArgs("CBS watch policy", nil, watch.Items(), "initial_update", &initial, "dependents", &dependents, "satellites", &satellites); err != nil {
				return nil, err
			}
			policy.Watch = &uup.CBSOrdinaryWatchPolicy{}
			policy.Watch.InitialUpdate = func(id uup.AssemblyIdentity, update string, target uint32, snapshot *uup.CBSUpdateStateIndex) (uup.CBSOrdinaryUpdateStart, error) {
				var start uup.CBSOrdinaryUpdateStart
				value, err := starlark.Call(thread, initial, starlark.Tuple{starlark.String(names[id.ExactKey()]), starlark.String(update), starlark.MakeUint64(uint64(target)), cbsUpdateIndexRecord(snapshot)}, nil)
				if err != nil {
					return start, err
				}
				entry, ok := value.(*starlark.Dict)
				if !ok {
					return start, fmt.Errorf("CBS initial_update must return dict(state, has_deployments)")
				}
				err = starlark.UnpackArgs("CBS initial update", nil, entry.Items(), "state", &start.State, "has_deployments", &start.HasDeployments)
				return start, err
			}
			watchRequests := func(fn starlark.Callable, e uup.CBSOrdinaryExecution, id *uup.AssemblyIdentity, snapshot *uup.CBSUpdateStateIndex) ([]uup.CBSOrdinaryRequest, error) {
				notifier, err := cbsOrdinaryExecutionRecord(e, names)
				if err != nil {
					return nil, err
				}
				args := starlark.Tuple{notifier}
				if id != nil {
					args = append(args, starlark.String(names[id.ExactKey()]))
				}
				args = append(args, cbsUpdateIndexRecord(snapshot))
				value, err := starlark.Call(thread, fn, args, nil)
				if err != nil {
					return nil, err
				}
				list, ok := value.(*starlark.List)
				if !ok {
					return nil, fmt.Errorf("CBS watch callback must return a request list")
				}
				return cbsPopulationRequests(index, list)
			}
			policy.Watch.Dependents = func(e uup.CBSOrdinaryExecution, snapshot *uup.CBSUpdateStateIndex) ([]uup.CBSOrdinaryRequest, error) {
				return watchRequests(dependents, e, nil, snapshot)
			}
			policy.Watch.Satellites = func(e uup.CBSOrdinaryExecution, id uup.AssemblyIdentity, snapshot *uup.CBSUpdateStateIndex) ([]uup.CBSOrdinaryRequest, error) {
				return watchRequests(satellites, e, &id, snapshot)
			}
		}
		result, err := uup.PlanCBSOrdinaryPopulation(index, owners, requests, policy)
		if err != nil {
			return nil, err
		}
		unresolved := make([]starlark.Value, 0, len(result.UnresolvedReferences))
		for _, ref := range result.UnresolvedReferences {
			unresolved = append(unresolved, starvalue.NewRecord(starlark.StringDict{
				"parent":         starlark.String(names[ref.Parent.ExactKey()]),
				"package":        csiIdentityRecord(ref.Package),
				"update":         starlark.String(ref.UpdateName),
				"intended_state": starlark.MakeUint64(uint64(ref.IntendedState)),
				"reason":         starlark.String(ref.Reason),
			}))
		}
		return &cbsPopulationRecord{
			Record:           starvalue.NewRecord(starlark.StringDict{"unresolved_references": starlark.NewList(unresolved), "index": cbsUpdateIndexRecord(result.Index), "execution_count": starlark.MakeInt(len(result.Executions)), "selected_executions": cbsSelectedExecutionsBuiltin(result.Executions, names), "admissions": starlark.MakeInt(result.Admissions), "deployment_actions": cbsDeploymentActionsBuiltin(result, names), "install_marks": cbsInstallMarksBuiltin(result), "deployment_plan": cbsDeploymentPlanBuiltin(result, names)}),
			nativeExecutions: result.Executions,
			names:            names,
		}, nil
	})
}

// cbsPopulationRecord avoids duplicating the native execution graph until an
// inspection consumer needs it. Actions and install marks use the private native
// population, not these mutable records. execution_count is the native count,
// independent of subsequent edits to the inspection list.
type cbsPopulationRecord struct {
	*starvalue.Record
	mu               sync.Mutex
	nativeExecutions []uup.CBSOrdinaryExecution
	names            map[string]string
	executions       *starlark.List
	frozen           bool
}

func (r *cbsPopulationRecord) Attr(name string) (starlark.Value, error) {
	if name != "executions" {
		return r.Record.Attr(name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.executions == nil {
		values := make([]starlark.Value, 0, len(r.nativeExecutions))
		for _, e := range r.nativeExecutions {
			value, err := cbsOrdinaryExecutionRecord(e, r.names)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		r.executions = starlark.NewList(values)
		if r.frozen {
			r.executions.Freeze()
		}
		r.nativeExecutions, r.names = nil, nil
	}
	return r.executions, nil
}

func (r *cbsPopulationRecord) AttrNames() []string {
	names := append(r.Record.AttrNames(), "executions")
	slices.Sort(names)
	return names
}

func (r *cbsPopulationRecord) String() string {
	return "<record " + strings.Join(r.AttrNames(), ", ") + ">"
}

func (r *cbsPopulationRecord) Freeze() {
	r.mu.Lock()
	if r.frozen {
		r.mu.Unlock()
		return
	}
	r.frozen = true
	executions := r.executions
	r.mu.Unlock()
	// Mutable inspection lists can contain this record. Mark before descending
	// and do not hold the lock across recursive Freeze calls.
	r.Record.Freeze()
	if executions != nil {
		executions.Freeze()
	}
}

func cbsOrdinaryExecutionRecord(e uup.CBSOrdinaryExecution, names map[string]string) (starlark.Value, error) {
	owners := make([]starlark.Value, 0, len(e.Owners))
	for _, o := range e.Owners {
		owners = append(owners, starvalue.NewRecord(starlark.StringDict{"package": starlark.String(o.Package), "owner": starlark.String(o.Owner), "state": starlark.MakeUint64(uint64(o.State)), "integration": starlark.MakeUint64(uint64(o.Integration))}))
	}
	updates := starlark.NewDict(len(e.Updates))
	for _, name := range slices.Sorted(maps.Keys(e.Updates)) {
		state := e.Updates[name]
		if err := updates.SetKey(starlark.String(name), starlark.MakeUint64(uint64(state))); err != nil {
			return nil, err
		}
	}
	starts := starlark.NewDict(len(e.UpdateStarts))
	for _, name := range slices.Sorted(maps.Keys(e.UpdateStarts)) {
		start := e.UpdateStarts[name]
		value := starvalue.NewRecord(starlark.StringDict{"state": starlark.MakeUint64(uint64(start.State)), "has_deployments": starlark.Bool(start.HasDeployments)})
		if err := starts.SetKey(starlark.String(name), value); err != nil {
			return nil, err
		}
	}
	dirty := make([]starlark.Value, 0, len(e.DirtyUpdates))
	for _, name := range slices.Sorted(maps.Keys(e.DirtyUpdates)) {
		dirty = append(dirty, starlark.String(name))
	}

	return starvalue.NewRecord(starlark.StringDict{"package": starlark.String(names[e.Identity.ExactKey()]), "intended_state": starlark.MakeUint64(uint64(e.IntendedState)), "owners": starlark.NewList(owners), "updates": updates, "update_starts": starts, "mum_populated": starlark.Bool(e.MUMPopulated), "mum_processed": starlark.Bool(e.MUMProcessed), "mum_passes": starlark.MakeInt(e.MUMPasses), "action": starlark.MakeUint64(uint64(e.Action)), "dirty": starlark.Bool(e.Dirty), "dirty_updates": starlark.NewList(dirty), "watch_processed": starlark.Bool(e.WatchProcessed)}), nil
}

// cbsSelectedExecutionsBuiltin exports only requested native package records.
// The mutable all-executions inspection list is never an authority for this
// view. Each call returns independent dictionaries, and missing packages are
// omitted so callers can intersect a transport inventory with admitted work.
func cbsSelectedExecutionsBuiltin(executions []uup.CBSOrdinaryExecution, names map[string]string) *starlark.Builtin {
	return starlark.NewBuiltin("selected_executions", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var packages *starlark.List
		var actions *starlark.List
		if err := starlark.UnpackArgs("selected_executions", args, kwargs, "packages", &packages, "actions?", &actions); err != nil {
			return nil, err
		}
		if packages.Len() > 65536 {
			return nil, fmt.Errorf("selected_executions: too many package names")
		}
		var actionSet map[uint32]bool
		if actions != nil {
			if actions.Len() > 7 {
				return nil, fmt.Errorf("selected_executions: action filter exceeds bound")
			}
			actionSet = make(map[uint32]bool, actions.Len())
			for i := 0; i < actions.Len(); i++ {
				var action uint32
				if err := starlark.AsInt(actions.Index(i), &action); err != nil || action > 6 {
					return nil, fmt.Errorf("selected_executions: actions must be integers in 0..6")
				}
				actionSet[action] = true
			}
		}
		selected := make(map[string]bool, packages.Len())
		for i := 0; i < packages.Len(); i++ {
			name, ok := starlark.AsString(packages.Index(i))
			if !ok || name == "" {
				return nil, fmt.Errorf("selected_executions: packages must contain nonempty strings")
			}
			selected[strings.ToLower(name)] = true
		}
		values := make([]starlark.Value, 0, min(len(selected), len(executions)))
		for _, e := range executions {
			if actionSet != nil && !actionSet[uint32(e.Action)] {
				continue
			}
			if !selected[strings.ToLower(names[e.Identity.ExactKey()])] {
				continue
			}
			value, err := cbsOrdinaryExecutionRecord(e, names)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return starlark.NewList(values), nil
	})
}
