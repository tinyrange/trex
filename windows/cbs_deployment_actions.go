package windows

import (
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// Keep the native population private: mutable inspection records must not alter
// the evidence used to project deployment actions in a later call.
func cbsDeploymentActionsBuiltin(population *uup.CBSOrdinaryPopulation, names map[string]string) *starlark.Builtin {
	return cbsDeploymentActionsFromProvider(func() ([]uup.CBSDeploymentAction, error) { return uup.PlanCBSDeploymentActions(population) }, names)
}

func cbsDeploymentActionsFromProvider(actionsForCall func() ([]uup.CBSDeploymentAction, error), names map[string]string) *starlark.Builtin {
	return starlark.NewBuiltin("cbs_population.deployment_actions", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var changedOnly bool
		if err := starlark.UnpackArgs("cbs_population.deployment_actions", args, kwargs, "changed_only?", &changedOnly); err != nil {
			return nil, err
		}
		actions, err := actionsForCall()
		if err != nil {
			return nil, err
		}
		count := 0
		for _, action := range actions {
			if !changedOnly || action.Stage || action.Action != uup.CBSActionNone {
				count++
			}
		}
		values := make([]starlark.Value, 0, count)
		for _, action := range actions {
			if changedOnly && !action.Stage && action.Action == uup.CBSActionNone {
				continue
			}
			values = append(values, starvalue.NewRecord(starlark.StringDict{
				"package":           starlark.String(names[action.Package.ExactKey()]),
				"update":            starlark.String(action.UpdateName),
				"deployment":        csiIdentityRecord(action.Deployment),
				"driver":            starlark.Bool(action.Driver),
				"driver_attributes": assemblyAttributeRecords(action.DriverAttributes),
				"stage":             starlark.Bool(action.Stage),
				"action":            starlark.MakeUint64(uint64(action.Action)),
			}))
		}
		return starlark.NewList(values), nil
	})
}
