package windows

import (
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// cbsDeploymentPlanBuiltin explicitly captures the complete validated action
// projection. Its result retains execution evidence but not the population's
// admission graph, package manifests, or callbacks. The original population is
// unchanged. Neither this projection nor its inspection lists grant completion.
func cbsDeploymentPlanBuiltin(population *uup.CBSOrdinaryPopulation, names map[string]string) *starlark.Builtin {
	return starlark.NewBuiltin("cbs_population.deployment_plan", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("cbs_population.deployment_plan", args, kwargs); err != nil {
			return nil, err
		}
		actions, err := uup.PlanCBSDeploymentActions(population)
		if err != nil {
			return nil, err
		}
		return cbsCapturedDeploymentPlan(actions, population.Executions, population.Admissions, names), nil
	})
}

// This helper deliberately receives no population/index pointer: none can be
// captured by a returned method. Actions are freshly owned by native validation;
// executions/names are private immutable evidence already owned by the binding.
func cbsCapturedDeploymentPlan(actions []uup.CBSDeploymentAction, executions []uup.CBSOrdinaryExecution, admissions int, names map[string]string) starlark.Value {
	provider := func() ([]uup.CBSDeploymentAction, error) { return actions, nil }
	return &cbsPopulationRecord{
		Record: starvalue.NewRecord(starlark.StringDict{
			"admissions":          starlark.MakeInt(admissions),
			"execution_count":     starlark.MakeInt(len(executions)),
			"selected_executions": cbsSelectedExecutionsBuiltin(executions, names),
			"deployment_actions":  cbsDeploymentActionsFromProvider(provider, names),
			"install_marks":       cbsInstallMarksFromProvider(provider),
		}),
		nativeExecutions: executions,
		names:            names,
	}
}
