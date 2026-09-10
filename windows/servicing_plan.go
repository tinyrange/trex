package windows

import (
	"fmt"

	"github.com/tinyrange/trex/archive/wim"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func servicingPlanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var baseValue, updatesValue starlark.Value
	packagesValue := starlark.Value(starlark.None)
	componentsValue := starlark.Value(starlark.None)
	image := "/image3"
	limit := 20
	baseValue = starlark.None
	if err := starlark.UnpackArgs("servicing_plan", args, kwargs, "updates", &updatesValue, "base?", &baseValue, "installed_packages?", &packagesValue, "installed_components?", &componentsValue, "image?", &image, "limit?", &limit); err != nil {
		return nil, err
	}
	if limit < 0 || limit > 1000 {
		return nil, fmt.Errorf("servicing_plan: limit must be between 0 and 1000")
	}
	iterable, ok := updatesValue.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("servicing_plan: updates got %s, want iterable", updatesValue.Type())
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	var stages []*uup.CumulativeStage
	var item starlark.Value
	for iterator.Next(&item) {
		var update *wim.Archive
		switch value := item.(type) {
		case *wim.Archive:
			update = value
		case starfile.File:
			var err error
			update, err = wim.Open(value)
			if err != nil {
				return nil, fmt.Errorf("servicing_plan: open update %d: %w", len(stages)+1, err)
			}
		default:
			return nil, fmt.Errorf("servicing_plan: update %d got %s, want wim or file", len(stages)+1, item.Type())
		}
		stage, err := uup.OpenCumulativeStage(update)
		if err != nil {
			return nil, fmt.Errorf("servicing_plan: open update %d: %w", len(stages)+1, err)
		}
		stages = append(stages, stage)
	}
	if len(stages) == 0 {
		return nil, fmt.Errorf("servicing_plan: at least one update is required")
	}
	var assemblyPlans []uup.StageAssemblyPlan
	var err error
	if base, ok := baseValue.(*wim.Archive); ok {
		assemblyPlans, err = uup.PlanAssemblyStages(base, image, stages)
	} else if baseValue != starlark.None {
		return nil, fmt.Errorf("servicing_plan: base got %s, want wim", baseValue.Type())
	} else {
		var packages, components []string
		packages, err = starlarkStrings("servicing_plan: installed_packages", packagesValue)
		if err != nil {
			return nil, err
		}
		components, err = starlarkStrings("servicing_plan: installed_components", componentsValue)
		if err != nil {
			return nil, err
		}
		assemblyPlans, err = uup.PlanAssemblyStagesFromInventory(packages, components, stages)
	}
	if err != nil {
		return nil, fmt.Errorf("servicing_plan: %w", err)
	}
	if len(assemblyPlans) != len(stages) {
		return nil, fmt.Errorf("servicing_plan: planner returned %d stage plans for %d stages", len(assemblyPlans), len(stages))
	}
	stageValues := make([]starlark.Value, len(stages))
	for index, stage := range stages {
		plan := assemblyPlans[index]
		packageValues := make([]starlark.Value, 0, min(limit, len(plan.Packages)))
		for _, pack := range plan.Packages[:min(limit, len(plan.Packages))] {
			packageValues = append(packageValues, starlark.String(pack.Path))
		}
		componentValues := make([]starlark.Value, 0, min(limit, len(plan.Components)))
		for _, component := range plan.Components[:min(limit, len(plan.Components))] {
			componentValues = append(componentValues, starlark.String(component.Path))
		}
		withBasis, payloadCount, sourceCount, carryCount := 0, 0, 0, 0
		if stage.Graph != nil {
			payloadCount = len(stage.Graph.Payloads)
			sourceCount = len(stage.Graph.Sources)
			carryCount = len(stage.Graph.Carries)
			for _, payload := range stage.Graph.Payloads {
				if payload.Basis != nil {
					withBasis++
				}
			}
		}
		stageValues[index] = starfile.NewRecord(starlark.StringDict{
			"carry_count":         starlark.MakeInt(carryCount),
			"component_count":     starlark.MakeInt(len(plan.Components)),
			"components":          starlark.NewList(componentValues),
			"metadata":            starlark.String(stage.MetadataName),
			"package_count":       starlark.MakeInt(len(plan.Packages)),
			"packages":            starlark.NewList(packageValues),
			"payload_count":       starlark.MakeInt(payloadCount),
			"psf":                 starlark.String(stage.PSFName),
			"source_count":        starlark.MakeInt(sourceCount),
			"with_basis_count":    starlark.MakeInt(withBasis),
			"without_basis_count": starlark.MakeInt(payloadCount - withBasis),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"complete": starlark.True,
		"stages":   starlark.NewList(stageValues),
	}), nil
}

func starlarkStrings(name string, value starlark.Value) ([]string, error) {
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("%s got %s, want iterable", name, value.Type())
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	var result []string
	var item starlark.Value
	for iterator.Next(&item) {
		text, ok := starlark.AsString(item)
		if !ok {
			return nil, fmt.Errorf("%s item got %s, want string", name, item.Type())
		}
		result = append(result, text)
	}
	return result, nil
}
