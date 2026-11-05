package native

import (
	"fmt"
	"strings"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// Pagination is over ownership edges, not whole deployments, so even a large
// deployment remains a bounded read. This is plan evidence, not applied state.
func inspectServicingOwnership(plans []uup.StageAssemblyPlan, features []string, featureID, deploymentName string, offset, limit int) (starlark.Value, error) {
	if offset < 0 || limit < 0 || limit > 1000 || len(plans) != len(features) {
		return nil, fmt.Errorf("inspect_servicing_ownership: invalid bounds or stage metadata")
	}
	entries := []starlark.Value{}
	total := 0
	found := featureID == ""
	for stage, plan := range plans {
		if featureID != "" && !strings.EqualFold(featureID, features[stage]) {
			continue
		}
		found = true
		for _, deployment := range plan.Deployments {
			if deploymentName != "" && !strings.EqualFold(deploymentName, deployment.Identity.Name) {
				continue
			}
			active := false
			for _, source := range deployment.Sources {
				active = active || !source.StagedOnly
			}
			for _, component := range deployment.Components {
				index := total
				total++
				if index < offset || len(entries) >= limit {
					continue
				}
				entries = append(entries, starvalue.NewRecord(starlark.StringDict{
					"feature_id":              starlark.String(features[stage]),
					"deployment":              starlark.String(deployment.Identity.Name),
					"deployment_version":      starlark.String(deployment.Identity.Version),
					"deployment_architecture": starlark.String(deployment.Identity.ProcessorArchitecture),
					"active":                  starlark.Bool(active),
					"source_count":            starlark.MakeInt(len(deployment.Sources)),
					"component":               starlark.String(component.Identity.Name),
					"component_stem":          starlark.String(component.Stem),
				}))
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("inspect_servicing_ownership: unknown installed-OS feature %q", featureID)
	}
	next := min(offset, total) + len(entries)
	return starvalue.NewRecord(starlark.StringDict{"edges": starlark.NewList(entries), "total": starlark.MakeInt(total), "next_offset": starlark.MakeInt(next), "has_more": starlark.Bool(next < total)}), nil
}
