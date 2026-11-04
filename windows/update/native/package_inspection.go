package native

import (
	"fmt"
	"path"
	"strings"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// Inspect selected package manifest effects, not every MUM in the transport.
// Aggregate update.mum files are named by their canonical CBS store identity.
func inspectServicingPackages(plans []uup.StageEffectPlan, features []string, featureID string, offset, limit int) (starlark.Value, error) {
	if offset < 0 || limit < 0 || limit > 1000 || len(plans) != len(features) {
		return nil, fmt.Errorf("inspect_servicing_packages: invalid bounds or stage metadata")
	}
	packages := []starlark.Value{}
	total := 0
	found := featureID == ""
	for stage, plan := range plans {
		if featureID != "" && !strings.EqualFold(featureID, features[stage]) {
			continue
		}
		found = true
		for _, file := range plan.Files {
			if file.Kind != "package-manifest" {
				continue
			}
			index := total
			total++
			if index < offset || len(packages) >= limit {
				continue
			}
			packages = append(packages, starvalue.NewRecord(starlark.StringDict{
				"feature_id":  starlark.String(features[stage]),
				"package":     starlark.String(strings.TrimSuffix(path.Base(file.StorePath), ".mum")),
				"source_name": starlark.String(file.SourceName),
				"store_path":  starlark.String(file.StorePath),
			}))
		}
	}
	if !found {
		return nil, fmt.Errorf("inspect_servicing_packages: unknown installed-OS feature %q", featureID)
	}
	next := min(offset, total) + len(packages)
	return starvalue.NewRecord(starlark.StringDict{
		"packages": starlark.NewList(packages), "total": starlark.MakeInt(total),
		"next_offset": starlark.MakeInt(next), "has_more": starlark.Bool(next < total),
	}), nil
}
