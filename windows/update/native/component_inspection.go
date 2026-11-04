package native

import (
	"fmt"
	"path"
	"strings"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// inspectServicingComponents exposes the selected identity and predecessor, not
// installed-state or payload validation. Pagination is over matching components
// in stable stage/plan order, so bounded clients can inspect the whole closure.
func inspectServicingComponents(plans []uup.StageAssemblyPlan, features []string, featureID, namePrefix string, offset, limit int) (starlark.Value, error) {
	if offset < 0 || limit < 0 || limit > 1000 {
		return nil, fmt.Errorf("inspect_servicing_components: offset must be nonnegative and limit between 0 and 1000")
	}
	if len(plans) != len(features) {
		return nil, fmt.Errorf("inspect_servicing_components: mismatched stage metadata")
	}
	entries := []starlark.Value{}
	total := 0
	found := featureID == ""
	for stage, plan := range plans {
		if featureID != "" && !strings.EqualFold(featureID, features[stage]) {
			continue
		}
		found = true
		for _, component := range plan.Components {
			if !strings.HasPrefix(strings.ToLower(component.Identity.Name), strings.ToLower(namePrefix)) {
				continue
			}
			index := total
			total++
			if index < offset || len(entries) >= limit {
				continue
			}
			entries = append(entries, starvalue.NewRecord(starlark.StringDict{
				"feature_id":    starlark.String(features[stage]),
				"name":          starlark.String(component.Identity.Name),
				"version":       starlark.String(component.Identity.Version),
				"architecture":  starlark.String(component.Identity.ProcessorArchitecture),
				"language":      starlark.String(component.Identity.Language),
				"stem":          starlark.String(component.Stem),
				"previous_stem": starlark.String(component.PreviousStem),
				"staged_only":   starlark.Bool(component.StagedOnly),
				"store_path":    starlark.String("/Windows/WinSxS/Manifests/" + path.Base(strings.ReplaceAll(component.Path, `\`, "/"))),
				"selected_by":   starlark.String(component.SelectedBy),
			}))
		}
	}
	if !found {
		return nil, fmt.Errorf("inspect_servicing_components: unknown installed-OS feature %q", featureID)
	}
	// Avoid overflow even for an offset beyond the end of the plan.
	next := min(offset, total) + len(entries)
	return starvalue.NewRecord(starlark.StringDict{
		"components": starlark.NewList(entries), "total": starlark.MakeInt(total),
		"next_offset": starlark.MakeInt(next), "has_more": starlark.Bool(next < total),
	}), nil
}
