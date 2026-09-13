package native

import (
	"fmt"
	"path"
	"strings"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// plannedServicingFile selects a declared file effect, including unchanged
// inherited files which have no canonical content-target record of their own.
func plannedServicingFile(plans []uup.StageEffectPlan, features []string, featureID, storePath string) (int, uup.StageFileEffect, error) {
	if len(plans) != len(features) {
		return 0, uup.StageFileEffect{}, fmt.Errorf("mismatched stage metadata")
	}
	normalize := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, "\\", "/")) }
	for stage, feature := range features {
		if !strings.EqualFold(feature, featureID) {
			continue
		}
		var selected *uup.StageFileEffect
		for _, file := range plans[stage].Files {
			if normalize(file.StorePath) != normalize(storePath) {
				continue
			}
			if selected != nil {
				return 0, uup.StageFileEffect{}, fmt.Errorf("ambiguous planned store path %q", storePath)
			}
			selected = &file
		}
		if selected == nil {
			return 0, uup.StageFileEffect{}, fmt.Errorf("unknown planned store path %q", storePath)
		}
		return stage, *selected, nil
	}
	return 0, uup.StageFileEffect{}, fmt.Errorf("unknown installed-OS feature %q", featureID)
}

// inspectServicingFiles exposes declared placement only. It has no payload
// reader and cannot be mistaken for the mandatory reconstruction/hash pass.
// Name and destination-prefix selectors form a union; plan order is preserved.
func inspectServicingFiles(plans []uup.StageEffectPlan, features []string, name, destinationPrefix string, limit int) (starlark.Value, error) {
	if limit < 0 || limit > 1000 {
		return nil, fmt.Errorf("inspect_servicing_files: limit must be between 0 and 1000")
	}
	if len(plans) != len(features) {
		return nil, fmt.Errorf("inspect_servicing_files: mismatched stage metadata")
	}
	normalize := func(value string) string { return strings.ToLower(strings.ReplaceAll(value, "\\", "/")) }
	name, destinationPrefix = normalize(name), normalize(destinationPrefix)
	if name == "" && destinationPrefix == "" {
		return nil, fmt.Errorf("inspect_servicing_files: name or destination_prefix is required")
	}
	files := []starlark.Value{}
	total := 0
	for stage, plan := range plans {
		for _, file := range plan.Files {
			matched := name != "" && (path.Base(normalize(file.SourceName)) == name || path.Base(normalize(file.StorePath)) == name)
			for _, destination := range file.Destinations {
				matched = matched || (destinationPrefix != "" && strings.HasPrefix(normalize(destination), destinationPrefix))
			}
			if !matched {
				continue
			}
			total++
			if len(files) >= limit {
				continue
			}
			destinations := make([]starlark.Value, len(file.Destinations))
			for index, destination := range file.Destinations {
				destinations[index] = starlark.String(destination)
			}
			files = append(files, starvalue.NewRecord(starlark.StringDict{
				"feature_id": starlark.String(features[stage]), "architecture": starlark.String(file.Architecture),
				"source_name": starlark.String(file.SourceName), "source_mode": starlark.String(file.SourceMode),
				"store_path": starlark.String(file.StorePath), "destinations": starlark.NewList(destinations),
			}))
		}
	}
	return starvalue.NewRecord(starlark.StringDict{
		"files": starlark.NewList(files), "total": starlark.MakeInt(total),
		"truncated": starlark.Bool(total > len(files)),
	}), nil
}
