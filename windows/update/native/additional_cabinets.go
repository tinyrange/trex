package native

import (
	"fmt"
	"github.com/tinyrange/trex/archive/wim"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"path"
	"strings"

	"github.com/tinyrange/trex/storage"
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

type additionalCabinet struct {
	feature string
	file    storage.Reader
	msu     bool
}

// Copy caller ordering before the preparation worker starts. The caller owns
// acquisition and outer-package authentication; CIX source/target hashes remain
// mandatory in OpenCanonicalStage. This does not create installed CBS state.
func unpackAdditionalCabinets(value *starlark.Dict, servicingOnly bool) ([]additionalCabinet, error) {
	if value == nil || value.Len() == 0 {
		return nil, nil
	}
	if !servicingOnly || value.Len() > 32 {
		return nil, fmt.Errorf("update_media: additional_cabinets requires servicing_only and at most 32 entries")
	}
	result := make([]additionalCabinet, 0, value.Len())
	names := make(map[string]bool)
	for _, item := range value.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok || name == "" || len(name) > 256 || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\x00\r\n/\\") || names[strings.ToLower(name)] {
			return nil, fmt.Errorf("update_media: additional cabinet feature IDs must be unique nonempty names")
		}
		file, ok := item[1].(starvalue.File)
		if !ok || file.Size() <= 0 || file.Size() > maximumReferencePayload {
			return nil, fmt.Errorf("update_media: additional cabinet %q requires a bounded nonempty file", name)
		}
		names[strings.ToLower(name)] = true
		result = append(result, additionalCabinet{feature: name, file: file})
	}
	return result, nil
}

func appendAdditionalStages(stages []uup.UpdateStagePlan, cabinets []additionalCabinet) ([]uup.UpdateStagePlan, error) {
	names := make(map[string]bool, len(stages)+len(cabinets))
	for _, stage := range stages {
		names[strings.ToLower(stage.FeatureID)] = true
	}
	result := append([]uup.UpdateStagePlan(nil), stages...)
	for _, cabinet := range cabinets {
		key := strings.ToLower(cabinet.feature)
		if names[key] {
			return nil, fmt.Errorf("update_media: additional cabinet duplicates feature %q", cabinet.feature)
		}
		names[key] = true
		result = append(result, uup.UpdateStagePlan{FeatureID: cabinet.feature, Scope: "installed-os"})
	}
	return result, nil
}

// unpackAdditionalMSUs uses the same bounded file/name admission as cabinets.
// Only the parser selection differs. Signature/hash verification stays with the
// caller; native express reconstruction still verifies every content digest.
func unpackAdditionalMSUs(value *starlark.Dict, servicingOnly bool) ([]additionalCabinet, error) {
	result, err := unpackAdditionalCabinets(value, servicingOnly)
	if err != nil {
		return nil, fmt.Errorf("additional_msus: %w", err)
	}
	for i := range result {
		result[i].msu = true
	}
	return result, nil
}

func openAdditionalStage(input additionalCabinet, cache *uup.StageMetadataCache) (*uup.CumulativeStage, error) {
	if !input.msu {
		return uup.OpenCanonicalStageCache(input.feature, input.file, cache)
	}
	// Catalog MSUs use an outer WIM containing one express metadata WIM and
	// one PSF. Ignore deployment helpers, but never silently choose between
	// multiple content graphs. The caller must separately include its SSU.
	outer, err := wim.OpenWithCache(input.file, bytecache.New(64<<20), 1)
	if err != nil {
		return nil, fmt.Errorf("catalog MSU: %w", err)
	}
	entries, err := outer.List("/image1")
	if err != nil {
		return nil, err
	}
	var metadata, payload string
	for _, entry := range entries {
		if entry.Directory {
			continue
		}
		switch strings.ToLower(path.Ext(entry.Name)) {
		case ".wim":
			if metadata != "" {
				return nil, fmt.Errorf("catalog MSU contains multiple metadata WIMs")
			}
			metadata = entry.Path
		case ".psf":
			if payload != "" {
				return nil, fmt.Errorf("catalog MSU contains multiple PSFs")
			}
			payload = entry.Path
		}
	}
	if metadata == "" || payload == "" {
		return nil, fmt.Errorf("catalog MSU requires exactly one metadata WIM and PSF")
	}
	metadataFile, err := outer.OpenFile(metadata)
	if err != nil {
		return nil, err
	}
	psf, err := outer.OpenFile(payload)
	if err != nil {
		return nil, err
	}
	return uup.OpenCumulativeStagePayloadsCache([]string{metadata}, []storage.Reader{metadataFile}, payload, psf, cache)
}

// Explicit ordering is necessary when a catalog LCU must follow its SSU but
// precede a separately acquired .NET rollup. Require a complete permutation.
func orderAdditionalStages(inputs []additionalCabinet, order *starlark.List) ([]additionalCabinet, error) {
	if order == nil || order.Len() == 0 {
		return inputs, nil
	}
	if order.Len() != len(inputs) {
		return nil, fmt.Errorf("additional_stage_order must name every additional stage exactly once")
	}
	byName := make(map[string]additionalCabinet, len(inputs))
	for _, input := range inputs {
		key := strings.ToLower(input.feature)
		if _, exists := byName[key]; exists {
			return nil, fmt.Errorf("duplicate additional stage %q", input.feature)
		}
		byName[key] = input
	}
	result := make([]additionalCabinet, 0, len(inputs))
	for i := 0; i < order.Len(); i++ {
		name, ok := starlark.AsString(order.Index(i))
		if !ok {
			return nil, fmt.Errorf("additional_stage_order requires string IDs")
		}
		key := strings.ToLower(name)
		item, ok := byName[key]
		if !ok {
			return nil, fmt.Errorf("additional_stage_order repeats or names unknown stage %q", name)
		}
		result = append(result, item)
		delete(byName, key)
	}
	return result, nil
}
