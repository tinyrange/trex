package uup

import (
	"sort"
	"strings"

	"github.com/tinyrange/trex/archive/wim"
)

// PlannedFileReadOrder returns a permutation for materializing the files with
// locality in their base WIM. It does not change the plan's semantic order:
// callers place results back at their original indices before applying them.
// These are metadata-only hints. All resolution and hash checks still happen
// in OpenPlannedFile; a missing hint never drops a file or chooses its bytes.
func (s *CumulativeStage) PlannedFileReadOrder(files []StageFileEffect) []int {
	type hint struct {
		order wim.FileReadOrder
		known bool
	}
	hints := make([]hint, len(files))
	indices := make([]int, len(files))
	for i, effect := range files {
		indices[i] = i
		var order wim.FileReadOrder
		var known bool
		switch effect.SourceMode {
		case "payload":
			order, known = s.contentReadOrder(effect.SourceName)
		case "predecessor":
			if effect.SourceDescriptor != nil && s.assemblyReadOrder != nil {
				order, known = s.assemblyReadOrder(*effect.SourceDescriptor)
			}
		case "installed":
			if s.assemblyNameReadOrder != nil {
				order, known = s.assemblyNameReadOrder(effect.SourceName)
			}
		}
		hints[i] = hint{order, known}
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a, b := hints[indices[i]], hints[indices[j]]
		if a.known != b.known {
			return a.known
		}
		if a.order.Source != b.order.Source {
			return a.order.Source < b.order.Source
		}
		if a.order.ResourceOffset != b.order.ResourceOffset {
			return a.order.ResourceOffset < b.order.ResourceOffset
		}
		return a.order.BlobOffset < b.order.BlobOffset
	})
	return indices
}

func (s *CumulativeStage) contentReadOrder(name string) (wim.FileReadOrder, bool) {
	if s == nil || s.Graph == nil {
		return wim.FileReadOrder{}, false
	}
	if payload, ok := s.expressByTarget[normalizeCIXName(name)]; ok {
		if s.assemblyReadOrder != nil {
			// The decoded file basis is normally much larger than the optional
			// nested patch basis. Prefer it without reading either one.
			if basis := s.nameExpressBasis(payload.Target.Name, payload.Basis); basis != nil {
				if order, ok := s.assemblyReadOrder(*basis); ok {
					return order, true
				}
			}
			if payload.RecordBasis != nil {
				return s.assemblyReadOrder(*payload.RecordBasis)
			}
		}
	}
	if carry, found := s.carryTarget(name); found && s.assemblyReadOrder != nil {
		return s.assemblyReadOrder(carry.Source)
	}
	return wim.FileReadOrder{}, false
}

// Index only the immutable completed-stage descriptors. Selection mirrors
// openTargetDescriptor: payloads before carries, exact length/hash, preferred
// matching name, otherwise the first matching target. No target is opened.
func (state *assemblyContentState) snapshotReadOrder() func(ContentDescriptor) (wim.FileReadOrder, bool) {
	type identity struct {
		length int64
		hash   [32]byte
	}
	type candidate struct {
		stage *CumulativeStage
		name  string
	}
	byContent := make(map[identity][]candidate)
	for i := len(state.prior) - 1; i >= 0; i-- {
		stage := state.prior[i].stage
		if stage == nil || stage.Graph == nil {
			continue
		}
		payloadKeys := make(map[identity]bool)
		for _, payload := range stage.Graph.Payloads {
			key := identity{payload.Target.Length, payload.Target.SHA256}
			payloadKeys[key] = true
			byContent[key] = append(byContent[key], candidate{stage, payload.Target.Name})
		}
		for _, carry := range stage.Graph.Carries {
			key := identity{carry.Target.Length, carry.Target.SHA256}
			if payloadKeys[key] {
				continue
			}
			byContent[key] = append(byContent[key], candidate{stage, carry.Target.Name})
		}
	}
	base, imagePath := state.base, state.imagePath
	return func(descriptor ContentDescriptor) (wim.FileReadOrder, bool) {
		matches := byContent[identity{descriptor.Length, descriptor.SHA256}]
		if len(matches) != 0 {
			selected := matches[0]
			for _, match := range matches {
				if match.stage != selected.stage {
					break
				}
				if normalizeCIXName(match.name) == normalizeCIXName(descriptor.Name) {
					selected = match
				}
			}
			return selected.stage.contentReadOrder(selected.name)
		}
		if base == nil || descriptor.Name == "" {
			return wim.FileReadOrder{}, false
		}
		name, err := baseAssemblyContentPath(imagePath, descriptor.Name)
		if err != nil {
			return wim.FileReadOrder{}, false
		}
		order, err := base.ReadOrder(name)
		return order, err == nil
	}
}

func (state *assemblyContentState) snapshotNameReadOrder() func(string) (wim.FileReadOrder, bool) {
	base, imagePath := state.base, state.imagePath
	prior := append([]completedAssemblyStage(nil), state.prior...)
	return func(name string) (wim.FileReadOrder, bool) {
		current := strings.TrimPrefix(strings.ReplaceAll(name, "/", `\`), `\`)
		for i := len(prior) - 1; i >= 0; i-- {
			completed := prior[i]
			if completed.stage.hasContentTarget(current) {
				return completed.stage.contentReadOrder(current)
			}
			identity, relative, err := ParseComponentContentName(current)
			if err != nil {
				continue
			}
			if previous, ok := completed.predecessorByStem[normalizeCIXName(identity.Stem)]; ok {
				current = strings.TrimSuffix(previous, `\`) + `\` + relative
			}
		}
		if base == nil {
			return wim.FileReadOrder{}, false
		}
		name, err := baseAssemblyContentPath(imagePath, current)
		if err != nil {
			return wim.FileReadOrder{}, false
		}
		order, err := base.ReadOrder(name)
		return order, err == nil
	}
}
