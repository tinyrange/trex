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
	if payload, ok := s.expressTarget(normalizeCIXName(name)); ok {
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

// Each completed stage owns one immutable exact-content index. Positive entries
// address payloads (index+1); negative entries address carries (-index-1).
// Payloads take precedence over all carries of the same identity. A snapshot
// retains only the preceding stage list, not another copy of every older index.
// This keeps long update histories linear rather than quadratic in metadata.
type readOrderIdentity struct {
	length int64
	hash   [32]byte
}

// Keep candidates in one contiguous allocation. The hash table contains only
// integer ranges, so singleton identities neither allocate objects nor make
// the collector scan every hash bucket for a slice pointer.
type contentCandidateSpan struct{ start, count int }
type contentCandidateIndex struct {
	spans  map[readOrderIdentity]contentCandidateSpan
	values []int
}

func (index *contentCandidateIndex) lookup(key readOrderIdentity) []int {
	span := index.spans[key]
	return index.values[span.start : span.start+span.count]
}
func (s *CumulativeStage) contentCandidates() *contentCandidateIndex {
	s.readOrderOnce.Do(func() {
		index := &contentCandidateIndex{spans: make(map[readOrderIdentity]contentCandidateSpan)}
		if s.Graph != nil {
			payloadKeys := make(map[readOrderIdentity]bool)
			for _, payload := range s.Graph.Payloads {
				key := readOrderIdentity{payload.Target.Length, payload.Target.SHA256}
				payloadKeys[key] = true
				span := index.spans[key]
				span.count++
				index.spans[key] = span
			}
			for _, carry := range s.Graph.Carries {
				key := readOrderIdentity{carry.Target.Length, carry.Target.SHA256}
				if !payloadKeys[key] {
					span := index.spans[key]
					span.count++
					index.spans[key] = span
				}
			}
			total := 0
			for key, span := range index.spans {
				index.spans[key] = contentCandidateSpan{start: total}
				total += span.count
			}
			index.values = make([]int, total)
			add := func(key readOrderIdentity, value int) {
				span := index.spans[key]
				index.values[span.start+span.count] = value
				span.count++
				index.spans[key] = span
			}
			for i, payload := range s.Graph.Payloads {
				add(readOrderIdentity{payload.Target.Length, payload.Target.SHA256}, i+1)
			}
			for i, carry := range s.Graph.Carries {
				key := readOrderIdentity{carry.Target.Length, carry.Target.SHA256}
				if !payloadKeys[key] {
					add(key, -i-1)
				}
			}
		}
		s.readOrderByContent = index
	})
	return s.readOrderByContent
}

// Selection mirrors openTargetDescriptor: newest stage, payloads before carries,
// exact length/hash, preferred matching name, otherwise first matching target.
// A selected stage with no locality hint must NOT fall through to older bytes.
func (state *assemblyContentState) snapshotReadOrder() func(ContentDescriptor) (wim.FileReadOrder, bool) {
	prior := append([]completedAssemblyStage(nil), state.prior...)
	for _, completed := range prior {
		if completed.stage != nil {
			completed.stage.contentCandidates()
		}
	}
	base, imagePath := state.base, state.imagePath
	return func(descriptor ContentDescriptor) (wim.FileReadOrder, bool) {
		key := readOrderIdentity{descriptor.Length, descriptor.SHA256}
		for i := len(prior) - 1; i >= 0; i-- {
			stage := prior[i].stage
			if stage == nil {
				continue
			}
			matches := stage.contentCandidates().lookup(key)
			if len(matches) == 0 {
				continue
			}
			selected := stage.candidateName(matches[0])
			for _, candidate := range matches {
				name := stage.candidateName(candidate)
				if normalizeCIXName(name) == normalizeCIXName(descriptor.Name) {
					selected = name
				}
			}
			return stage.contentReadOrder(selected)
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
