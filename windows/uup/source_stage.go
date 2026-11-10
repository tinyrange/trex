package uup

import (
	"fmt"
)

// BindSourceStageContent appends an update as a reconstruction source only.
// Unlike PlanStage, it neither evaluates package applicability nor projects an
// installed component population. Manifest names supply predecessor *hints*;
// express reconstruction still verifies every basis and target hash, and exact
// metadata consumers must independently authorize all servicing effects.
// Source-only and installed-state planning cannot be mixed on one planner.
func (planner *AssemblyPlanner) BindSourceStageContent(stage *CumulativeStage) error {
	if planner == nil || planner.state == nil || planner.content == nil || stage == nil {
		return fmt.Errorf("uup servicing: assembly planner and stage are required")
	}
	if planner.sealed || (!planner.sourceOnly && len(planner.content.prior) != 0) {
		return fmt.Errorf("uup servicing: cannot mix source-only and installed-state planning")
	}
	entries, err := stage.assemblyEntries()
	if err != nil {
		return err
	}
	index, err := newComponentMetadataIndex(entries, stage.openAssemblyFile, stage.releaseAssemblyFile)
	if err != nil {
		return err
	}
	// Use immutable, eagerly computed name hints. No XML/payload is read here,
	// and no mutable inventory is captured by readers retained across stages.
	predecessors := make(map[string]string)
	names := graphStringStore{seen: make(map[string]string)}
	// Source hints use the on-disk family shape, not CBS full-identity
	// applicability. Each family needs only its newest preceding name. The
	// hash-qualified resolver remains authoritative when a hint is absent or
	// names content not installed in this edition.
	previous := planner.state.latestComponentByFamily
	next := make(map[string]manifestPath, len(previous))
	for family, candidate := range previous {
		next[family] = candidate
	}
	for _, candidates := range index.byHash {
		for _, candidate := range candidates {
			component := candidate.Component
			family := componentFamilyKey(component.Identity)
			if old, found := previous[family]; found {
				predecessors[names.copy(normalizeCIXName(component.Stem))] = names.copy(old.Component.Stem)
			}
			candidate.Identity = component.Identity
			if old, found := next[family]; !found || compareVersions(component.Identity.Version, old.Identity.Version) > 0 {
				next[family] = candidate
			}
		}
	}
	stage.assemblyResolver = planner.content.snapshotResolver()
	stage.baseRecovery = planner.content.reverse
	stage.assemblyNameResolver = planner.content.snapshotNameResolver()
	stage.assemblyReadOrder = planner.content.snapshotReadOrder()
	stage.assemblyNameReadOrder = planner.content.snapshotNameReadOrder()
	stage.assemblyDictionary = planner.content.dictionaryResolver()
	stage.predecessorByStem = predecessors
	planner.content.prior = append(planner.content.prior, completedAssemblyStage{stage: stage, predecessorByStem: predecessors})
	planner.state = &assemblyImageState{latestComponentByFamily: next}
	planner.sourceOnly = true
	return nil
}
