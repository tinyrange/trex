package uup

import (
	"fmt"
	"sort"
	"strings"
)

const (
	CBSStateAbsent    uint32 = 0x00
	CBSStateStaged    uint32 = 0x40
	CBSStateInstalled uint32 = 0x70
)

// CBSPackageIntent supplies a resolved package context. IntendedState is an
// input from the transaction, NOT the resulting
// package CurrentState. Local detection is uncapped; parent detection and
// emitted owners are capped by the containing package intent. Parents
// must already be resolved by CBS parent/version policy; a global update-name
// lookup is not an equivalent substitute. SelectableChoices contains explicit
// choices (including false) recovered from the image or requested by the user.
// Missing choices use the manifest's detectNone default. Update-state snapshots
// accept resolved absent/resolved/staged/superseded/installed/permanent states;
// owner projection supports only staged/superseded/installed containing intents.
type CBSPackageIntent struct {
	Manifest          *AssemblyManifest
	IntendedState     uint32
	Parents           []AssemblyIdentity
	SelectableChoices map[string]bool
	// EditionNames are the explicitly resolved current/target edition identity
	// names for an offline session. Required only for edition-gated selection.
	EditionNames []string
}

// CBSPackageOwnerIntent describes one child-package Owners value. It does not
// set that child's CurrentState or infer permanence. Only liberated Product
// references project the owner to the child identity.
type CBSPackageOwnerIntent struct {
	Package     string
	Owner       string
	Integration uint32
	State       uint32
}

func (o CBSPackageOwnerIntent) Value() uint32 { return o.Integration<<16 | o.State }

type cbsUpdateContext struct {
	input     CBSPackageIntent
	name      string
	updates   map[string]AssemblyPackageUpdate
	choices   map[string]bool
	published cbsSnapshotTable[uint32]
}

type cbsUpdateQuery struct{ pack, update string }

type cbsUpdateIntents struct {
	components *CBSComponentStateIndex
	packages   cbsPackageContexts
	memo       map[cbsUpdateQuery]uint32
	visiting   map[cbsUpdateQuery]bool
}

// CBSUpdateStateIndex is a memoized view of one resolved execution snapshot.
// Rebuild it after changing package intents, choices or parent resolution.
// Manifests must remain immutable for the lifetime of the index. A raw update
// query is not newly capped by its own package (an explicitly published target
// may already carry a cap); parent queries and emitted update
// intents are capped. This distinction also applies to absent/resolved packages
// awaiting admission, not only the staged/installed owner-planning subset.
type CBSUpdateStateIndex struct {
	// names is an immutable alias-to-key index shared by execution snapshots.
	names map[string]string
	graph cbsUpdateIntents
}

// CBSUpdateState distinguishes local applicability/selection from the intent
// emitted after applying the containing package's current execution target.
type CBSUpdateState struct {
	RawState      uint32
	IntendedState uint32
}

// NewCBSUpdateStateIndex validates the explicit package scopes and resolved
// states. It does not infer parent scopes, perform execution scheduling, or
// authorize removals. Pending states and unspecified targets are rejected.
func NewCBSUpdateStateIndex(inputs []CBSPackageIntent) (*CBSUpdateStateIndex, error) {
	if len(inputs) > MaxCBSPackageContexts {
		return nil, fmt.Errorf("CBS update context count exceeds bound")
	}
	g := cbsUpdateIntents{memo: map[cbsUpdateQuery]uint32{}, visiting: map[cbsUpdateQuery]bool{}}
	names := make(map[string]string, len(inputs))
	for _, input := range inputs {
		if input.Manifest == nil || input.Manifest.Package == nil {
			return nil, fmt.Errorf("CBS owner context has no package manifest")
		}
		if !resolvedCBSParentState(input.IntendedState) {
			return nil, fmt.Errorf("unsupported CBS package intent %#x", input.IntendedState)
		}
		name, err := cbsPackageName(input.Manifest.Identity)
		if err != nil {
			return nil, err
		}
		key := input.Manifest.Identity.ExactKey()
		if g.packages.get(key) != nil {
			return nil, fmt.Errorf("duplicate CBS package context %q", name)
		}
		input.Parents = append([]AssemblyIdentity(nil), input.Parents...)
		input.EditionNames = append([]string(nil), input.EditionNames...)
		ctx := &cbsUpdateContext{input: input, name: name, updates: map[string]AssemblyPackageUpdate{}, choices: map[string]bool{}}
		for _, u := range input.Manifest.PackageUpdates {
			un := strings.ToLower(u.Name)
			if un == "" {
				return nil, fmt.Errorf("empty CBS update name in %q", name)
			}
			if _, ok := ctx.updates[un]; ok {
				return nil, fmt.Errorf("duplicate CBS update %q in %q", u.Name, name)
			}
			ctx.updates[un] = u
		}
		for un, selected := range input.SelectableChoices {
			un = strings.ToLower(un)
			if _, ok := ctx.choices[un]; ok {
				return nil, fmt.Errorf("duplicate CBS update choice %q", un)
			}
			u, ok := ctx.updates[un]
			if !ok {
				return nil, fmt.Errorf("choice for unknown CBS update %q", un)
			}
			selectable := false
			for _, c := range u.Conditions {
				selectable = selectable || c.Name == "selectable"
			}
			if !selectable {
				return nil, fmt.Errorf("choice for nonselectable CBS update %q", un)
			}
			ctx.choices[un] = selected
		}
		g.packages.add(key, ctx)
		names[name] = key
		names[strings.ToLower(name)] = key
	}
	for _, ctx := range g.packages.all() {
		for _, p := range ctx.input.Parents {
			if g.packages.get(g.packages.keyForIdentity(p)) == nil {
				return nil, fmt.Errorf("unresolved CBS parent %q for %q", p.Name, ctx.name)
			}
		}
	}
	return &CBSUpdateStateIndex{graph: g, names: names}, nil
}

// UpdateState queries one update in its exact package scope, preferring an
// explicitly published session target to metadata evaluation. Unlike owner
// projection this read-only result can be absent; whether an emitted zero-state
// request is allowed is a separate execution/removal policy decision.
func (index *CBSUpdateStateIndex) UpdateState(identity AssemblyIdentity, update string) (CBSUpdateState, error) {
	if index == nil {
		return CBSUpdateState{}, fmt.Errorf("nil CBS update state index")
	}
	ctx := index.graph.packages.get(index.graph.packages.keyForIdentity(identity))
	if ctx == nil {
		return CBSUpdateState{}, fmt.Errorf("CBS update package context is absent: %q", identity.Name)
	}
	state, err := index.graph.update(cbsUpdateQuery{index.graph.packages.keyForIdentity(identity), strings.ToLower(update)}, 0)
	if err != nil {
		return CBSUpdateState{}, err
	}
	return CBSUpdateState{RawState: state, IntendedState: min(state, ctx.input.IntendedState)}, nil
}

// PlanCBSPackageOwners evaluates package-reference update conditions in explicit
// package scopes, emitting edges only to the explicitly selected target package
// identities. Selection/applicability is not inferred from reference presence.
// It is a pure, failure-atomic owner-intent planner, not a CBS
// registry transaction. It deliberately rejects unsupported predicates instead
// of silently disabling features. Transaction-root owners, supersedence, parent selection,
// final package states and deployment actions are separate transaction work.
func PlanCBSPackageOwners(inputs []CBSPackageIntent, targets []AssemblyIdentity) ([]CBSPackageOwnerIntent, error) {
	selected := make(map[string]bool, len(targets))
	for _, target := range targets {
		if _, err := cbsPackageName(target); err != nil {
			return nil, err
		}
		selected[target.ExactKey()] = true
	}
	for _, input := range inputs {
		if input.IntendedState != CBSStateStaged && input.IntendedState != CBSStateSuperseded && input.IntendedState != CBSStateInstalled {
			return nil, fmt.Errorf("unsupported CBS package intent %#x", input.IntendedState)
		}
	}
	index, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		return nil, err
	}
	g := &index.graph
	for key := range selected {
		if g.packages.get(key) == nil {
			return nil, fmt.Errorf("selected CBS target has no package context")
		}
	}
	owners := map[[2]string]CBSPackageOwnerIntent{}
	for _, input := range inputs {
		ctx := g.packages.get(input.Manifest.Identity.ExactKey())
		for _, r := range input.Manifest.References {
			if r.Kind != "package" || !selected[r.Identity.ExactKey()] {
				continue
			}
			target, err := cbsPackageName(r.Identity)
			if err != nil {
				return nil, err
			}
			state, err := g.update(cbsUpdateQuery{input.Manifest.Identity.ExactKey(), strings.ToLower(r.UpdateName)}, 0)
			if err != nil {
				return nil, fmt.Errorf("CBS owner %q -> %q: %w", ctx.name, target, err)
			}
			state = min(state, input.IntendedState)
			if state == CBSStateAbsent {
				return nil, fmt.Errorf("CBS owner %q -> %q requires removal policy", ctx.name, target)
			}
			owner := ctx.name
			var integration uint32
			switch r.Integrate {
			case "", "visible":
				integration = 2
			case "hidden":
				integration = 3
			case "liberate":
				// CBS AddPackage projects only liberated releaseType Product
				// children to self owners; ordinary liberated children retain
				// their containing owner. See csi-offline-state.md.
				targetContext := g.packages.get(r.Identity.ExactKey())
				for _, a := range targetContext.input.Manifest.Package.Attributes {
					if a.Namespace == "" && a.Name == "releaseType" && a.Value == "Product" {
						owner = target
					}
				}
				integration = 4
			default:
				return nil, fmt.Errorf("unsupported CBS package integration %q", r.Integrate)
			}
			key := [2]string{strings.ToLower(target), strings.ToLower(owner)}
			o, exists := owners[key]
			if exists {
				if o.Integration != integration {
					return nil, fmt.Errorf("conflicting CBS integration for %q owner %q", target, owner)
				}
				if state > o.State {
					o.State = state
				}
			} else {
				o = CBSPackageOwnerIntent{Package: target, Owner: owner, Integration: integration, State: state}
			}
			owners[key] = o
		}
	}
	result := make([]CBSPackageOwnerIntent, 0, len(owners))
	for _, o := range owners {
		result = append(result, o)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if strings.EqualFold(a.Package, b.Package) {
			return strings.ToLower(a.Owner) < strings.ToLower(b.Owner)
		}
		return strings.ToLower(a.Package) < strings.ToLower(b.Package)
	})
	return result, nil
}

func (g *cbsUpdateIntents) update(q cbsUpdateQuery, depth int) (uint32, error) {
	if ctx := g.packages.get(q.pack); ctx != nil {
		if state, ok := ctx.published.lookup(q.update); ok {
			return state, nil
		}
	}
	return g.applicable(q, depth)
}

func (g *cbsUpdateIntents) applicable(q cbsUpdateQuery, depth int) (uint32, error) {
	if depth > maximumManifestDepth {
		return 0, fmt.Errorf("CBS update dependency exceeds depth bound")
	}
	if s, ok := g.memo[q]; ok {
		return s, nil
	}
	if g.visiting[q] {
		return 0, fmt.Errorf("cyclic CBS update dependency %q", q.update)
	}
	ctx := g.packages.get(q.pack)
	u, ok := ctx.updates[q.update]
	if !ok {
		return 0, fmt.Errorf("unknown local CBS update %q in %q", q.update, ctx.name)
	}
	g.visiting[q] = true
	defer delete(g.visiting, q)
	// GetInstallState's local detector path does not apply the containing
	// package cap. Parent queries and emitted owner edges do so separately.
	// However, update() first honors explicitly published session targets,
	// which can themselves have been capped when they were published.
	state := CBSStateInstalled
	var applicable uint32
	hasApplicable := false
	for _, c := range u.Conditions {
		limit, err := g.condition(ctx, q, c, depth+1)
		if err != nil {
			return 0, fmt.Errorf("CBS package %q update %q: %w", ctx.name, q.update, err)
		}
		if c.Name == "applicable" {
			// Distinct applicability blocks are alternatives; detectors
			// inside one block remain conjunctive.
			hasApplicable = true
			applicable = max(applicable, limit)
		} else {
			state = min(state, limit)
		}
	}
	if hasApplicable {
		state = min(state, applicable)
	}
	g.memo[q] = state
	return state, nil
}

func cbsConditionAttributes(c ManifestCondition, allowed ...string) (map[string]string, error) {
	if c.Namespace != "" && c.Namespace != "urn:schemas-microsoft-com:asm.v3" {
		return nil, fmt.Errorf("unsupported CBS condition namespace %q", c.Namespace)
	}
	out := map[string]string{}
	for _, a := range c.Attributes {
		// encoding/xml retains declarations as attributes. The resolved
		// element/attribute namespaces, not prefix spelling, carry semantics.
		if a.Namespace == "xmlns" || (a.Namespace == "" && a.Name == "xmlns") {
			continue
		}
		valid := false
		for _, name := range allowed {
			valid = valid || (a.Namespace == "" && a.Name == name)
		}
		if !valid {
			return nil, fmt.Errorf("unsupported %s attribute %q", c.Name, a.Name)
		}
		if _, exists := out[a.Name]; exists {
			return nil, fmt.Errorf("duplicate %s attribute %q", c.Name, a.Name)
		}
		out[a.Name] = a.Value
	}
	return out, nil
}

func (g *cbsUpdateIntents) condition(ctx *cbsUpdateContext, q cbsUpdateQuery, c ManifestCondition, depth int) (uint32, error) {
	if c.Name != "applicable" && c.Name != "selectable" {
		return 0, fmt.Errorf("unsupported CBS update condition %q", c.Name)
	}
	attrs, err := cbsConditionAttributes(c, "disposition", "absentIfCapabilityAbsent")
	if err != nil {
		return 0, err
	}
	// This boolean controls capability deployment execution, not the default
	// selection or detectUpdate intent. PopulateExecutionUpdates dispatches
	// capability references separately from package references. Validate it
	// here without pretending that owner-intent planning executes capabilities.
	if value, ok := attrs["absentIfCapabilityAbsent"]; ok && value != "true" && value != "false" {
		return 0, fmt.Errorf("invalid CBS absentIfCapabilityAbsent %q", value)
	}
	// ProcessUpdateGroupType initializes SELECTABLE_TYPE::disposition to
	// CbsStateStaged (0x40) before parsing attributes. Preserve the distinction
	// between an omitted attribute and an explicitly invalid empty value.
	if c.Name == "selectable" {
		if _, present := attrs["disposition"]; !present {
			attrs["disposition"] = "staged"
		}
	}
	selectionEnabled := true
	if c.Name == "selectable" {
		selectionEnabled, err = cbsEditionSelection(c, ctx.input.EditionNames)
		if err != nil {
			return 0, err
		}
	}
	switch attrs["disposition"] {
	case "absent":
		if c.Name != "selectable" {
			return 0, fmt.Errorf("unsupported CBS absent applicability")
		}
		// A disabled selectable can have absent intent. Dependencies may
		// query that intent; emitting a removal owner still fails separately.
	case "detect":
		if c.Name != "applicable" {
			return 0, fmt.Errorf("unsupported CBS detect selection disposition")
		}
	case "installed":
		if c.Name != "selectable" {
			return 0, fmt.Errorf("unsupported CBS installed applicability")
		}
	case "staged":
	default:
		return 0, fmt.Errorf("unsupported CBS %s disposition %q", c.Name, attrs["disposition"])
	}
	if len(c.Children) == 0 {
		return 0, fmt.Errorf("CBS %s requires a supported predicate", c.Name)
	}
	// CApplicability::Initialize adds repeated detectUpdate nodes to its
	// detector list; EvaluateParent keeps a failed detector's result false.
	// These siblings are conjunctive, unlike nested applicability alternatives.
	enabled := true
	detected := uint32(0x1000)
	predicates := 0
	for _, d := range c.Children {
		if c.Name == "selectable" && d.Name == "customInformation" {
			continue // Fully validated by cbsEditionSelection.
		}
		predicates++
		v, err := g.predicate(ctx, q, d, depth)
		if err != nil {
			return 0, err
		}
		enabled = enabled && v.match
		if !v.match {
			detected = min(detected, v.state)
		}
	}
	if predicates == 0 {
		return 0, fmt.Errorf("CBS %s requires a supported predicate", c.Name)
	}
	if !selectionEnabled {
		if _, chosen := ctx.choices[q.update]; chosen {
			return 0, fmt.Errorf("choice for edition-disabled CBS update %q", q.update)
		}
		return CBSStateInstalled, nil
	}
	// A user choice changes selectability only. Applicability must still hold.
	if c.Name == "selectable" {
		if selected, ok := ctx.choices[q.update]; ok {
			enabled = selected
		}
	}
	if enabled {
		return CBSStateInstalled, nil
	}
	switch attrs["disposition"] {
	case "absent":
		return CBSStateAbsent, nil
	case "staged":
		return CBSStateStaged, nil
	case "installed":
		return CBSStateInstalled, nil
	default:
		if detected == 0x1000 {
			return 0, fmt.Errorf("CBS detect applicability has no resolved failure state")
		}
		return detected, nil
	}
}

// A detector returns both a predicate and a state. In particular a missing
// parent update is (absent, false), not (staged, false).
type cbsUpdateDetection struct {
	state uint32
	match bool
}

func (g *cbsUpdateIntents) predicate(ctx *cbsUpdateContext, q cbsUpdateQuery, d ManifestCondition, depth int) (cbsUpdateDetection, error) {
	result := cbsUpdateDetection{state: 0x1000}
	switch d.Name {
	case "updateComponent":
		return g.componentPredicate(d)
	case "detectNone":
		a, err := cbsConditionAttributes(d, "default")
		if err != nil {
			return cbsUpdateDetection{}, err
		}
		if len(d.Children) != 0 || (a["default"] != "true" && a["default"] != "false") {
			return cbsUpdateDetection{}, fmt.Errorf("unsupported CBS detectNone predicate")
		}
		result.match = a["default"] == "true"
	case "detectUpdate":
		if _, err := cbsConditionAttributes(d); err != nil {
			return cbsUpdateDetection{}, err
		}
		// Native initialization removes exact local self references. Evaluate
		// ORs the remaining references and retains the greatest observed state.
		result.state = CBSStateAbsent
		remaining := 0
		for _, r := range d.Children {
			a, err := cbsConditionAttributes(r, "name", "set")
			if err != nil {
				return cbsUpdateDetection{}, err
			}
			if len(r.Children) != 0 || a["name"] == "" {
				return cbsUpdateDetection{}, fmt.Errorf("invalid CBS update reference")
			}
			// cbscore retains set but queries parent updates by name alone.
			if set, present := a["set"]; present && (r.Name != "parent" || set != "display") {
				return cbsUpdateDetection{}, fmt.Errorf("unsupported CBS update reference set %q", set)
			}
			name := strings.ToLower(a["name"])
			if r.Name == "update" && a["name"] == ctx.updates[q.update].Name {
				continue
			}
			remaining++
			switch r.Name {
			case "update":
				s, err := g.update(cbsUpdateQuery{q.pack, name}, depth)
				if err != nil {
					return cbsUpdateDetection{}, err
				}
				result.state = max(result.state, s)
				result.match = s >= CBSStateInstalled
			case "parent":
				for _, p := range ctx.input.Parents {
					parent := g.packages.get(g.packages.keyForIdentity(p))
					if _, ok := parent.updates[name]; !ok {
						continue
					}
					s, err := g.update(cbsUpdateQuery{g.packages.keyForIdentity(p), name}, depth)
					if err != nil {
						return cbsUpdateDetection{}, err
					}
					s = min(s, parent.input.IntendedState)
					result.state = max(result.state, s)
					result.match = s >= CBSStateInstalled
					if result.match {
						break
					}
				}
			default:
				return cbsUpdateDetection{}, fmt.Errorf("unsupported CBS detectUpdate reference %q", r.Name)
			}
			if result.match {
				break
			}
		}
		if remaining == 0 {
			return cbsUpdateDetection{state: CBSStateInstalled, match: true}, nil
		}
	default:
		return cbsUpdateDetection{}, fmt.Errorf("unsupported CBS update predicate %q", d.Name)
	}
	return result, nil
}
