package uup

import "fmt"

// CBSStateUnspecified is the native no-parent result, not an installed package
// state. Package applicability converts this sentinel after evaluating parents.
const CBSStateUnspecified uint32 = 0x1000

// CBSParentEvaluation supplies transaction policy that is not encoded by the
// parent XML. Resolve must apply version policy and query effective intended
// state (including pending/session overrides), returning absent for an unmatched
// identity. It must not equate the presence of a MUM with installed state.
type CBSParentEvaluation struct {
	Resolve func(AssemblyReference) (uint32, error)
	// StandaloneSatisfied enables the native standalone-parent bypass. The
	// caller must resolve the package/session flags; integrate="standalone"
	// alone does not enable it. Nested constraints are still evaluated.
	StandaloneSatisfied bool
}

// EvaluateCBSPackageParents reduces the parsed parent tree using resolved
// intended states. Direct identities and root blocks are alternatives. Nested
// blocks are alternatives constrained by their enclosing block. A failed direct
// identity uses the block disposition, whose default is detect, NOT staged.
// This does not implement version selection, supersedence, owner aggregation,
// or final CurrentState. No input is mutated and errors return no usable state.
func EvaluateCBSPackageParents(manifest *AssemblyManifest, evaluation CBSParentEvaluation) (uint32, error) {
	if manifest == nil || manifest.Package == nil {
		return 0, fmt.Errorf("CBS parent evaluation requires a package manifest")
	}
	type block struct {
		refs        []AssemblyReference
		children    []int
		disposition uint32
		detect      bool
		standalone  bool
	}
	blocks := make([]block, len(manifest.PackageParents))
	var roots []int
	for i, parent := range manifest.PackageParents {
		// Parsed blocks are preorder. Reject malformed caller-built trees,
		// including cycles and disconnected forward references.
		if parent.ParentGroup < 0 || parent.ParentGroup > i {
			return 0, fmt.Errorf("invalid CBS enclosing parent group %d", parent.ParentGroup)
		}
		if parent.ParentGroup == 0 {
			roots = append(roots, i)
		} else {
			p := &blocks[parent.ParentGroup-1]
			p.children = append(p.children, i)
		}
		attrs, err := cbsConditionAttributes(ManifestCondition{Name: "parent", Attributes: parent.Attributes},
			"integrate", "disposition", "buildCompare", "revisionCompare", "distributionCompare", "serviceCompare", "set")
		if err != nil {
			return 0, err
		}
		// ProcessVersionCompareAttribute consumes serviceCompare and
		// distributionCompare without parsing their values or assigning a
		// comparison field (cbscore 26100.9441, cases 3/5 -> 0x5325e).
		// They do not constrain this reduction or its runtime resolver.
		// PopulateParents copies set to PackageParent+0x20, but neither
		// parent-state evaluator reads it. Keep it in the manifest for other
		// queries; it is not an extra identity constraint in this reduction.
		if set, present := attrs["set"]; present && set == "" {
			return 0, fmt.Errorf("empty CBS parent set")
		}
		b := &blocks[i]
		switch attrs["disposition"] {
		case "", "detect":
			b.detect = true
		case "staged":
			b.disposition = CBSStateStaged
		case "absent":
			b.disposition = CBSStateAbsent
		default:
			return 0, fmt.Errorf("unsupported CBS parent disposition %q", attrs["disposition"])
		}
		switch attrs["integrate"] {
		case "", "separate", "delegate", "subsume":
		case "standalone":
			b.standalone = true
		default:
			return 0, fmt.Errorf("unsupported CBS parent integration %q", attrs["integrate"])
		}
	}
	for _, ref := range manifest.References {
		if ref.Kind != "parent" {
			continue
		}
		if ref.ParentGroup < 1 || ref.ParentGroup > len(blocks) {
			return 0, fmt.Errorf("unscoped CBS parent identity %q", ref.Identity.Name)
		}
		b := &blocks[ref.ParentGroup-1]
		b.refs = append(b.refs, ref)
	}
	for i, b := range blocks {
		if len(b.refs) == 0 {
			return 0, fmt.Errorf("CBS parent group %d has no direct identities", i+1)
		}
	}
	if len(roots) == 0 {
		return CBSStateUnspecified, nil
	}
	if evaluation.Resolve == nil {
		return 0, fmt.Errorf("CBS parent evaluation requires an intended-state resolver")
	}
	var evaluate func(int, int) (uint32, error)
	evaluate = func(index, depth int) (uint32, error) {
		if depth > maximumManifestDepth {
			return 0, fmt.Errorf("CBS parent tree exceeds depth bound")
		}
		b := blocks[index]
		var state uint32
		if b.standalone && evaluation.StandaloneSatisfied {
			state = CBSStateInstalled
		} else {
			for _, ref := range b.refs {
				s, err := evaluation.Resolve(ref)
				if err != nil {
					return 0, fmt.Errorf("CBS parent %q: %w", ref.Identity.Name, err)
				}
				// Pending/invalid/unspecified states need transaction query
				// policy before entering this evaluator. 0x80 is permanent.
				if !resolvedCBSParentState(s) {
					return 0, fmt.Errorf("unresolved CBS parent intended state %#x", s)
				}
				if s >= CBSStateInstalled {
					state = CBSStateInstalled
					break
				}
				if !b.detect {
					s = b.disposition
				}
				state = max(state, s)
			}
		}
		if state == CBSStateAbsent || len(b.children) == 0 {
			return state, nil
		}
		var nested uint32
		for _, child := range b.children {
			s, err := evaluate(child, depth+1)
			if err != nil {
				return 0, err
			}
			nested = max(nested, s)
			if nested >= CBSStateInstalled {
				break
			}
		}
		return min(state, nested), nil
	}
	var state uint32
	for _, root := range roots {
		s, err := evaluate(root, 0)
		if err != nil {
			return 0, err
		}
		state = max(state, s)
		if state >= CBSStateInstalled {
			break
		}
	}
	return state, nil
}
