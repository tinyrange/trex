package uup

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/windows/registry"
)

// CSISourceChange describes an already-authorized source operation on one
// deployment. Kind is the native TLC mask: 1 pinned, 2 installed, or 4 staged.
// Data is the complete CBS primary/secondary payload, including for deletion.
// Choosing operations is the caller's responsibility: in particular a queued
// stage request is not evidence of successful payload staging.
type CSISourceChange struct {
	Kind   uint32
	Delete bool
	Data   []byte
}

// CSISourceValueEdit changes only one value of a deployment key, not the key,
// composition backlinks, status flags, winner membership, or files.
type CSISourceValueEdit struct {
	Delete bool
	Value  registry.Value
}

type CSISourceCounts struct {
	Pinned    uint32
	Installed uint32
	Staged    uint32
}

type CSISourceWritePlan struct {
	Edits  []CSISourceValueEdit
	Before CSISourceCounts
	After  CSISourceCounts
}

// PlanCSISourceWrites plans ordered CBS source-value edits for one deployment.
// before must contain its COMPLETE p!/i!/s! source inventory, not other values.
// Non-CBS installers are deliberately unsupported; omission of their sources
// would make the returned counts unsuitable for reference analysis.
//
// WCP CommonTlcMarkTwiddle leaves an existing source value untouched on add,
// even when the requested secondary bytes differ. This matters for preserving
// opaque resident metadata. New source data is copied, not aliased. Deletion
// requires a present source as a planner precondition; duplicate removal is an
// error rather than silently hiding an inconsistent operation list. Different
// kinds of the same source are independent. A remove followed by add is retained
// in order and can replace secondary data. On any error no partial plan escapes.
//
// Source counts alone do not authorize composition deletion or image activation.
func PlanCSISourceWrites(before []registry.Value, changes []CSISourceChange) (CSISourceWritePlan, error) {
	if len(before) > 1<<20 || len(changes) > 1<<20 {
		return CSISourceWritePlan{}, fmt.Errorf("CSI source write input bound exceeded")
	}
	type sourceState struct {
		name    string
		primary string
	}
	sources := make(map[string]sourceState, len(before))
	var plan CSISourceWritePlan
	var work uint64
	consume := func(data []byte) error {
		work += uint64(len(data))
		if work > 64<<20 {
			return fmt.Errorf("CSI source write payload bound exceeded")
		}
		return nil
	}
	for _, value := range before {
		if err := consume(value.Data); err != nil {
			return CSISourceWritePlan{}, err
		}
		if value.Type != 3 || len(value.Name) < 3 || value.Name[1] != '!' {
			return CSISourceWritePlan{}, fmt.Errorf("invalid CSI source value %q", value.Name)
		}
		var kind uint32
		switch strings.ToLower(value.Name[:1]) {
		case "p":
			kind = 1
		case "i":
			kind = 2
		case "s":
			kind = 4
		default:
			return CSISourceWritePlan{}, fmt.Errorf("unsupported CSI source kind %q", value.Name)
		}
		source, err := ParseCBSDeploymentSource(value.Data)
		if err != nil {
			return CSISourceWritePlan{}, err
		}
		if !strings.EqualFold(value.Name[2:], source.SourceKey) {
			return CSISourceWritePlan{}, fmt.Errorf("CSI source name does not match payload: %q", value.Name)
		}
		key := strings.ToLower(value.Name)
		if _, exists := sources[key]; exists {
			return CSISourceWritePlan{}, fmt.Errorf("duplicate CSI source value %q", value.Name)
		}
		sources[key] = sourceState{name: value.Name, primary: source.Primary}
		csiSourceCount(&plan.Before, kind, true)
	}
	plan.After = plan.Before
	for _, change := range changes {
		prefix := ""
		switch change.Kind {
		case 1:
			prefix = "p!"
		case 2:
			prefix = "i!"
		case 4:
			prefix = "s!"
		default:
			return CSISourceWritePlan{}, fmt.Errorf("unsupported CSI source mask %d", change.Kind)
		}
		if err := consume(change.Data); err != nil {
			return CSISourceWritePlan{}, err
		}
		source, err := ParseCBSDeploymentSource(change.Data)
		if err != nil {
			return CSISourceWritePlan{}, err
		}
		name := prefix + source.SourceKey
		key := strings.ToLower(name)
		old, exists := sources[key]
		if exists && !strings.EqualFold(old.primary, source.Primary) {
			return CSISourceWritePlan{}, fmt.Errorf("CSI source-key collision for %q", name)
		}
		if change.Delete {
			if !exists {
				return CSISourceWritePlan{}, fmt.Errorf("cannot remove absent CSI source %q", name)
			}
			plan.Edits = append(plan.Edits, CSISourceValueEdit{Delete: true, Value: registry.Value{Name: old.name}})
			delete(sources, key)
			csiSourceCount(&plan.After, change.Kind, false)
		} else if !exists {
			sources[key] = sourceState{name: name, primary: source.Primary}
			plan.Edits = append(plan.Edits, CSISourceValueEdit{Value: registry.Value{Name: name, Type: 3, Data: append([]byte(nil), change.Data...)}})
			csiSourceCount(&plan.After, change.Kind, true)
		}
	}
	return plan, nil
}

func csiSourceCount(counts *CSISourceCounts, kind uint32, add bool) {
	count := &counts.Pinned
	switch kind {
	case 2:
		count = &counts.Installed
	case 4:
		count = &counts.Staged
	}
	if add {
		*count++
	} else {
		*count--
	}
}
