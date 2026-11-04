package uup

import (
	"fmt"
	"strings"
)

// CBSDeploymentAction projects one component/driver reference from a completed
// ordinary population. Stage and Action are separate phases: a new staged-only
// source has Stage=true and Action=None. Package/feature references are not CSI
// deployments. Driver actions additionally require the native driver operation
// queue; they must not be applied as component-only registry changes.
type CBSDeploymentAction struct {
	Package    AssemblyIdentity
	UpdateName string
	Deployment AssemblyIdentity
	Driver     bool
	// DriverAttributes are copied from the containing MUM driver declaration,
	// not inferred from the deployment name or its component file list.
	DriverAttributes []ManifestAttribute
	Stage            bool
	Action           CBSExecutionAction
}

// PlanCBSDeploymentActions projects the ordinary no-restage execution path in
// execution/manifest order. It uses retained initial update states, never the
// package's last action or its dirty bits. Unchanged references are retained so
// callers can distinguish preservation from absence. It does not resolve
// payloads, synthesize source metadata, execute driver operations, select
// winners or authorize a CSI commit. Force/restage, removal below staged and
// component-watch reexecution require a different, explicit transaction policy.
func PlanCBSDeploymentActions(population *CBSOrdinaryPopulation) ([]CBSDeploymentAction, error) {
	if population == nil || population.Index == nil {
		return nil, fmt.Errorf("CBS deployment actions require a population snapshot")
	}
	result := []CBSDeploymentAction{}
	seenPackages := map[string]bool{}
	for _, e := range population.Executions {
		key := e.Identity.ExactKey()
		ctx := population.Index.graph.packages.get(key)
		if ctx == nil || seenPackages[key] || ctx.input.IntendedState != e.IntendedState {
			return nil, fmt.Errorf("CBS deployment actions have a foreign, duplicate or stale package %q", e.Identity.Name)
		}
		seenPackages[key] = true
		if len(e.DirtyUpdates) != 0 {
			return nil, fmt.Errorf("CBS deployment actions require drained package notifications")
		}
		seenReferences := map[string]bool{}
		for _, ref := range ctx.input.Manifest.References {
			if ref.Kind != "component" && ref.Kind != "driver" {
				continue
			}
			if ref.UpdateName == "" {
				return nil, fmt.Errorf("CBS deployment has no containing update")
			}
			update := strings.ToLower(ref.UpdateName)
			start, known := e.UpdateStarts[update]
			target, published := e.Updates[update]
			if !known || !published || !start.HasDeployments {
				return nil, fmt.Errorf("CBS deployment %q lacks resolved initial/target update states", ref.UpdateName)
			}
			from, to := cbsDirtyState(start.State), cbsDirtyState(target)
			// A resolved source retains its manifest pin but still requires ordinary
			// payload staging before stage/install. Unpin/unresolve and pending
			// operations remain unsupported, never translated into uninstall.
			preservedResolved := from == 0x20 && to == 0x20
			if !preservedResolved && ((from != 0 && from != 0x20 && from != CBSStateStaged && from != CBSStateInstalled) ||
				(to != CBSStateStaged && to != CBSStateInstalled && !(from == 0 && to == 0))) {
				return nil, fmt.Errorf("CBS deployment %q / %q transition %#x -> %#x requires transaction policy", e.Identity.Name, ref.UpdateName, start.State, target)
			}
			if to > cbsDirtyState(e.IntendedState) {
				return nil, fmt.Errorf("CBS deployment target exceeds package target")
			}
			name, err := csiDeploymentKey(ref.Identity)
			if err != nil {
				return nil, err
			}
			referenceKey := update + "\x00" + name
			if seenReferences[referenceKey] {
				return nil, fmt.Errorf("duplicate CBS deployment reference in update %q", ref.UpdateName)
			}
			seenReferences[referenceKey] = true
			action := cbsOrdinaryAction(from, to)
			// CCbsExecutionUpdate::Execute passes suppress-resolve/stage=true.
			if action == CBSActionStage {
				action = CBSActionNone
			}
			var driverAttributes []ManifestAttribute
			if ref.Kind == "driver" {
				driverAttributes = append(driverAttributes, ref.Attributes...)
			}
			packageID, deploymentID := e.Identity, ref.Identity
			packageID.Attributes = append([]ManifestAttribute(nil), packageID.Attributes...)
			deploymentID.Attributes = append([]ManifestAttribute(nil), deploymentID.Attributes...)
			result = append(result, CBSDeploymentAction{
				Package: packageID, UpdateName: ref.UpdateName,
				Deployment: deploymentID, Driver: ref.Kind == "driver",
				DriverAttributes: driverAttributes,
				Stage:            e.IntendedState >= CBSStateStaged && from < CBSStateStaged && to > 0x20,
				Action:           action,
			})
			if len(result) > 1<<20 {
				return nil, fmt.Errorf("CBS deployment action bound exceeded")
			}
		}
	}
	return result, nil
}
