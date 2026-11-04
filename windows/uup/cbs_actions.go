package uup

// CBSExecutionAction is the resolved stage-change action used by ordinary CBS
// execution items. These are not owner states and do not authorize CSI writes.
type CBSExecutionAction uint32

const (
	CBSActionNone CBSExecutionAction = iota
	CBSActionResolve
	CBSActionStage
	CBSActionInstall
	CBSActionUninstall
	CBSActionUninstallUnstage
	CBSActionUninstallUnstageUnresolve
	CBSActionUnstage
	CBSActionUnstageUnresolve
	CBSActionUnresolve
)

func cbsDirtyState(state uint32) uint32 {
	if state == CBSStateSuperseded {
		return CBSStateStaged
	}
	return state
}

// Inputs have already passed resolvedCBSParentState. Pending/partial states and
// force-action switches are deliberately outside the ordinary population path.
func cbsOrdinaryAction(from, to uint32) CBSExecutionAction {
	from, to = cbsDirtyState(from), cbsDirtyState(to)
	if from == 0x80 {
		from = CBSStateInstalled
	}
	if to == 0x80 {
		to = CBSStateInstalled
	}
	if from == to {
		return CBSActionNone
	}
	if from < to {
		switch to {
		case 0x20:
			return CBSActionResolve
		case CBSStateStaged:
			return CBSActionStage
		case CBSStateInstalled:
			return CBSActionInstall
		}
	}
	switch from {
	case CBSStateInstalled:
		switch to {
		case CBSStateStaged:
			return CBSActionUninstall
		case 0x20:
			return CBSActionUninstallUnstage
		default:
			return CBSActionUninstallUnstageUnresolve
		}
	case CBSStateStaged:
		if to == 0x20 {
			return CBSActionUnstage
		}
		return CBSActionUnstageUnresolve
	default:
		return CBSActionUnresolve
	}
}
