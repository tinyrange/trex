package uefi

import "fmt"

// ResetRequest is a non-returning firmware lifecycle transition, not a guest
// failure. Type is EFI_RESET_TYPE: 0 cold, 1 warm, 2 shutdown. The caller must
// quiesce every CPU and device before resetting or shutting down the machine.
type ResetRequest struct{ Type uint32 }

func (r *ResetRequest) Error() string { return fmt.Sprintf("UEFI reset request %d", r.Type) }

// NonvolatileVariables returns an independent snapshot for the next hardware
// boot. Volatile variables and all runtime address mappings die with this boot.
func (f *Firmware) NonvolatileVariables() []Variable {
	var result []Variable
	for _, v := range f.machine.variables {
		if v.Attributes&1 != 0 {
			v.Data = append([]byte(nil), v.Data...)
			result = append(result, v)
		}
	}
	return result
}

func (f *Firmware) RestoreNonvolatileVariables(variables []Variable) error {
	for key, v := range f.machine.variables {
		if v.Attributes&1 != 0 {
			delete(f.machine.variables, key)
		}
	}
	for _, v := range variables {
		if v.Attributes&1 == 0 {
			return fmt.Errorf("uefi: volatile variable in persistent store")
		}
		if err := f.machine.SetVariable(v); err != nil {
			return err
		}
	}
	return nil
}
