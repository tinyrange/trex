package ckd

import "fmt"

// recordOrganization accepts only the component combinations verified by the
// supplied primary VVRs. Bit 0 is independent of keyed/relative organization.
// The component's maximum record length distinguishes ordinary non-keyed
// record data from linear data (whose maximum record length is zero).
func (v *VVR) recordOrganization() (VSAMOrganization, error) {
	if !v.Index {
		switch v.DataFlags {
		case 0x80, 0x81:
			if v.KeyLength > 0 {
				return VSAMKSDS, nil
			}
		case 2, 3:
			if v.KeyLength == 0 && v.KeyOffset == 0 {
				return VSAMRRDS, nil
			}
		case 0, 1:
			if v.KeyLength == 0 && v.KeyOffset == 0 && (v.DataFlags == 1 || v.MaximumRecordLength > 0) {
				return VSAMESDS, nil
			}
		}
	}
	return "", fmt.Errorf("VSAM: linear, inconsistent or unsupported record organization (flags %#02x)", v.DataFlags)
}
