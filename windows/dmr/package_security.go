package dmr

import "fmt"

// EncodeRepositorySecurity constructs the Windows 11 26100 SECU payload from
// the repository's package SID, IsInbox and legacy Capabilities fields. The
// capability mask is not a list of all manifest capabilities: the native DMR
// producer selects only its ten well-known capability entries, in table order.
// ariFlags must be the DMR root flags, not StateRepository Package.Flags.
func EncodeRepositorySecurity(ariFlags uint32, packageSID []byte, isInbox bool, capabilities uint32) ([]byte, error) {
	if ariFlags&3 != 0 {
		return nil, nil
	}
	context := SecurityContext{PackageSID: packageSID}
	if isInbox {
		context.Flags = 1
	}
	// OneCore RetrieveSecurityContextAndAddSection's table at RVA 3098b0
	// maps bits 0..9 to WELL_KNOWN_SID_TYPE 85,86,87,91,88,89,90,93,92,94.
	for bit, rid := range [...]uint32{1, 2, 3, 7, 4, 5, 6, 9, 8, 10} {
		if capabilities&(1<<bit) == 0 {
			continue
		}
		// Revision 1, authority 15, subauthorities 3 and capability RID.
		sid := []byte{1, 2, 0, 0, 0, 0, 0, 15, 3, 0, 0, 0, 0, 0, 0, 0}
		le.PutUint32(sid[12:], rid)
		context.Capabilities = append(context.Capabilities, sid)
	}
	return EncodeSecurityContext(context)
}

// EncodePackageSecurity applies the native DMR section-presence rule to ARI
// package flags (not StateRepository Flags or PackageType). Flags bit0 is set
// for frameworks; the native producer skips SECU for either low flag bit.
// A nil result means omit the section, not emit an empty security context.
// Other packages require an explicitly constructed context; no SID/capabilities
// or security policy are synthesized here.
func EncodePackageSecurity(ariFlags uint32, context *SecurityContext) ([]byte, error) {
	if ariFlags&3 != 0 {
		return nil, nil
	}
	if context == nil {
		return nil, fmt.Errorf("dmr: package requires an explicit security context")
	}
	return EncodeSecurityContext(*context)
}
