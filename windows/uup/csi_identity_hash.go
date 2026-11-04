package uup

// HashCSIIdentity returns the native non-cryptographic identity discriminator
// from a full COMPONENTS identity/appid, never from an abbreviated key name.
// omitVersion selects the version-independent family hash used in native
// component-family and winner key suffixes. It preserves type and versionScope;
// this is not the CBS update-analyzer's major/minor family rule. This function
// does not decide applicability, installation or the winning version.
func HashCSIIdentity(data []byte, omitVersion bool) (uint64, error) {
	id, err := parseCSIIdentity(data)
	if err != nil {
		return 0, err
	}
	return csiIdentityHash(id, omitVersion)
}
