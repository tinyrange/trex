package uup

import "encoding/binary"

// CBSDeploymentSourceRecord is the bounded native two-length source payload
// stored in canonical CSI p!/s!/i! values. Secondary is opaque; it is neither
// part of Primary nor part of SourceKey. Inspection does not imply activation.
type CBSDeploymentSourceRecord struct {
	Package   AssemblyIdentity
	Update    string
	Primary   string
	Secondary []byte
	SourceKey string
}

// ParseCBSDeploymentSource validates native framing and the exact package/update
// identity. Returned data does not alias the caller's buffer.
func ParseCBSDeploymentSource(data []byte) (CBSDeploymentSourceRecord, error) {
	source, err := parseCBSDeploymentSource(data)
	if err != nil {
		return CBSDeploymentSourceRecord{}, err
	}
	length := binary.LittleEndian.Uint32(data[:4])
	primary := string(data[8 : 8+length])
	key, err := cbsSourceKey(primary)
	if err != nil {
		return CBSDeploymentSourceRecord{}, err
	}
	return CBSDeploymentSourceRecord{
		Package: source.Package, Update: source.Update, Primary: primary,
		Secondary: append([]byte(nil), data[8+length:]...), SourceKey: key,
	}, nil
}

// ParseCSIIdentity decodes a COMPONENTS identity/appid value, preserving type
// and versionScope rather than reconstructing identity from a lossy key name.
func ParseCSIIdentity(data []byte) (AssemblyIdentity, error) {
	return parseCSIIdentity(data)
}

// FormatCSIIdentity validates and formats a full COMPONENTS identity/appid,
// preserving type and versionScope. BuildType is not part of CSI identity.
func FormatCSIIdentity(identity AssemblyIdentity) ([]byte, error) {
	return marshalCSIIdentity(identity)
}
