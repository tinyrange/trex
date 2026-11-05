package uup

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// CSIDeploymentKey encodes a complete persisted CSI identity as a canonical
// deployment registry key. It is not a WinSxS directory name.
func CSIDeploymentKey(identity []byte) (string, error) {
	id, err := ParseCSIIdentity(identity)
	if err != nil {
		return "", err
	}
	return csiDeploymentKey(id)
}

// csiDeploymentKey is the canonical deployment registry name, not a WinSxS
// directory name. Architecture and culture participate in the hash even though
// they do not appear in the readable prefix.
func csiDeploymentKey(id AssemblyIdentity) (string, error) {
	hash, err := csiIdentityHash(id, false)
	if err != nil {
		return "", err
	}
	if err := validateCSIIdentity(id); err != nil {
		return "", err
	}
	name := componentPathName(id.Name)
	if len(name) > 24 {
		name = name[:11] + ".." + name[len(name)-11:]
	}
	return fmt.Sprintf("%s_%s_%s_%016x", name, strings.ToLower(id.PublicKeyToken), id.Version, hash), nil
}

// marshalCSIIdentity writes the un-terminated UTF-8 display identity persisted
// in COMPONENTS identity/appid values. BuildType is manifest metadata, not part
// of the canonical CSI identity.
func marshalCSIIdentity(id AssemblyIdentity) ([]byte, error) {
	culture := id.Language
	if culture == "" || strings.EqualFold(culture, "none") {
		culture = "neutral"
	}
	text := id.Name + ", Culture=" + culture
	for _, a := range id.Attributes {
		if a.Namespace == "" && strings.EqualFold(a.Name, "type") {
			text += ", Type=" + a.Value
		}
	}
	text += ", Version=" + id.Version + ", PublicKeyToken=" + id.PublicKeyToken + ", ProcessorArchitecture=" + id.ProcessorArchitecture
	if id.VersionScope != "" {
		text += ", versionScope=" + id.VersionScope
	}
	if _, err := parseCSIIdentity([]byte(text)); err != nil {
		return nil, err
	}
	if _, err := csiTextHash(text); err != nil {
		return nil, err
	}
	if strings.ContainsAny(text, `/\`) {
		return nil, fmt.Errorf("invalid CSI identity path separator")
	}
	return []byte(text), nil
}

// cbsSourceKey hashes only the primary source string; the optional opaque
// secondary data does not participate in source identity. Consecutive '_' in
// the readable prefix are collapsed before truncation, but NOT before hashing.
func cbsSourceKey(primary string) (string, error) {
	hash, err := csiTextHash(primary)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(primary, `/\`) {
		return "", fmt.Errorf("invalid CBS source path separator")
	}
	parts := strings.FieldsFunc(strings.ToLower(primary), func(r rune) bool { return r == '_' })
	prefix := strings.Join(parts, "_")
	if len(prefix) > 60 {
		prefix = prefix[:60]
	}
	return fmt.Sprintf("CBS_%s_%016x", prefix, hash), nil
}

func marshalCBSDeploymentSource(source cbsDeploymentSource, secondary []byte) ([]byte, error) {
	id := source.Package
	packageName, err := cbsPackageName(id)
	if err != nil {
		return nil, err
	}
	primary := packageName + "." + source.Update
	if len(primary)+len(secondary) > (64<<10)-8 {
		return nil, fmt.Errorf("CBS source exceeds framing bound")
	}
	data := make([]byte, 8+len(primary)+len(secondary))
	binary.LittleEndian.PutUint32(data, uint32(len(primary)))
	binary.LittleEndian.PutUint32(data[4:], uint32(len(secondary)))
	copy(data[8:], primary)
	copy(data[8+len(primary):], secondary)
	parsed, err := parseCBSDeploymentSource(data)
	if err != nil {
		return nil, err
	}
	if parsed.Package.ExactKey() != id.ExactKey() || parsed.Update != source.Update {
		return nil, fmt.Errorf("CBS source cannot round-trip identity")
	}
	if _, err := cbsSourceKey(primary); err != nil {
		return nil, err
	}
	return data, nil
}

// csiFileKey encodes a manifest-relative filename as a COMPONENTS f! value
// name. The readable prefix uses at most 25 sanitized characters, collapsing
// replacement runs; the hash always covers the original name. Even a literal
// underscore requires hashing. Checked against all 40,429 native f! records in
// the 26300.9457 image, including nested WebView files and Start-menu links.
func csiFileKey(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty CSI filename")
	}
	hash, err := csiTextHash(name)
	if err != nil {
		return "", err
	}
	lower := strings.ToLower(name)
	var safe strings.Builder
	changed := false
	underscore := false
	for _, c := range lower {
		valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'
		if !valid {
			changed = true
			if !underscore {
				safe.WriteByte('_')
			}
			underscore = true
		} else {
			safe.WriteRune(c)
			underscore = false
		}
	}
	if !changed && len(lower) <= 25 {
		return "f!" + lower, nil
	}
	prefix := safe.String()
	if len(prefix) > 25 {
		prefix = prefix[:25]
	}
	return fmt.Sprintf("f!%s_%016x", prefix, hash), nil
}
