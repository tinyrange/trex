package uup

import "strings"

// validateCSIIdentity has the same acceptance boundary as marshalCSIIdentity,
// without allocating, reparsing and hashing an unused display string on the
// common ASCII path. Unusual syntax uses the original validator, including its
// exact diagnostics; this is not a second, more permissive identity grammar.
func validateCSIIdentity(id AssemblyIdentity) error {
	if simpleCSIIdentity(id) {
		return nil
	}
	_, err := marshalCSIIdentity(id)
	return err
}

func simpleCSIIdentity(id AssemblyIdentity) bool {
	culture := id.Language
	if culture == "" || strings.EqualFold(culture, "none") {
		culture = "neutral"
	}
	fields := [5]string{id.Name, culture, id.Version, id.PublicKeyToken, id.ProcessorArchitecture}
	size := len(", Culture=") + len(", Version=") + len(", PublicKeyToken=") + len(", ProcessorArchitecture=")
	for _, field := range fields {
		if !simpleCSIField(field) {
			return false
		}
		size += len(field)
		if size > 64<<10 {
			return false
		}
	}
	if _, ok := assemblyVersionParts(id.Version); !ok {
		return false
	}
	typed := false
	for _, a := range id.Attributes {
		if a.Namespace != "" || !strings.EqualFold(a.Name, "type") {
			continue
		}
		if typed || !simpleCSIField(a.Value) {
			return false
		}
		typed = true
		size += len(", Type=") + len(a.Value)
		if size > 64<<10 {
			return false
		}
	}
	if id.VersionScope != "" {
		if !simpleCSIField(id.VersionScope) {
			return false
		}
		size += len(", versionScope=") + len(id.VersionScope)
	}
	return size <= 64<<10
}

func simpleCSIField(value string) bool {
	if value == "" || len(value) > 64<<10 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 32 || c > 127 {
			return false
		}
		switch c {
		case ',', '=', '"', '/', '\\':
			return false
		}
	}
	return true
}
