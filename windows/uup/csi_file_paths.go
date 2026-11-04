package uup

import (
	"fmt"
	"strings"
)

// CSIFileDestinationName implements WCP's shallow destination-name selection.
// It does not expand macros, validate a final path, or authorize a projection.
// In particular, a trailing backslash selects the preceding path, not its leaf.
func CSIFileDestinationName(file AssemblyFile) (string, error) {
	var override string
	present := false
	for _, a := range file.Attributes {
		if a.Namespace != "" || a.Name != "destinationName" {
			continue
		}
		if present {
			return "", fmt.Errorf("CSI file: duplicate destinationName")
		}
		present, override = true, a.Value
	}
	if present {
		return override, nil
	}
	i := strings.LastIndexByte(file.Name, '\\')
	if i < 0 {
		return file.Name, nil
	}
	if i == len(file.Name)-1 {
		return file.Name[:i], nil
	}
	return file.Name[i+1:], nil
}

// CSIFileDirectoryMacro returns the IRtlUserProfile special-directory identifier
// selected by WCP for a runtime directory macro (without the $(...) delimiters).
// This is not a filesystem path: the image's user-profile provider must resolve
// the ID, registry expansion and offline root mapping separately. Only the
// observed amd64 store policy is supported; unknown policy fails closed.
func CSIFileDirectoryMacro(targetArchitecture, componentArchitecture, macro string) (uint32, error) {
	target, err := csiPathASCIIKey(targetArchitecture)
	if err != nil {
		return 0, err
	}
	arch, err := csiPathASCIIKey(componentArchitecture)
	if err != nil {
		return 0, err
	}
	name, err := csiPathASCIIKey(macro)
	if err != nil {
		return 0, err
	}
	if target != "amd64" {
		return 0, fmt.Errorf("CSI file macro: unsupported target architecture %q", targetArchitecture)
	}
	redirected := false
	switch arch {
	case "x86", "wow64", "amd64.x86":
		redirected = true
	case "amd64", "msil", "data", "":
	default:
		return 0, fmt.Errorf("CSI file macro: unsupported component architecture %q", componentArchitecture)
	}
	// WCP LookupStringReplacement fixed table; these do not depend on bitness.
	fixed := map[string]uint32{
		"runtime.bootdrive": 0x100000, "runtime.commonfilesx86": 44,
		"runtime.documentssettings": 62, "runtime.fonts": 20,
		"runtime.inf": 0x30000, "runtime.mui": 0x40000,
		"runtime.programfilesx86": 42, "runtime.system": 0x50000,
		"runtime.systemroot": 36, "runtime.windows": 36, "runtime.windir": 36,
		"runtime.help": 0xa0000, "runtime.apppatch": 0xb0000,
		"runtime.public": 0xc0000, "runtime.programdata": 0xd0000,
		"runtime.startmenu": 11, "runtime.startup": 7,
		"runtime.userprofile": 0x110000, "runtime.localappdata": 28,
		"runtime.appdata": 26, "runtime.programs": 2,
	}
	if id, ok := fixed[name]; ok {
		return id, nil
	}
	// Native bitness 2 versus redirected bitness 3 in an amd64 store.
	dependent := map[string][2]uint32{
		"runtime.system32": {37, 41}, "runtime.syswow64": {41, 41},
		"runtime.programfiles": {38, 42}, "runtime.commonfiles": {43, 44},
		"runtime.drivers": {0x20000, 0xe0000}, "runtime.wbem": {0x70000, 0xf0000},
		"runtime.testbin": {0x440000, 0x450000},
	}
	if pair, ok := dependent[name]; ok {
		if redirected {
			return pair[1], nil
		}
		return pair[0], nil
	}
	return 0, fmt.Errorf("CSI file macro: unsupported directory macro %q", macro)
}

func csiPathASCIIKey(s string) (string, error) {
	for i := range len(s) {
		if s[i] >= 0x80 || s[i] == 0 {
			return "", fmt.Errorf("CSI file macro: expected non-NUL ASCII name")
		}
	}
	return strings.ToLower(s), nil
}

// CSIFileAttributes parses the native manifest file-attribute mask. Absence
// retains WCP's 0xa0 constructor default; an explicit value replaces it, even
// when empty. This is not the final filesystem mask: commit policy is separate.
func CSIFileAttributes(file AssemblyFile) (uint32, error) {
	var value string
	present := false
	for _, a := range file.Attributes {
		if a.Namespace != "" || a.Name != "attributes" {
			continue
		}
		if present {
			return 0, fmt.Errorf("CSI file attributes: duplicate attributes")
		}
		present, value = true, a.Value
	}
	if !present {
		return 0xa0, nil
	}
	for i := range len(value) {
		if value[i] >= 0x80 || value[i] == 0 {
			return 0, fmt.Errorf("CSI file attributes: unsupported non-ASCII or NUL token")
		}
	}
	// Native IsCharacterWhitespace accepts only XML whitespace, not the wider
	// Unicode whitespace set used by strings.Fields.
	words := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	var mask uint32
	for _, word := range words {
		switch strings.ToLower(word) {
		case "readonly":
			mask |= 0x1
		case "hidden":
			mask |= 0x2
		case "system":
			mask |= 0x4
		case "archive":
			mask |= 0x20
		case "temporary":
			mask |= 0x100
		case "offline":
			mask |= 0x1000
		case "notcontentindexed":
			mask |= 0x2000
		default:
			return 0, fmt.Errorf("CSI file attributes: unsupported token %q", word)
		}
	}
	return mask, nil
}
