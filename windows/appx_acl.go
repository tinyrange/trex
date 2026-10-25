package windows

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

func appxUTF16(value string) []byte {
	units := utf16.Encode([]rune(value))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}
func appxSID(authority byte, words ...uint32) []byte {
	out := make([]byte, 8+4*len(words))
	out[0] = 1
	out[1] = byte(len(words))
	out[7] = authority
	for i, w := range words {
		binary.LittleEndian.PutUint32(out[8+4*i:], w)
	}
	return out
}
func appxACE(kind, flags byte, mask uint32, sid, condition []byte) []byte {
	out := make([]byte, (8+len(sid)+len(condition)+3)&^3)
	out[0] = kind
	out[1] = flags
	binary.LittleEndian.PutUint16(out[2:], uint16(len(out)))
	binary.LittleEndian.PutUint32(out[4:], mask)
	copy(out[8:], sid)
	copy(out[8+len(sid):], condition)
	return out
}

// AppxPackageACL constructs WindowsApps package grants from a native parent's
// inheritable DACL. Execute access for Users is conditional on WIN://SYSAPPID;
// the package capability SID is derived from the lowercase family identity.
// Unsupported inherited ACE layouts/flags fail closed. Noninheritable parent
// grants are not copied. kind is root, directory (descendant), or file.
func AppxPackageACL(parent []byte, family, kind string) ([]byte, error) {
	return appxPackageACL(parent, family, kind, false)
}

// Frameworks are shared across application identities. Native Windows framework
// payloads grant read/execute to both AppContainer groups and Users, rather than
// binding resource access to the framework's own (non-running) identity.
func appxPackageACL(parent []byte, family, kind string, framework bool) ([]byte, error) {
	if len(family) < 3 || len(family) > 255 || strings.Count(family, "_") != 1 {
		return nil, fmt.Errorf("invalid package family")
	}
	for _, c := range family {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return nil, fmt.Errorf("invalid package family")
		}
	}
	if kind != "root" && kind != "directory" && kind != "file" {
		return nil, fmt.Errorf("invalid package ACL kind")
	}
	rev, entries, err := ParseACL(parent)
	if err != nil {
		return nil, err
	}
	condition := []byte("artx")
	for _, token := range []struct {
		kind byte
		text string
	}{{0xf8, "WIN://SYSAPPID"}, {0x10, family}} {
		raw := appxUTF16(token.text)
		condition = append(condition, token.kind)
		condition = binary.LittleEndian.AppendUint32(condition, uint32(len(raw)))
		condition = append(condition, raw...)
	}
	condition = append(condition, 0x86) // MS-DTYP conditional equality token
	hash := sha256.Sum256(appxUTF16(strings.ToLower(family)))
	words := []uint32{3}
	for i := 0; i < 28; i += 4 {
		words = append(words, binary.LittleEndian.Uint32(hash[i:]))
	}
	flags := byte(3)
	if kind == "directory" {
		flags = 19
	}
	if kind == "file" {
		flags = 16
	}
	users := appxSID(5, 32, 545)
	aces := [][]byte{appxACE(9, flags, 0x1200a9, users, condition), appxACE(0, flags, 0x1200a9, appxSID(15, words...), nil), appxACE(0, flags, 0x120089, users, nil)}
	if framework {
		aces = [][]byte{
			appxACE(0, flags, 0x1200a9, appxSID(15, 2, 1), nil),
			appxACE(0, flags, 0x1200a9, appxSID(15, 2, 2), nil),
			appxACE(0, flags, 0x1200a9, users, nil),
		}
	}
	inherited := 0
	for _, entry := range entries {
		if entry.Flags&3 == 0 {
			continue
		}
		if (entry.Type != 0 && entry.Type != 1) || entry.Flags & ^byte(0x13) != 0 {
			return nil, fmt.Errorf("unsupported WindowsApps inherited ACE")
		}
		if kind == "file" && entry.Flags&1 == 0 {
			continue
		}
		if kind != "file" && entry.Flags&2 == 0 {
			return nil, fmt.Errorf("unsupported object-only WindowsApps inheritance")
		}
		raw := append([]byte(nil), entry.Data...)
		raw[1] = entry.Flags | 16
		if kind == "file" {
			raw[1] = 16
		}
		aces = append(aces, raw)
		inherited++
	}
	if inherited == 0 {
		return nil, fmt.Errorf("WindowsApps DACL has no inheritable grants")
	}
	size := 8
	for _, ace := range aces {
		size += len(ace)
	}
	if size > 65535 || len(aces) > 65535 {
		return nil, fmt.Errorf("package ACL too large")
	}
	out := make([]byte, 8, size)
	out[0] = rev
	binary.LittleEndian.PutUint16(out[2:], uint16(size))
	binary.LittleEndian.PutUint16(out[4:], uint16(len(aces)))
	for _, ace := range aces {
		out = append(out, ace...)
	}
	return out, nil
}
func appxPackageACLBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var family string
	kind := "root"
	framework := false
	if err := starlark.UnpackArgs("appx_package_acl", args, kwargs, "parent", &source, "family", &family, "kind?", &kind, "framework?", &framework); err != nil {
		return nil, err
	}
	raw, err := bytesForBinaryValueLimited(source, 65535)
	if err != nil {
		return nil, err
	}
	acl, err := appxPackageACL(raw, family, kind, framework)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(acl), nil
}
