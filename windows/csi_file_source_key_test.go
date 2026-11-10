package windows

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// Retain the independent interpreter implementation as a semantic oracle. The
// production key must preserve full tuple equality, not just hash collisions.
const referenceFileSourceKey = `
def servicing_file_source_key(identity, name):
    """Bounded native FileInfo key, NOT an exact payload/store identity.

    InsertFileInfo ignores all version fields for nonSxS scope, but retains
    major/minor for absent scope. The source filename is independently case-folded.
    Preserve the full component_identity on declarations for payload lookup;
    neither a transition label nor this intern key authorizes source bytes.
    Other scopes and non-ASCII comparison require additional native evidence.
    """
    d = windows.csi_identity(identity)
    if d.version_scope.lower() not in ["", "nonsxs"]:
        fail("unsupported file source versionScope")
    if not name or "/" in name or ":" in name or any([part in ["", ".", ".."] for part in name.split("\\")]):
        fail("file source key requires a relative source name")
    fields = [d.name, d.language, d.processor_architecture, d.public_key_token, d.type, d.version_scope, name]
    for field in fields:
        if any([ord(c) < 32 or ord(c) > 126 for c in field.elems()]):
            fail("file source key requires bounded ASCII comparison")
    version_family = () if d.version_scope.lower() == "nonsxs" else tuple([int(part) for part in d.version.split(".")[:2]])
    return tuple([field.lower() for field in fields]) + (version_family,)

`

func TestCSIFileSourceKeyDifferential(t *testing.T) {
	thread := &starlark.Thread{Name: "file source key"}
	globals, err := starlark.ExecFile(thread, "reference.star", referenceFileSourceKey, starlark.StringDict{
		"windows": &starlarkstruct.Module{Name: "windows", Members: Builtins()},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "Microsoft-Windows-Example, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
	identities := []string{base, strings.ToUpper(base), strings.ReplaceAll(base, "10.0.26100.9444", "1.1.0.0"), strings.ReplaceAll(base, "10.0.26100.9444", "01.00.0.0"), strings.ReplaceAll(base, "neutral", "en-US"), strings.ReplaceAll(base, "Example", "naïve"), strings.ReplaceAll(base, "Example", "bad\tname"), base + ", Unknown=x", base + ", Culture=en-US", "", strings.Repeat("x", 65537)}
	names := []string{"Case.dll", `Amd64\UNIDRV.DLL`, "", "..", `a\..\b`, `\a`, `a\`, `a\\b`, "a/b", "c:a", "naïve.dll", "bad\x7f", "bad\x00", " .dll"}
	for _, identity := range identities {
		for _, suffix := range []string{"", ", versionScope=nonSxS", ", type=win32", ", type=dualModeDriver, versionScope=NonSxS", ", versionScope=unknown"} {
			for _, name := range names {
				args := starlark.Tuple{starlark.Bytes(identity + suffix), starlark.String(name)}
				want, oldErr := starlark.Call(thread, globals["servicing_file_source_key"], args, nil)
				got, newErr := starlark.Call(thread, Builtins()["csi_file_source_key"], args, nil)
				if (oldErr == nil) != (newErr == nil) {
					t.Fatalf("%q %q: reference %v; native %v", identity+suffix, name, oldErr, newErr)
				}
				if oldErr != nil {
					continue
				}
				equal, err := starlark.Equal(got, want)
				if err != nil || !equal {
					t.Fatalf("%q %q: got %v want %v (%v)", identity+suffix, name, got, want, err)
				}
				if _, err := got.Hash(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, args := range []starlark.Tuple{{starlark.String(base), starlark.String("a")}, {starlark.Bytes(base), starlark.None}} {
		if _, err := starlark.Call(thread, Builtins()["csi_file_source_key"], args, nil); err == nil {
			t.Fatal("accepted wrong input types")
		}
	}
}
