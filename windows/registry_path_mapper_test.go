package windows

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestRegistryPathMapperSnapshotAndUnicode(t *testing.T) {
	rules := starlark.NewList([]starlark.Value{
		starlark.Tuple{starlark.String(`\Registry\Machine\Software`), starlark.MakeInt(3)},
		starlark.Tuple{starlark.String(`\Registry\Machine\Software\K`), starlark.MakeInt(3)},
		starlark.Tuple{starlark.String(`\Registry\Machine\Software\Shared`), starlark.MakeInt(0)},
	})
	mapper, err := registryPathMapperBuiltin(nil, nil, starlark.Tuple{rules}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The compiled table owns the inputs, and each result is independent.
	rules.Clear()
	call := func(key string) *starlark.Dict {
		t.Helper()
		result, err := starlark.Call(&starlark.Thread{}, mapper, starlark.Tuple{starlark.String(key), starlark.String("x86")}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return result.(*starlark.Dict)
	}
	for _, tc := range []struct{ key, want string }{
		{`HKLM\Software\K\Child`, `\Registry\Machine\Software\K\WOW6432Node\Child`},
		{`HKLM\Software\Shared\Child`, `\Registry\Machine\Software\Shared\Child`},
		{`HKLM\Software\SharedExtra`, `\Registry\Machine\Software\WOW6432Node\SharedExtra`},
		{`HKLM\Software\Wow6432Node\Other`, `\Registry\Machine\Software\Wow6432Node\Other`},
		{`HKEY_CURRENT_USER\Software`, `\Registry\User\Software`},
	} {
		first := call(tc.key)
		value, _, _ := first.Get(starlark.String("path"))
		if string(value.(starlark.String)) != tc.want {
			t.Fatalf("%q: %s, want %q", tc.key, value, tc.want)
		}
		first.SetKey(starlark.String("path"), starlark.None)
		again := call(tc.key)
		value, _, _ = again.Get(starlark.String("path"))
		if value == starlark.None {
			t.Fatal("result mutation reached compiled mapper")
		}
	}
}

func TestRegistryPathMapperRejectsInvalidRulesAndKeys(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		flags  int
	}{
		{`HKLM\Software`, 3}, {`\Registry\Machine\Software\`, 3}, {`\Registry\\Machine`, 3},
		{"\\Registry\\Machine\x00", 3}, {strings.Repeat("x", 32769), 3}, {`\Registry\Machine`, 4}, {`\Registry\Machine`, -1},
	} {
		_, err := registryPathMapperBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{starlark.Tuple{starlark.String(tc.prefix), starlark.MakeInt(tc.flags)}})}, nil)
		if err == nil {
			t.Fatalf("accepted rule %#v", tc)
		}
	}
	m := registryPathMapper{`\registry\machine\software`: 3}
	for _, key := range []string{"", `HKLM\\Software`, `HKLM\$(key)`, "HKLM\\A\x00B", `HKEY_USERS\S-1-5-18`, `HKCU\Software`, `HKEY_CURRENT_USER\Wow6432Node`, `HKLM\Software\X\Wow6432Node`, `HKLM\Software\Wow6432Node\Wow6432Node`} {
		if _, _, err := m.resolve(key, "x86"); err == nil {
			t.Fatalf("accepted %q", key)
		}
	}
	if _, _, err := m.resolve(`HKLM\Software`, "arm64"); err == nil {
		t.Fatal("accepted unknown architecture")
	}
	if _, _, err := (registryPathMapper{`\registry\machine\software`: 1}).resolve(`HKLM\Software`, "x86"); err == nil {
		t.Fatal("accepted redirect without anchor")
	}
}

func TestRegistryPathMapperManagedNativeView(t *testing.T) {
	m := registryPathMapper{`\registry\machine\software`: 3}
	// Native CSI bitness2 for MSIL, unlike x86/wow64 bitness3. These
	// ServerManager keys come from the Server managed plug-in manifests.
	for _, key := range []string{
		`HKLM\Software\Microsoft\ServerManager\Roles\16\Plugins`,
		`HKLM\Software\Microsoft\ServerManager\Roles\481\Plugins`,
		`HKCR\CLSID\{fixture}`, // catches accidental blanket WOW redirection
	} {
		scope, path, err := m.resolve(key, "msil")
		nativeScope, nativePath, nativeErr := m.resolve(key, "amd64")
		_, wowPath, wowErr := m.resolve(key, "wow64")
		if err != nil || nativeErr != nil || wowErr != nil || scope != nativeScope || path != nativePath || path == wowPath {
			t.Fatalf("%s: managed %s %s %v; native %s %s %v; WOW %s %v", key, scope, path, err, nativeScope, nativePath, nativeErr, wowPath, wowErr)
		}
	}
}
