package windows

import (
	"bytes"
	"testing"

	"go.starlark.net/starlark"
)

func TestAssemblyNumericRegistryTypeHiveRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
	}{
		{"FFFF0012", 0xffff0012}, {"00040007", 0x00040007}, {"00200000", 0x00200000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := assemblyRegistryDataBuiltin(nil, nil, starlark.Tuple{starlark.String(tc.name), starlark.String("49000000")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := registryDataFromStarlark(tc.name, value)
			if err != nil {
				t.Fatal(err)
			}
			root := newRegistryTree("SYSTEM")
			setRegistryValue(root, "/DriverDatabase/Properties/Test", "", encoded)
			data, err := buildRegistryHive(root)
			if err != nil {
				t.Fatal(err)
			}
			hive, err := newRegistryHive(testHiveFile(data))
			if err != nil {
				t.Fatal(err)
			}
			key, err := hive.lookup("/DriverDatabase/Properties/Test")
			if err != nil {
				t.Fatal(err)
			}
			values, err := hive.readRawValues(key)
			if err != nil {
				t.Fatal(err)
			}
			if len(values) != 1 || values[0].value.typ != tc.code || !bytes.Equal(values[0].value.data, []byte{0x49, 0, 0, 0}) {
				t.Fatalf("raw hive value: %#v", values)
			}
		})
	}
}

func TestAssemblyRegistryData(t *testing.T) {
	for _, tc := range []struct{ kind, text, want string }{
		{"REG_MULTI_SZ", `"first","second"`, `["first", "second"]`},
		{"REG_MULTI_SZ", `vmms`, `["vmms"]`},
		{"REG_MULTI_SZ", `"MountedDevices\"`, `["MountedDevices\\"]`},
		{"REG_MULTI_SZ", `"a,b", "a""b"`, `["a,b", "a\"b"]`},
		{"REG_MULTI_SZ", ``, `[]`},
		{"REG_DWORD", `0xffffffff`, `4294967295`},
		{"REG_DWORD", `-1`, `4294967295`},
		{"REG_QWORD", `0000004001000000`, `5368709120`},
		{"REG_QWORD", `0x100000000`, `4294967296`},
		{"REG_QWORD", `0x0`, `0`},
		{"REG_NONE", ``, `b""`},
		{"REG_RESOURCE_LIST", `00aB`, `b"\x00\xab"`},
		{"REG_RESOURCE_REQUIREMENTS_LIST", `0100`, `b"\x01\x00"`},
		{"REG_SZ", `a,b`, `"a,b"`},
		{"FFFF0012", `4900520051000000`, `b"I\x00R\x00Q\x00\x00\x00"`},
		{"00040007", `4e004500430000000000`, `b"N\x00E\x00C\x00\x00\x00\x00\x00"`},
		{"00200000", ``, `b""`},
	} {
		t.Run(tc.kind+tc.text, func(t *testing.T) {
			got, err := assemblyRegistryDataBuiltin(nil, nil, starlark.Tuple{starlark.String(tc.kind), starlark.String(tc.text)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			if _, err := registryDataFromStarlark(tc.kind, got); err != nil {
				t.Fatalf("not accepted by hive writer: %v", err)
			}
		})
	}
	for _, tc := range [][2]string{
		{"REG_MULTI_SZ", `"unterminated`}, {"REG_MULTI_SZ", "a\nb"},
		{"REG_MULTI_SZ", "a\x00b"}, {"REG_BINARY", "0"},
		{"REG_QWORD", "00"}, {"REG_DWORD", "4294967296"}, {"unsupported", ""},
		{"FFFF0012", "0"}, {"FFFF0012", "not hex"}, {"FFFF001", "00"}, {"1FFFF0012", "00"}, {"GGGG0012", "00"},
	} {
		if _, err := assemblyRegistryDataBuiltin(nil, nil, starlark.Tuple{starlark.String(tc[0]), starlark.String(tc[1])}, nil); err == nil {
			t.Fatalf("accepted invalid %v", tc)
		}
	}
}

func TestAssemblyRegistryMacroExpansion(t *testing.T) {
	macros := map[string]string{"runtime.system32": `C:\Windows\SysWOW64`, "assembly.empty": "", "build.packagemoniker": "$(build.PackageMoniker)"}
	for _, tc := range [][2]string{
		{`$(Runtime.System32)\fdssdp.dll`, `C:\Windows\SysWOW64\fdssdp.dll`},
		{`$$(assembly.empty)(Registry:HKLM\key)`, `$(Registry:HKLM\key)`},
		{`@{$(build.PackageMoniker)?resource}`, `@{$(build.PackageMoniker)?resource}`},
		{`%SystemRoot%\System32\a.dll`, `%SystemRoot%\System32\a.dll`},
	} {
		got, err := expandAssemblyRegistryMacros(tc[0], macros)
		if err != nil || got != tc[1] {
			t.Fatalf("%q = %q: %v", tc[0], got, err)
		}
	}
	for _, value := range []string{"$(unknown)", "$(runtime.system32"} {
		if _, err := expandAssemblyRegistryMacros(value, macros); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
