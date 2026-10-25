package windows

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

func apiSetNamespaceFixture() []byte {
	b := make([]byte, 512)
	put := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	wide := func(at int, text string) uint32 {
		units := utf16.Encode([]rune(text))
		for i, u := range units {
			binary.LittleEndian.PutUint16(b[at+i*2:], u)
		}
		return uint32(len(units) * 2)
	}
	put(0, 6)
	put(4, 512)
	put(12, 2)
	put(16, 28)
	put(20, 76)
	put(24, 31)
	put(32, 160)
	length := wide(160, "ext-test-l1-1-2")
	put(36, length)
	put(40, length-4)
	put(44, 92)
	put(48, 2)
	put(56, 300)
	length = wide(300, "ext-unhosted-l1-1-0")
	put(60, length)
	put(64, length-4)
	put(68, 132)
	put(72, 1)
	put(80, 0)
	put(88, 1)
	put(104, 220)
	put(108, wide(220, "base.dll"))
	put(116, 244)
	put(120, wide(244, "dwm.exe"))
	put(124, 260)
	put(128, wide(260, "alternate.dll"))
	return b
}

func TestAPISetNamespaceHosts(t *testing.T) {
	value, err := parseAPISetNamespace(apiSetNamespaceFixture())
	if err != nil {
		t.Fatal(err)
	}
	get := func(d starlark.Value, key string) starlark.Value {
		v, _, _ := d.(*starlark.Dict).Get(starlark.String(key))
		return v
	}
	contracts := get(value, "contracts").(*starlark.List)
	if contracts.Len() != 2 || get(contracts.Index(0), "name").String() != `"ext-test-l1-1-2"` {
		t.Fatalf("contracts: %s", contracts)
	}
	hosts := get(contracts.Index(0), "hosts").(*starlark.List)
	if get(hosts.Index(0), "host").String() != `"base.dll"` || get(hosts.Index(1), "alias").String() != `"dwm.exe"` || get(hosts.Index(1), "host").String() != `"alternate.dll"` {
		t.Fatalf("hosts: %s", hosts)
	}
	if get(get(contracts.Index(1), "hosts").(*starlark.List).Index(0), "host").String() != `""` {
		t.Fatal("lost unhosted contract")
	}
	if err := contracts.Append(starlark.None); err == nil {
		t.Fatal("mutable namespace result")
	}
}

func TestAPISetNamespaceMalformed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		at    int
		value uint32
	}{
		{"version", 0, 7}, {"size", 4, 513}, {"count", 12, 0xffffffff}, {"entries", 16, 0xfffffff0},
		{"hash index", 80, 2}, {"odd name", 36, 3}, {"long hash", 40, 500}, {"values", 44, 0xfffffffe},
		{"host span", 108, 0xffffffff}, {"surrogate", 160, 0x0074d800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := apiSetNamespaceFixture()
			binary.LittleEndian.PutUint32(b[tc.at:], tc.value)
			if _, err := parseAPISetNamespace(b); err == nil {
				t.Fatal("accepted malformed namespace")
			}
		})
	}
}
