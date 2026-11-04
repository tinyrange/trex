package uup

import (
	"math/rand"
	"strings"
	"testing"
)

func TestCSIIdentityValidationMatchesDisplayBoundary(t *testing.T) {
	base := AssemblyIdentity{Name: "Microsoft-Windows-Test", Language: "neutral", Version: "10.0.26100.9711", PublicKeyToken: "31bf3856ad364e35", ProcessorArchitecture: "amd64"}
	check := func(id AssemblyIdentity) {
		t.Helper()
		_, old := marshalCSIIdentity(id)
		got := validateCSIIdentity(id)
		if (old == nil) != (got == nil) {
			t.Fatalf("acceptance differs for %+v: old=%v new=%v", id, old, got)
		}
	}
	check(base)
	cases := []string{"", "none", "NONE", "neutral", "x y", "x, Type=driver", "x,y", "a=b", `"quote"`, `a\b`, "a/b", "x\x00", "\r", "\n", "\t", "\x7f", "é", "\xff", "1.2.3.4", "1.2.3", "1.2.3.18446744073709551616", "1.2.3.-1", "1.2.3.+1", strings.Repeat("x", 65500), strings.Repeat("x", 65536)}
	set := func(id *AssemblyIdentity, field int, value string) {
		switch field {
		case 0:
			id.Name = value
		case 1:
			id.Language = value
		case 2:
			id.Version = value
		case 3:
			id.PublicKeyToken = value
		case 4:
			id.ProcessorArchitecture = value
		case 5:
			id.VersionScope = value
		case 6:
			id.Attributes = []ManifestAttribute{{Name: "TyPe", Value: value}}
		}
	}
	for field := 0; field < 7; field++ {
		for _, value := range cases {
			id := base
			set(&id, field, value)
			check(id)
		}
	}
	for _, attrs := range [][]ManifestAttribute{
		{{Name: "type", Value: "driver"}, {Name: "TYPE", Value: "driver"}},
		{{Namespace: "other", Name: "type", Value: "x,y"}},
		{{Name: "buildType", Value: "\xff"}},
		{{Name: "type", Value: ""}},
	} {
		id := base
		id.Attributes = attrs
		check(id)
	}
	rng := rand.New(rand.NewSource(4531))
	for i := 0; i < 6000; i++ {
		data := make([]byte, rng.Intn(90))
		for j := range data {
			data[j] = byte(rng.Intn(256))
		}
		id := base
		set(&id, rng.Intn(7), string(data))
		check(id)
	}
	// Exercise both sides of the exact serialized 64-KiB limit.
	for size := 65400; size <= 65540; size++ {
		id := base
		id.Name = strings.Repeat("x", size)
		check(id)
	}
}

func BenchmarkCSIIdentityValidation(b *testing.B) {
	id := AssemblyIdentity{Name: "Microsoft-Windows-Test", Language: "neutral", Version: "10.0.26100.9711", PublicKeyToken: "31bf3856ad364e35", ProcessorArchitecture: "amd64"}
	b.Run("display", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := marshalCSIIdentity(id); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("validate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := validateCSIIdentity(id); err != nil {
				b.Fatal(err)
			}
		}
	})
}
