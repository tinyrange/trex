package uup

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func TestAssemblyIdentityKeyAndVersionBoundaries(t *testing.T) {
	oldVersion := func(version string) ([4]uint64, bool) {
		var result [4]uint64
		parts := strings.Split(version, ".")
		if len(parts) != 4 {
			return result, false
		}
		for i, s := range parts {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return result, false
			}
			result[i] = n
		}
		return result, true
	}
	cases := []string{"", "1", "1.2", "1.2.3", "1.2.3.4", "1.2.3.4.5", "1.2.bad", "1.2.bad.4", "1.2.4294967295.4", "1.2.4294967296.4", "1.2.+3.4", "1.2.-3.4", "1.2..4", "1.2.0x3.4", "1.2.03.4", "NONE", "é", "\xff"}
	rng := rand.New(rand.NewSource(434))
	for i := 0; i < 2000; i++ {
		value := make([]byte, rng.Intn(50))
		for j := range value {
			value[j] = byte(rng.Intn(256))
		}
		cases = append(cases, string(value))
	}
	for _, value := range cases {
		want, ok := oldVersion(value)
		got, valid := assemblyVersionParts(value)
		if got != want || valid != ok {
			t.Fatalf("%q: %v %t != %v %t", value, got, valid, want, ok)
		}
		id := AssemblyIdentity{Name: value, PublicKeyToken: "TOKEN", ProcessorArchitecture: "amd64", Language: value, Version: value}
		old := id.StableKey() + "\x00" + strings.ToLower(id.Version)
		if got := id.ExactKey(); got != old {
			t.Fatalf("identity fold differs: %q != %q", got, old)
		}
	}
}
