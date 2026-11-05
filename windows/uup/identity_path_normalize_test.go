package uup

import (
	"math/rand"
	"strings"
	"testing"
)

func referenceComponentPathName(name string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '(' || r == ')' {
			return -1
		}
		return r
	}, strings.ToLower(name))
}

func TestComponentPathNameMatchesRuneMapping(t *testing.T) {
	inputs := []string{"", "Microsoft-Windows-Kernel32", "Microsoft (R) Name", "IİıΣσςK", "abc..def", string([]byte{0xff, 'A', 0xfe})}
	rng := rand.New(rand.NewSource(73341))
	for i := 0; i < 2000; i++ {
		data := make([]byte, rng.Intn(120))
		rng.Read(data)
		inputs = append(inputs, string(data))
	}
	for _, input := range inputs {
		if got, want := componentPathName(input), referenceComponentPathName(input); got != want {
			t.Fatalf("normalizing %q: got %q want %q", input, got, want)
		}
	}
}

var normalizedPathSink string

func BenchmarkComponentPathName(b *testing.B) {
	name := "microsoft-windows-client-features-shell-desktop"
	b.Run("rune-map", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			normalizedPathSink = referenceComponentPathName(name)
		}
	})
	b.Run("punctuation-fast-path", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			normalizedPathSink = componentPathName(name)
		}
	})
}
