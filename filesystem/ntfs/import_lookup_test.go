package ntfs

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

func TestImportFoldMatchesSimpleFold(t *testing.T) {
	// Exercise every Unicode fold cycle, including Kelvin K, long s, sigma,
	// dotted/dotless I and characters whose uppercase is not their fold key.
	for r := rune(0); r <= unicode.MaxRune; r++ {
		next := unicode.SimpleFold(r)
		if next == r {
			continue
		}
		if ntfsImportFold(string(r)) != ntfsImportFold(string(next)) {
			t.Fatalf("fold cycle mismatch: %U and %U", r, next)
		}
	}
}

func TestImportChildLookupMatchesLinear(t *testing.T) {
	parent := &ntfsNode{dir: true}
	names := []string{"Kernel", "Kernel", "ſystem", "SYSTEM", "Σ", "ς", "İ", "i", "ı", "ß", "ẞ", "SS", "alias"}
	queries := append(append([]string{}, names...), "missing", "kernel", "system", "σ", "ALIAS")
	for i, name := range names {
		node := &ntfsNode{id: uint64(i), name: name}
		if name == "alias" {
			node = parent.children[0].node
		}
		parent.children = append(parent.children, &ntfsDirectoryLink{node: node, name: name})
		for _, query := range queries {
			var want *ntfsNode
			for _, link := range parent.children {
				if strings.EqualFold(link.name, query) {
					want = link.node
					break
				}
			}
			if got := ntfsChildByName(parent, query); got != want {
				t.Fatalf("after adding %q, lookup %q = %p, want %p", name, query, got, want)
			}
		}
	}
}

func BenchmarkImportWideDirectory(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			names := make([]string, size)
			for i := range names {
				names[i] = fmt.Sprintf("component-%08d.dll", i)
			}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				parent := &ntfsNode{dir: true}
				for _, name := range names {
					if ntfsChildByName(parent, name) != nil {
						b.Fatal("unexpected duplicate")
					}
					parent.children = append(parent.children, &ntfsDirectoryLink{name: name, node: &ntfsNode{name: name}})
				}
			}
		})
	}
}
