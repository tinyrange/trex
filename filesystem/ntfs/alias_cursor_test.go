package ntfs

import (
	"fmt"
	"strings"
	"testing"
)

// Reference the original exhaustive candidate search, including aliases owned
// by the same file. Imported names and hard links participate in this policy.
func linearDOSAlias(name string, node *ntfsNode, used map[string]*ntfsNode) string {
	base, ext := name, ""
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		base, ext = name[:dot], name[dot+1:]
	}
	base, ext = ntfsSanitizeDOSPart(base), ntfsSanitizeDOSPart(ext)
	if base == "" {
		base = "_"
	}
	if len(ext) > 3 {
		ext = ext[:3]
	}
	for serial := 1; ; serial++ {
		suffix := fmt.Sprintf("~%d", serial)
		n := max(1, 8-len(suffix))
		candidate := base[:min(len(base), n)] + suffix
		if ext != "" {
			candidate += "." + ext
		}
		if owner := used[candidate]; owner == nil || owner == node {
			return candidate
		}
	}
}

func TestDOSAliasCursorMatchesExhaustiveSearch(t *testing.T) {
	used := map[string]*ntfsNode{}
	groups := map[string]*ntfsAliasCursor{}
	nodes := make([]*ntfsNode, 1500)
	for i := range nodes {
		nodes[i] = &ntfsNode{id: uint64(i + 16)}
	}
	// Long original names that already occupy generated-looking aliases.
	for i := 1; i < 1100; i += 7 {
		used[fmt.Sprintf("ABCDEF~%d.DLL", i)] = nodes[i]
	}
	stems := []string{"abcdef-long", "abcdeg-long", "abcd-other", "a", "å---", "abcdef other"}
	for i := 0; i < 9000; i++ {
		name := fmt.Sprintf("%s-%d.%s", stems[i%len(stems)], i, []string{"dll", "exe", "DLL"}[i%3])
		node := nodes[(i*17)%len(nodes)]
		want := linearDOSAlias(name, node, used)
		got := ntfsDOSAlias(name, node, used, groups)
		if got != want {
			t.Fatalf("iteration %d (%s owner %d): got %s want %s", i, name, node.id, got, want)
		}
		used[got] = node
	}
}

func BenchmarkDOSAliasCollisions(b *testing.B) {
	for n := 0; n < b.N; n++ {
		used := map[string]*ntfsNode{}
		groups := map[string]*ntfsAliasCursor{}
		for i := 0; i < 10000; i++ {
			node := &ntfsNode{id: uint64(i + 16)}
			alias := ntfsDOSAlias(fmt.Sprintf("amd64_component_%d", i), node, used, groups)
			used[alias] = node
		}
	}
}
