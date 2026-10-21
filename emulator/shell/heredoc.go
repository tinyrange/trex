package shell

import (
	"mvdan.cc/sh/v3/syntax"
	"strings"
)

// <<- strips source tabs, not tabs produced by expansions. Copy literals so a
// function's parsed body can be safely reused by concurrent pipeline stages.
func stripHeredocTabs(word *syntax.Word) *syntax.Word {
	result := &syntax.Word{}
	start := true
	for _, part := range word.Parts {
		literal, ok := part.(*syntax.Lit)
		if !ok {
			result.Parts = append(result.Parts, part)
			start = false
			continue
		}
		copy := *literal
		var b strings.Builder
		for _, c := range literal.Value {
			if start && c == '\t' {
				continue
			}
			b.WriteRune(c)
			start = c == '\n'
		}
		copy.Value = b.String()
		result.Parts = append(result.Parts, &copy)
	}
	return result
}

// Quoted delimiters suppress even backslash removal. The parser represents
// their bodies as literal text; Document would still consume backslashes.
func quotedHeredoc(delimiter *syntax.Word) bool {
	for _, part := range delimiter.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok || strings.ContainsRune(lit.Value, 92) {
			return true
		}
	}
	return false
}
