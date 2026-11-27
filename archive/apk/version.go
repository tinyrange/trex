package apk

import (
	"cmp"
	"strings"
)

type versionPart struct {
	kind  int
	value string
}

const (
	firstNumber = iota
	dotNumber
	letter
	suffix
	suffixNumber
	commitHash
	revision
	end
)

var suffixOrder = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

func digits(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

// Alpine versions consist of dot-separated numbers, an optional lowercase
// letter, release suffixes, an optional commit hash and a package revision.
func versionParts(s string) ([]versionPart, bool) {
	i := digits(s)
	if i == 0 {
		return nil, false
	}
	parts := []versionPart{{firstNumber, s[:i]}}
	for i < len(s) && s[i] == '.' {
		n := digits(s[i+1:])
		if n == 0 {
			return nil, false
		}
		parts = append(parts, versionPart{dotNumber, s[i+1 : i+1+n]})
		i += 1 + n
	}
	if i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
		parts = append(parts, versionPart{letter, s[i : i+1]})
		i++
	}
	for i < len(s) && s[i] == '_' {
		start := i + 1
		i = start
		for i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
			i++
		}
		word := s[start:i]
		if suffixOrder[word] == 0 {
			return nil, false
		}
		parts = append(parts, versionPart{suffix, word})
		n := digits(s[i:])
		if n > 0 {
			parts = append(parts, versionPart{suffixNumber, s[i : i+n]})
			i += n
		}
	}
	if i < len(s) && s[i] == '~' {
		start := i + 1
		i = start
		for i < len(s) && strings.ContainsRune("0123456789abcdefABCDEF", rune(s[i])) {
			i++
		}
		if i == start {
			return nil, false
		}
		parts = append(parts, versionPart{commitHash, s[start:i]})
	}
	if strings.HasPrefix(s[i:], "-r") {
		i += 2
		n := digits(s[i:])
		if n == 0 {
			return nil, false
		}
		parts = append(parts, versionPart{revision, s[i : i+n]})
		i += n
	}
	return append(parts, versionPart{kind: end}), i == len(s)
}

func compareVersions(a, b string, prefix bool) int {
	x, xOK := versionParts(a)
	y, yOK := versionParts(b)
	if !xOK || !yOK {
		return strings.Compare(a, b)
	}
	for i, p := range x {
		q := y[i]
		if p.kind != q.kind {
			switch {
			case q.kind == end && prefix:
				return 0
			case p.kind == suffix && suffixOrder[p.value] < 0:
				return -1
			case q.kind == suffix && suffixOrder[q.value] < 0:
				return 1
			default:
				return cmp.Compare(q.kind, p.kind)
			}
		}
		var order int
		switch p.kind {
		case end:
			return 0
		case suffix:
			order = cmp.Compare(suffixOrder[p.value], suffixOrder[q.value])
		case firstNumber, dotNumber, suffixNumber, revision:
			if p.kind == dotNumber && (strings.HasPrefix(p.value, "0") || strings.HasPrefix(q.value, "0")) {
				order = strings.Compare(p.value, q.value)
			} else {
				a, b := strings.TrimLeft(p.value, "0"), strings.TrimLeft(q.value, "0")
				order = cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
			}
		default:
			order = strings.Compare(p.value, q.value)
		}
		if order != 0 {
			return order
		}
	}
	return 0
}
