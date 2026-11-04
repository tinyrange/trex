package uup

import "sort"

// Normalize each immutable name once, not once per comparison. Values and keys
// move together, retaining the original comparator and its non-stable ordering.
type cixNameSorter[T any] struct {
	values []T
	keys   []string
}

func (s cixNameSorter[T]) Len() int           { return len(s.values) }
func (s cixNameSorter[T]) Less(i, j int) bool { return s.keys[i] < s.keys[j] }
func (s cixNameSorter[T]) Swap(i, j int) {
	s.values[i], s.values[j] = s.values[j], s.values[i]
	s.keys[i], s.keys[j] = s.keys[j], s.keys[i]
}
func sortCIXNames[T any](values []T, name func(T) string) {
	keys := make([]string, len(values))
	for i, value := range values {
		keys[i] = normalizeCIXName(name(value))
	}
	sort.Sort(cixNameSorter[T]{values, keys})
}
