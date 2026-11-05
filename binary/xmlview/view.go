// Package xmlview defines read-only native access to immutable XML trees.
// It exposes values and iterators, never mutable backing slices.
package xmlview

import "iter"

type Attribute struct{ Name, Namespace, Prefix, Value string }

type Node interface {
	Name() string
	Namespace() string
	Text() string
	Attributes() iter.Seq[Attribute]
	Children() iter.Seq[Node]
	Attribute(name, namespace string) (string, bool)
}

// Provider is implemented by native immutable XML values. Starlark objects
// cannot synthesize a provider by exposing similarly named attributes.
type Provider interface{ XMLView() Node }
