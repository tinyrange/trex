package star

import (
	"iter"

	"github.com/tinyrange/trex/binary/xmlview"
)

// xmlNodeView retains the immutable binary.xml tree without exposing slices.
type xmlNodeView struct{ node *binaryXMLNode }

func (n *binaryXMLNode) XMLView() xmlview.Node { return xmlNodeView{n} }

func (n xmlNodeView) Name() string      { return n.node.name }
func (n xmlNodeView) Namespace() string { return n.node.namespace }
func (n xmlNodeView) Text() string      { return n.node.allText() }
func (n xmlNodeView) Attributes() iter.Seq[xmlview.Attribute] {
	return func(yield func(xmlview.Attribute) bool) {
		for _, a := range n.node.attributes {
			if !yield(xmlview.Attribute{Name: a.name, Namespace: a.namespace, Prefix: a.prefix, Value: a.value}) {
				return
			}
		}
	}
}
func (n xmlNodeView) Children() iter.Seq[xmlview.Node] {
	return func(yield func(xmlview.Node) bool) {
		for _, part := range n.node.content {
			if part.kind == binaryXMLChild && !yield(xmlNodeView{part.child}) {
				return
			}
		}
	}
}
func (n xmlNodeView) Attribute(name, namespace string) (string, bool) {
	for _, a := range n.node.attributes {
		if a.name == name && a.namespace == namespace {
			return a.value, true
		}
	}
	return "", false
}
