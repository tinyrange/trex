package star

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

const (
	defaultBinaryXMLLimit = 16 << 20
	defaultBinaryXMLDepth = 256
	defaultBinaryXMLNodes = 1 << 20
)

type binaryXMLDocument struct {
	root   *binaryXMLNode
	prefix []binaryXMLPart
	suffix []binaryXMLPart
}

type binaryXMLAttribute struct {
	name      string
	namespace string
	prefix    string
	value     string
}

type binaryXMLNode struct {
	name       string
	namespace  string
	prefix     string
	attributes []binaryXMLAttribute
	content    []binaryXMLPart
}

type binaryXMLPartKind uint8

const (
	binaryXMLText binaryXMLPartKind = iota
	binaryXMLChild
	binaryXMLComment
	binaryXMLDirective
	binaryXMLProcInst
)

type binaryXMLPart struct {
	kind   binaryXMLPartKind
	text   string
	target string
	child  *binaryXMLNode
}

type binaryXMLNamespaceScope struct {
	parent       *binaryXMLNamespaceScope
	declarations map[string]string
}

const (
	xmlNamespace      = "http://www.w3.org/XML/1998/namespace"
	xmlnsNamespace    = "http://www.w3.org/2000/xmlns/"
	legacyXMLNSMarker = "xmlns"
)

func binaryXMLBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := defaultBinaryXMLLimit
	maxDepth := defaultBinaryXMLDepth
	maxNodes := defaultBinaryXMLNodes
	if err := starlark.UnpackArgs(
		"xml", args, kwargs,
		"value", &value,
		"maximum?", &maximum,
		"max_depth?", &maxDepth,
		"max_nodes?", &maxNodes,
	); err != nil {
		return nil, err
	}
	if maximum < 0 || maxDepth < 1 || maxNodes < 1 {
		return nil, fmt.Errorf("xml: limits must be positive")
	}
	data, err := bytesForBinaryValueLimited(value, int64(maximum))
	if err != nil {
		return nil, fmt.Errorf("xml: %w", err)
	}
	data, err = decodeXMLBytes(data)
	if err != nil {
		return nil, fmt.Errorf("xml: %w", err)
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(strings.ReplaceAll(label, "-", "")) {
		case "utf8", "utf16", "unicode":
			return input, nil
		default:
			return nil, fmt.Errorf("unsupported declared encoding %q", label)
		}
	}
	document := &binaryXMLDocument{}
	var root *binaryXMLNode
	stack := make([]*binaryXMLNode, 0, min(16, maxDepth))
	scope := &binaryXMLNamespaceScope{declarations: map[string]string{"xml": xmlNamespace, "xmlns": xmlnsNamespace}}
	scopes := []*binaryXMLNamespaceScope{scope}
	nodes := 0
	for {
		token, err := decoder.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xml: parse: %w", err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if len(stack) >= maxDepth {
				return nil, fmt.Errorf("xml: nesting depth exceeds limit %d", maxDepth)
			}
			nodes++
			if nodes > maxNodes {
				return nil, fmt.Errorf("xml: node count exceeds limit %d", maxNodes)
			}
			var declarations map[string]string
			for _, attribute := range token.Attr {
				switch {
				case attribute.Name.Space == "" && attribute.Name.Local == "xmlns":
					if declarations == nil {
						declarations = make(map[string]string)
					}
					declarations[""] = attribute.Value
				case attribute.Name.Space == "xmlns":
					if declarations == nil {
						declarations = make(map[string]string)
					}
					declarations[attribute.Name.Local] = attribute.Value
				}
			}
			scope := scopes[len(scopes)-1]
			if declarations != nil {
				scope = &binaryXMLNamespaceScope{parent: scope, declarations: declarations}
			}
			prefix := token.Name.Space
			namespace, known := scope.lookup(prefix)
			if prefix != "" && !known {
				return nil, fmt.Errorf("xml: undeclared namespace prefix %q", prefix)
			}
			node := &binaryXMLNode{name: token.Name.Local, namespace: namespace, prefix: prefix}
			node.attributes = make([]binaryXMLAttribute, 0, len(token.Attr))
			for _, attribute := range token.Attr {
				attributePrefix := attribute.Name.Space
				attributeNamespace := ""
				if attributePrefix == "xmlns" || (attributePrefix == "" && attribute.Name.Local == "xmlns") {
					attributeNamespace = legacyXMLNSMarker
				} else if attributePrefix != "" {
					var attributeKnown bool
					attributeNamespace, attributeKnown = scope.lookup(attributePrefix)
					if !attributeKnown {
						return nil, fmt.Errorf("xml: undeclared attribute namespace prefix %q", attributePrefix)
					}
				}
				node.attributes = append(node.attributes, binaryXMLAttribute{
					name:      attribute.Name.Local,
					namespace: attributeNamespace,
					prefix:    attributePrefix,
					value:     attribute.Value,
				})
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("xml: multiple root elements")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.content = append(parent.content, binaryXMLPart{kind: binaryXMLChild, child: node})
			}
			stack = append(stack, node)
			scopes = append(scopes, scope)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("xml: unmatched closing element %q", token.Name.Local)
			}
			current := stack[len(stack)-1]
			if current.name != token.Name.Local || current.prefix != token.Name.Space {
				return nil, fmt.Errorf("xml: closing element %q does not match %q", token.Name.Local, current.name)
			}
			stack = stack[:len(stack)-1]
			scopes = scopes[:len(scopes)-1]
		case xml.CharData:
			part := binaryXMLPart{kind: binaryXMLText, text: string(token)}
			if len(stack) != 0 {
				stack[len(stack)-1].content = append(stack[len(stack)-1].content, part)
			} else if root == nil {
				if strings.TrimSpace(part.text) != "" {
					return nil, fmt.Errorf("xml: character data before root element")
				}
				document.prefix = append(document.prefix, part)
			} else {
				if strings.TrimSpace(part.text) != "" {
					return nil, fmt.Errorf("xml: character data after root element")
				}
				document.suffix = append(document.suffix, part)
			}
		case xml.Comment:
			appendXMLPart(document, root, stack, binaryXMLPart{kind: binaryXMLComment, text: string(token)})
		case xml.Directive:
			appendXMLPart(document, root, stack, binaryXMLPart{kind: binaryXMLDirective, text: string(token)})
		case xml.ProcInst:
			appendXMLPart(document, root, stack, binaryXMLPart{kind: binaryXMLProcInst, target: token.Target, text: string(token.Inst)})
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("xml: parse: unclosed element %q", stack[len(stack)-1].name)
	}
	if root == nil {
		return nil, fmt.Errorf("xml: document has no root element")
	}
	document.root = root
	return document, nil
}

func (s *binaryXMLNamespaceScope) lookup(prefix string) (string, bool) {
	for scope := s; scope != nil; scope = scope.parent {
		if namespace, ok := scope.declarations[prefix]; ok {
			return namespace, true
		}
	}
	if prefix == "" {
		return "", true
	}
	return "", false
}

func appendXMLPart(document *binaryXMLDocument, root *binaryXMLNode, stack []*binaryXMLNode, part binaryXMLPart) {
	if len(stack) != 0 {
		stack[len(stack)-1].content = append(stack[len(stack)-1].content, part)
	} else if root == nil {
		document.prefix = append(document.prefix, part)
	} else {
		document.suffix = append(document.suffix, part)
	}
}

func decodeXMLBytes(data []byte) ([]byte, error) {
	if len(data) >= 3 && bytes.Equal(data[:3], []byte{0xef, 0xbb, 0xbf}) {
		return data[3:], nil
	}
	if len(data) < 2 {
		return data, nil
	}
	var order binary.ByteOrder
	switch {
	case data[0] == 0xff && data[1] == 0xfe:
		order = binary.LittleEndian
	case data[0] == 0xfe && data[1] == 0xff:
		order = binary.BigEndian
	default:
		return data, nil
	}
	data = data[2:]
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("UTF-16 input has odd size")
	}
	units := make([]uint16, len(data)/2)
	for index := range units {
		units[index] = order.Uint16(data[index*2:])
	}
	for index := 0; index < len(units); index++ {
		switch {
		case units[index] >= 0xd800 && units[index] <= 0xdbff:
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return nil, fmt.Errorf("UTF-16 input contains an unpaired high surrogate")
			}
			index++
		case units[index] >= 0xdc00 && units[index] <= 0xdfff:
			return nil, fmt.Errorf("UTF-16 input contains an unpaired low surrogate")
		}
	}
	return []byte(string(utf16.Decode(units))), nil
}

func (d *binaryXMLDocument) String() string       { return "<binary.xml_document>" }
func (d *binaryXMLDocument) Type() string         { return "binary.xml_document" }
func (d *binaryXMLDocument) Freeze()              {}
func (d *binaryXMLDocument) Truth() starlark.Bool { return starlark.True }
func (d *binaryXMLDocument) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *binaryXMLDocument) AttrNames() []string { return []string{"bytes", "root", "with_root"} }
func (d *binaryXMLDocument) Attr(name string) (starlark.Value, error) {
	switch name {
	case "root":
		return d.root, nil
	case "bytes":
		return starlark.NewBuiltin("bytes", d.bytesBuiltin), nil
	case "with_root":
		return starlark.NewBuiltin("with_root", d.withRootBuiltin), nil
	}
	return nil, nil
}

func (n *binaryXMLNode) String() string       { return "<binary.xml_node " + n.name + ">" }
func (n *binaryXMLNode) Type() string         { return "binary.xml_node" }
func (n *binaryXMLNode) Freeze()              {}
func (n *binaryXMLNode) Truth() starlark.Bool { return starlark.True }
func (n *binaryXMLNode) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", n.Type())
}
func (n *binaryXMLNode) AttrNames() []string {
	return []string{"attribute", "attributes", "bytes", "child", "children", "children_named", "direct_text", "name", "namespace", "prefix", "qualified_name", "text", "with_children", "with_text"}
}
func (n *binaryXMLNode) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(n.name), nil
	case "namespace":
		return starlark.String(n.namespace), nil
	case "prefix":
		return starlark.String(n.prefix), nil
	case "qualified_name":
		return starlark.String(qualifiedXMLName(n.prefix, n.name)), nil
	case "text":
		return starlark.String(n.allText()), nil
	case "direct_text":
		return starlark.String(n.directText()), nil
	case "attributes":
		values := make([]starlark.Value, 0, len(n.attributes))
		for _, attribute := range n.attributes {
			record := starlark.NewDict(4)
			_ = record.SetKey(starlark.String("name"), starlark.String(attribute.name))
			_ = record.SetKey(starlark.String("namespace"), starlark.String(attribute.namespace))
			_ = record.SetKey(starlark.String("prefix"), starlark.String(attribute.prefix))
			_ = record.SetKey(starlark.String("value"), starlark.String(attribute.value))
			values = append(values, record)
		}
		return starlark.NewList(values), nil
	case "children":
		children := n.childNodes()
		values := make([]starlark.Value, len(children))
		for index, child := range children {
			values[index] = child
		}
		return starlark.NewList(values), nil
	case "attribute":
		return starlark.NewBuiltin("attribute", n.attributeBuiltin), nil
	case "child":
		return starlark.NewBuiltin("child", n.childBuiltin), nil
	case "children_named":
		return starlark.NewBuiltin("children_named", n.childrenNamedBuiltin), nil
	case "bytes":
		return starlark.NewBuiltin("bytes", n.bytesBuiltin), nil
	case "with_children":
		return starlark.NewBuiltin("with_children", n.withChildrenBuiltin), nil
	case "with_text":
		return starlark.NewBuiltin("with_text", n.withTextBuiltin), nil
	default:
		return nil, nil
	}
}

func (n *binaryXMLNode) allText() string {
	var output strings.Builder
	for _, part := range n.content {
		switch part.kind {
		case binaryXMLText:
			output.WriteString(part.text)
		case binaryXMLChild:
			output.WriteString(part.child.allText())
		}
	}
	return output.String()
}

func (n *binaryXMLNode) directText() string {
	var output strings.Builder
	for _, part := range n.content {
		if part.kind == binaryXMLText {
			output.WriteString(part.text)
		}
	}
	return output.String()
}

func (n *binaryXMLNode) childNodes() []*binaryXMLNode {
	children := make([]*binaryXMLNode, 0)
	for _, part := range n.content {
		if part.kind == binaryXMLChild {
			children = append(children, part.child)
		}
	}
	return children
}

func (n *binaryXMLNode) attributeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	namespace := ""
	fallback := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("attribute", args, kwargs, "name", &name, "default?", &fallback, "namespace?", &namespace); err != nil {
		return nil, err
	}
	for _, attribute := range n.attributes {
		if attribute.name == name && attribute.namespace == namespace {
			return starlark.String(attribute.value), nil
		}
	}
	return fallback, nil
}

func (n *binaryXMLNode) childBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	namespace := ""
	if err := starlark.UnpackArgs("child", args, kwargs, "name", &name, "namespace?", &namespace); err != nil {
		return nil, err
	}
	for _, child := range n.childNodes() {
		if child.name == name && child.namespace == namespace {
			return child, nil
		}
	}
	return starlark.None, nil
}

func (n *binaryXMLNode) childrenNamedBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	namespace := ""
	if err := starlark.UnpackArgs("children_named", args, kwargs, "name", &name, "namespace?", &namespace); err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0)
	for _, child := range n.childNodes() {
		if child.name == name && child.namespace == namespace {
			values = append(values, child)
		}
	}
	return starlark.NewList(values), nil
}

func (d *binaryXMLDocument) withRootBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var root *binaryXMLNode
	if err := starlark.UnpackArgs("with_root", args, kwargs, "root", &root); err != nil {
		return nil, err
	}
	return &binaryXMLDocument{
		root:   root,
		prefix: append([]binaryXMLPart(nil), d.prefix...),
		suffix: append([]binaryXMLPart(nil), d.suffix...),
	}, nil
}

func (n *binaryXMLNode) withChildrenBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("with_children", args, kwargs, "children", &value); err != nil {
		return nil, err
	}
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("with_children: children must be iterable")
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	children := make([]*binaryXMLNode, 0)
	var item starlark.Value
	for iterator.Next(&item) {
		child, ok := item.(*binaryXMLNode)
		if !ok {
			return nil, fmt.Errorf("with_children: child %d is %s, want binary.xml_node", len(children), item.Type())
		}
		if len(children) >= defaultBinaryXMLNodes {
			return nil, fmt.Errorf("with_children: child count exceeds limit %d", defaultBinaryXMLNodes)
		}
		children = append(children, child)
	}
	clone := n.clone()
	content := make([]binaryXMLPart, 0, len(n.content)+len(children))
	inserted := false
	for _, part := range n.content {
		if part.kind == binaryXMLChild {
			if !inserted {
				for _, child := range children {
					content = append(content, binaryXMLPart{kind: binaryXMLChild, child: child})
				}
				inserted = true
			}
			continue
		}
		content = append(content, part)
	}
	if !inserted {
		for _, child := range children {
			content = append(content, binaryXMLPart{kind: binaryXMLChild, child: child})
		}
	}
	clone.content = content
	return clone, nil
}

func (n *binaryXMLNode) withTextBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackArgs("with_text", args, kwargs, "text", &text); err != nil {
		return nil, err
	}
	clone := n.clone()
	content := make([]binaryXMLPart, 0, len(n.content)+1)
	inserted := false
	for _, part := range n.content {
		if part.kind == binaryXMLText {
			if !inserted {
				content = append(content, binaryXMLPart{kind: binaryXMLText, text: text})
				inserted = true
			}
			continue
		}
		if !inserted && part.kind == binaryXMLChild {
			content = append(content, binaryXMLPart{kind: binaryXMLText, text: text})
			inserted = true
		}
		content = append(content, part)
	}
	if !inserted {
		content = append(content, binaryXMLPart{kind: binaryXMLText, text: text})
	}
	clone.content = content
	return clone, nil
}

func (n *binaryXMLNode) clone() *binaryXMLNode {
	return &binaryXMLNode{
		name:       n.name,
		namespace:  n.namespace,
		prefix:     n.prefix,
		attributes: append([]binaryXMLAttribute(nil), n.attributes...),
		content:    append([]binaryXMLPart(nil), n.content...),
	}
}

func (d *binaryXMLDocument) bytesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum := defaultBinaryXMLLimit
	if err := starlark.UnpackArgs("bytes", args, kwargs, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 0 {
		return nil, fmt.Errorf("bytes: maximum must be non-negative")
	}
	data, err := renderXML(d.prefix, d.root, d.suffix, maximum)
	if err != nil {
		return nil, fmt.Errorf("bytes: %w", err)
	}
	return starlark.Bytes(data), nil
}

func (n *binaryXMLNode) bytesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum := defaultBinaryXMLLimit
	if err := starlark.UnpackArgs("bytes", args, kwargs, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 0 {
		return nil, fmt.Errorf("bytes: maximum must be non-negative")
	}
	data, err := renderXML(nil, n, nil, maximum)
	if err != nil {
		return nil, fmt.Errorf("bytes: %w", err)
	}
	return starlark.Bytes(data), nil
}

type boundedXMLWriter struct {
	buffer  bytes.Buffer
	maximum int
}

func (w *boundedXMLWriter) Write(data []byte) (int, error) {
	if len(data) > w.maximum-w.buffer.Len() {
		return 0, fmt.Errorf("serialized XML exceeds limit %d", w.maximum)
	}
	return w.buffer.Write(data)
}

func (w *boundedXMLWriter) writeString(value string) error {
	_, err := w.Write([]byte(value))
	return err
}

func renderXML(prefix []binaryXMLPart, root *binaryXMLNode, suffix []binaryXMLPart, maximum int) ([]byte, error) {
	if root == nil {
		return nil, fmt.Errorf("document has no root element")
	}
	writer := &boundedXMLWriter{maximum: maximum}
	for _, part := range prefix {
		if err := renderXMLPart(writer, part); err != nil {
			return nil, err
		}
	}
	if err := renderXMLNode(writer, root); err != nil {
		return nil, err
	}
	for _, part := range suffix {
		if err := renderXMLPart(writer, part); err != nil {
			return nil, err
		}
	}
	return bytes.Clone(writer.buffer.Bytes()), nil
}

func renderXMLNode(writer *boundedXMLWriter, node *binaryXMLNode) error {
	if err := writer.writeString("<" + qualifiedXMLName(node.prefix, node.name)); err != nil {
		return err
	}
	for _, attribute := range node.attributes {
		if err := writer.writeString(" " + qualifiedXMLName(attribute.prefix, attribute.name) + "=\""); err != nil {
			return err
		}
		if err := xml.EscapeText(writer, []byte(attribute.value)); err != nil {
			return err
		}
		if err := writer.writeString("\""); err != nil {
			return err
		}
	}
	if len(node.content) == 0 {
		return writer.writeString("/>")
	}
	if err := writer.writeString(">"); err != nil {
		return err
	}
	for _, part := range node.content {
		if err := renderXMLPart(writer, part); err != nil {
			return err
		}
	}
	return writer.writeString("</" + qualifiedXMLName(node.prefix, node.name) + ">")
}

func renderXMLPart(writer *boundedXMLWriter, part binaryXMLPart) error {
	switch part.kind {
	case binaryXMLText:
		return xml.EscapeText(writer, []byte(part.text))
	case binaryXMLChild:
		return renderXMLNode(writer, part.child)
	case binaryXMLComment:
		return writer.writeString("<!--" + part.text + "-->")
	case binaryXMLDirective:
		return writer.writeString("<!" + part.text + ">")
	case binaryXMLProcInst:
		separator := ""
		if part.text != "" {
			separator = " "
		}
		return writer.writeString("<?" + part.target + separator + part.text + "?>")
	default:
		return fmt.Errorf("unknown XML content kind %d", part.kind)
	}
}

func qualifiedXMLName(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + ":" + name
}
