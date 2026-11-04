package windows

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/binary/xmlview"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// assembly_declarations extracts raw direct file/directory/security membership
// declarations once from an immutable XML view. It does not interpret macros,
// choose winners, resolve security references, or authorize filesystem effects.
// Foreign-namespace elements are not assembly declarations. Duplicate and
// unknown declarations remain explicit for the caller's qualification policy.
func assemblyDeclarationsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("assembly_declarations", args, kwargs, "root", &value); err != nil {
		return nil, err
	}
	provider, ok := value.(xmlview.Provider)
	if !ok {
		return nil, fmt.Errorf("assembly_declarations requires a binary.xml_node")
	}
	root := provider.XMLView()
	ns := root.Namespace()
	if ns != "urn:schemas-microsoft-com:asm.v1" && ns != "urn:schemas-microsoft-com:asm.v3" {
		return nil, fmt.Errorf("unsupported runtime assembly namespace")
	}
	c := assemblyDeclarationCollector{remaining: 1 << 20, namespace: ns}
	var architectures, files, directories, definitions, memberships starlark.Tuple
	managed := false
	for node := range root.Children() {
		if !c.take() {
			break
		}
		if node.Namespace() != ns {
			continue
		}
		switch node.Name() {
		case "assemblyIdentity":
			architectures = append(architectures, c.attr(node, "processorArchitecture", starlark.String("")))
		case "file":
			refs, links := starlark.Tuple{}, starlark.Tuple{}
			for child := range node.Children() {
				if !c.take() {
					break
				}
				if child.Namespace() != ns {
					continue
				}
				switch child.Name() {
				case "gac", "ngen":
					managed = true
				case "securityDescriptor":
					refs = append(refs, c.security(child, false))
				case "link":
					content := strings.TrimSpace(child.Text()) != ""
					for range child.Children() {
						content = true
						break
					}
					links = append(links, starfile.NewRecord(starlark.StringDict{
						"destination": c.attr(child, "destination", starlark.String("")),
						"attributes":  c.attributes(child), "has_content": starlark.Bool(content),
					}))
				}
			}
			fields := starlark.StringDict{"links": links, "security_references": refs}
			for _, pair := range [][2]string{{"name", "name"}, {"destination_name", "destinationName"}, {"template", "destinationPath"}, {"attributes", "attributes"}, {"compress", "compress"}, {"writable_type", "writeableType"}, {"load_from", "loadFrom"}} {
				fallback := starlark.Value(starlark.None)
				if pair[0] == "compress" {
					fallback = starlark.String("true")
				}
				fields[pair[0]] = c.attr(node, pair[1], fallback)
			}
			files = append(files, starfile.NewRecord(fields))
		case "directories":
			for child := range node.Children() {
				if !c.take() {
					break
				}
				if child.Namespace() != ns {
					continue
				}
				var refs starlark.Tuple
				for ref := range child.Children() {
					if !c.take() {
						break
					}
					if ref.Namespace() == ns && ref.Name() == "securityDescriptor" {
						refs = append(refs, c.security(ref, false))
					}
				}
				directories = append(directories, starfile.NewRecord(starlark.StringDict{
					"tag": starlark.String(child.Name()), "template": c.attr(child, "destinationPath", starlark.String("")),
					"attributes": c.attributes(child), "security_references": refs,
				}))
			}
		case "trustInfo":
			for _, definition := range c.path([]xmlview.Node{node}, []string{"security", "accessControl", "securityDescriptorDefinitions", "securityDescriptorDefinition"}) {
				definitions = append(definitions, c.security(definition, true))
			}
		case "memberships":
			for _, membership := range c.path([]xmlview.Node{node}, []string{"categoryMembership"}) {
				var ids starlark.Tuple
				for _, id := range c.path([]xmlview.Node{membership}, []string{"id"}) {
					fields := starlark.StringDict{}
					for _, name := range []string{"name", "publicKeyToken", "typeName", "version"} {
						fields[name] = c.attr(id, name, starlark.String(""))
					}
					ids = append(ids, starfile.NewRecord(fields))
				}
				memberships = append(memberships, ids)
			}
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	result := starfile.NewRecord(starlark.StringDict{"architectures": architectures, "files": files, "directories": directories, "security_definitions": definitions, "memberships": memberships, "managed_assembly": starlark.Bool(managed)})
	result.Freeze()
	return result, nil
}

type assemblyDeclarationCollector struct {
	remaining int
	namespace string
	err       error
}

func (c *assemblyDeclarationCollector) take() bool {
	if c.remaining == 0 {
		c.err = fmt.Errorf("assembly declarations exceed node/attribute bound")
		return false
	}
	c.remaining--
	return true
}
func (c *assemblyDeclarationCollector) attr(node xmlview.Node, name string, fallback starlark.Value) starlark.Value {
	if text, ok := node.Attribute(name, ""); ok {
		return starlark.String(text)
	}
	return fallback
}
func (c *assemblyDeclarationCollector) attributes(node xmlview.Node) starlark.Value {
	result := []starlark.Value{}
	for attr := range node.Attributes() {
		if !c.take() {
			break
		}
		d := starlark.NewDict(4)
		for _, pair := range [][2]string{{"name", attr.Name}, {"namespace", attr.Namespace}, {"prefix", attr.Prefix}, {"value", attr.Value}} {
			_ = d.SetKey(starlark.String(pair[0]), starlark.String(pair[1]))
		}
		result = append(result, d)
	}
	return starlark.NewList(result)
}
func (c *assemblyDeclarationCollector) security(node xmlview.Node, definition bool) starlark.Value {
	fields := starlark.StringDict{"name": c.attr(node, "name", starlark.None), "attributes": c.attributes(node)}
	if definition {
		fields["sddl"] = c.attr(node, "sddl", starlark.None)
		fields["operation_hint"] = c.attr(node, "operationHint", starlark.None)
	}
	return starfile.NewRecord(fields)
}
func (c *assemblyDeclarationCollector) path(nodes []xmlview.Node, steps []string) []xmlview.Node {
	for _, step := range steps {
		var next []xmlview.Node
		for _, node := range nodes {
			for child := range node.Children() {
				if !c.take() {
					return nil
				}
				if child.Namespace() == c.namespace && child.Name() == step {
					next = append(next, child)
				}
			}
		}
		nodes = next
	}
	return nodes
}
