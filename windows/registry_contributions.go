package windows

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/binary/xmlview"
	"go.starlark.net/starlark"
)

// This collector decodes declarations, not admission, security authorization,
// contribution precedence, mutable-value policy, or a hive transaction. All
// contributors, including duplicates and unchanged ones, survive in input order.
const registryContributionMaxRecords = 1 << 20
const registryContributionMaxBytes = 256 << 20

type registryContributionInput struct {
	root         xmlview.Node
	architecture string
	side         int
	owner        int
}
type registryContributionPath struct{ scope, path, folded string }
type registryContributionPathKey struct{ key, architecture string }
type registryContributionValueKey struct {
	architecture, name, kind, value, mutable, hint, downlevel string
}
type registryContributionValue struct {
	name          string
	kind          uint32
	raw           starlark.Bytes
	mutable, hint string
	empty         bool
}
type registryContributionBudget struct{ records, bytes int }

func (b *registryContributionBudget) record() error {
	if b.records == 0 {
		return fmt.Errorf("registry contributions exceed record bound")
	}
	b.records--
	return nil
}
func (b *registryContributionBudget) text(value string) error {
	if len(value) > b.bytes {
		return fmt.Errorf("registry contributions exceed byte bound")
	}
	b.bytes -= len(value)
	return nil
}

func registryContributionsBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var manifests *starlark.List
	var resolve, expand starlark.Callable
	var captureRecords bool
	prefix := starlark.Value(starlark.None)
	maxRecords, maxBytes := registryContributionMaxRecords, registryContributionMaxBytes
	if err := starlark.UnpackArgs("registry_contributions", args, kwargs,
		"manifests", &manifests, "resolve_key", &resolve, "expand_string", &expand,
		"key_prefix?", &prefix, "max_records?", &maxRecords, "max_bytes?", &maxBytes, "capture_key_records?", &captureRecords); err != nil {
		return nil, err
	}
	if manifests.Len() > 65536 || maxRecords < 1 || maxRecords > registryContributionMaxRecords || maxBytes < 1 || maxBytes > registryContributionMaxBytes {
		return nil, fmt.Errorf("registry contributions: invalid limits or manifest count")
	}
	keyPrefix := ""
	captureKeys := prefix != starlark.None
	if captureKeys {
		var ok bool
		keyPrefix, ok = starlark.AsString(prefix)
		if !ok || len(keyPrefix) > 32768 || strings.ContainsRune(keyPrefix, 0) {
			return nil, fmt.Errorf("registry contributions: invalid key prefix")
		}
		keyPrefix = strings.ToLower(keyPrefix)
	}
	// Capture input rows before any user callback. Callbacks run on this thread
	// and must be pure for this invocation; native code never calls from workers.
	inputs := make([]registryContributionInput, 0, manifests.Len())
	for row := range manifests.Elements() {
		dict, ok := row.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("registry contribution manifest must be a dict")
		}
		var root starlark.Value
		var arch, side string
		var owner int
		if err := starlark.UnpackArgs("registry contribution manifest", nil, dict.Items(), "root", &root, "architecture", &arch, "side", &side, "owner", &owner); err != nil {
			return nil, err
		}
		provider, ok := root.(xmlview.Provider)
		if !ok {
			return nil, fmt.Errorf("registry contribution root must be a binary.xml_node")
		}
		if owner < 0 || owner > 1<<30 || (side != "before" && side != "after") || len(arch) > 256 {
			return nil, fmt.Errorf("invalid registry contribution owner, side or architecture length")
		}
		sideIndex := 0
		if side == "after" {
			sideIndex = 1
		}
		inputs = append(inputs, registryContributionInput{provider.XMLView(), arch, sideIndex, owner})
	}
	budget := registryContributionBudget{maxRecords, maxBytes}
	paths := make(map[registryContributionPathKey]registryContributionPath)
	values := make(map[registryContributionValueKey]registryContributionValue)
	lastOwner := -1
	groups := starlark.NewDict(0)
	keys := starlark.NewDict(0)
	keyRecords := starlark.NewDict(0)
	for _, input := range inputs {
		if input.owner != lastOwner {
			// Bound pure decoding memo to one contiguous contribution owner.
			clear(values)
			lastOwner = input.owner
		}
		root, ns := input.root, input.root.Namespace()
		if ns != "urn:schemas-microsoft-com:asm.v1" && ns != "urn:schemas-microsoft-com:asm.v3" {
			return nil, fmt.Errorf("unsupported runtime registry assembly namespace")
		}
		if err := budget.record(); err != nil {
			return nil, err
		}
		definitions, err := registryContributionDefinitions(root, &budget)
		if err != nil {
			return nil, err
		}
		for container := range root.Children() {
			if container.Name() != "registryKeys" || container.Namespace() != ns {
				continue
			}
			for node := range container.Children() {
				if err := budget.record(); err != nil {
					return nil, err
				}
				if node.Name() != "registryKey" || node.Namespace() != ns {
					return nil, fmt.Errorf("unsupported registryKeys child")
				}
				attrs, err := registryContributionAttributes(node, &budget)
				if err != nil {
					return nil, err
				}
				key := attrs["keyName"]
				if key == "" {
					return nil, fmt.Errorf("registry declaration requires keyName")
				}
				references := 0
				var selectedSecurity starlark.Value = starlark.None
				for child := range node.Children() {
					if child.Name() == "securityDescriptor" && child.Namespace() == ns {
						references++
						if references > 1 {
							return nil, fmt.Errorf("duplicate runtime registry security reference")
						}
						name, found := child.Attribute("name", "")
						if !found || definitions[name] == "" {
							return nil, fmt.Errorf("unresolved runtime registry security reference: %s", name)
						}
						selectedSecurity = starlark.String(definitions[name])
					}
				}
				// Empty keys participate in key-side capture, but never imply
				// deletion or creation. Their security references still validate.
				pathKey := registryContributionPathKey{key, input.architecture}
				path, found := paths[pathKey]
				if !found {
					result, err := starlark.Call(thread, resolve, starlark.Tuple{starlark.String(key), starlark.String(input.architecture)}, nil)
					if err != nil {
						return nil, err
					}
					dict, ok := result.(*starlark.Dict)
					if !ok {
						return nil, fmt.Errorf("registry key resolver must return dict(scope, path)")
					}
					if err := starlark.UnpackArgs("registry resolved key", nil, dict.Items(), "scope", &path.scope, "path", &path.path); err != nil {
						return nil, err
					}
					if path.scope != "system" && path.scope != "user" {
						return nil, fmt.Errorf("invalid resolved registry scope")
					}
					// The callback supplies OS-version root/redirection policy.
					// This is not a physical hive or profile mount binding.
					if strings.ContainsRune(path.path, 0) || strings.Contains(path.path, "$(") || !strings.HasPrefix(strings.ToLower(path.path), "\\registry\\") {
						return nil, fmt.Errorf("invalid resolved registry path")
					}
					if err := budget.text(path.path); err != nil {
						return nil, err
					}
					path.folded = strings.ToLower(path.path)
					paths[pathKey] = path
				}
				if captureRecords {
					owner := starlark.MakeInt(input.owner)
					rows, found, err := keyRecords.Get(owner)
					if err != nil {
						return nil, err
					}
					if !found {
						rows = starlark.NewList(nil)
						if err := keyRecords.SetKey(owner, rows); err != nil {
							return nil, err
						}
					}
					attributes := starlark.NewDict(len(attrs))
					for name, value := range attrs {
						if err := attributes.SetKey(starlark.String(name), starlark.String(value)); err != nil {
							return nil, err
						}
					}
					side := "before"
					if input.side == 1 {
						side = "after"
					}
					row := starlark.Tuple{starlark.String(side), starlark.String(path.scope), starlark.String(path.path), attributes, selectedSecurity}
					if err := rows.(*starlark.List).Append(row); err != nil {
						return nil, err
					}
				}
				if captureKeys && strings.HasPrefix(path.folded, keyPrefix) {
					identity := starlark.Tuple{starlark.String(path.scope), starlark.String(path.folded)}
					prior, found, err := keys.Get(identity)
					if err != nil {
						return nil, err
					}
					var sides *starlark.List
					if found {
						sides = prior.(*starlark.List)
					} else {
						sides = starlark.NewList([]starlark.Value{starlark.String(path.path), starlark.False, starlark.False})
						if err := keys.SetKey(identity, sides); err != nil {
							return nil, err
						}
					}
					if err := sides.SetIndex(1+input.side, starlark.True); err != nil {
						return nil, err
					}
				}
				for node := range node.Children() {
					if node.Name() != "registryValue" || node.Namespace() != ns {
						continue
					}
					if err := budget.record(); err != nil {
						return nil, err
					}
					for range node.Children() {
						return nil, fmt.Errorf("unsupported registryValue content")
					}
					if strings.TrimSpace(node.Text()) != "" {
						return nil, fmt.Errorf("unsupported registryValue content")
					}
					attrs, err := registryContributionAttributes(node, &budget)
					if err != nil {
						return nil, err
					}
					key, err := registryContributionDecodeKey(attrs, input.architecture)
					if err != nil {
						return nil, err
					}
					value, found := values[key]
					if !found {
						value, err = registryContributionDecode(thread, expand, key, &budget)
						if err != nil {
							return nil, err
						}
						if err := budget.text(value.name); err != nil {
							return nil, err
						}
						if err := budget.text(string(value.raw)); err != nil {
							return nil, err
						}
						values[key] = value
					}
					identity := starlark.Tuple{starlark.String(path.scope), starlark.String(path.folded), starlark.String(strings.ToLower(value.name))}
					pair, found, err := groups.Get(identity)
					if err != nil {
						return nil, err
					}
					if !found {
						pair = starlark.NewList([]starlark.Value{starlark.NewList(nil), starlark.NewList(nil)})
						if err := groups.SetKey(identity, pair); err != nil {
							return nil, err
						}
					}
					contribution := starlark.Tuple{starlark.MakeInt(input.owner), starlark.MakeUint64(uint64(value.kind)), value.raw, starlark.String(value.mutable), starlark.String(value.hint), starlark.Bool(value.empty)}
					if err := pair.(*starlark.List).Index(input.side).(*starlark.List).Append(contribution); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	result := starlark.NewDict(2)
	result.SetKey(starlark.String("groups"), groups)
	result.SetKey(starlark.String("keys"), keys)
	if captureRecords {
		result.SetKey(starlark.String("key_records"), keyRecords)
	}
	return result, nil
}

func registryContributionAttributes(node xmlview.Node, budget *registryContributionBudget) (map[string]string, error) {
	attrs := make(map[string]string)
	for a := range node.Attributes() {
		if a.Namespace == "xmlns" {
			continue
		}
		if a.Namespace != "" {
			return nil, fmt.Errorf("unsupported attribute namespace %q", a.Namespace)
		}
		if _, found := attrs[a.Name]; found {
			return nil, fmt.Errorf("duplicate attribute %q", a.Name)
		}
		if err := budget.text(a.Name); err != nil {
			return nil, err
		}
		if err := budget.text(a.Value); err != nil {
			return nil, err
		}
		attrs[a.Name] = a.Value
	}
	return attrs, nil
}

func registryContributionDefinitions(root xmlview.Node, budget *registryContributionBudget) (map[string]string, error) {
	nodes := []xmlview.Node{root}
	for _, tag := range []string{"trustInfo", "security", "accessControl", "securityDescriptorDefinitions", "securityDescriptorDefinition"} {
		var next []xmlview.Node
		for _, node := range nodes {
			for child := range node.Children() {
				if child.Name() == tag && child.Namespace() == root.Namespace() {
					if err := budget.record(); err != nil {
						return nil, err
					}
					next = append(next, child)
				}
			}
		}
		nodes = next
	}
	definitions := make(map[string]string, len(nodes))
	for _, node := range nodes {
		name, _ := node.Attribute("name", "")
		sddl, _ := node.Attribute("sddl", "")
		if name == "" || sddl == "" {
			return nil, fmt.Errorf("runtime security definition requires name and sddl")
		}
		if definitions[name] != "" {
			return nil, fmt.Errorf("duplicate runtime security definition: %s", name)
		}
		if err := budget.text(name); err != nil {
			return nil, err
		}
		if err := budget.text(sddl); err != nil {
			return nil, err
		}
		definitions[name] = sddl
	}
	return definitions, nil
}

func registryContributionDecodeKey(attrs map[string]string, architecture string) (registryContributionValueKey, error) {
	for name := range attrs {
		switch name {
		case "name", "valueType", "value", "mutable", "operationHint", "IEDownlevelValue":
		default:
			return registryContributionValueKey{}, fmt.Errorf("unsupported registry value preparation attributes: %s", name)
		}
	}
	for _, name := range []string{"name", "valueType", "value"} {
		if _, ok := attrs[name]; !ok {
			return registryContributionValueKey{}, fmt.Errorf("registry value preparation requires %s", name)
		}
	}
	mutable, ok := attrs["mutable"]
	if !ok {
		mutable = "false"
	}
	if mutable != "true" && mutable != "false" {
		return registryContributionValueKey{}, fmt.Errorf("unsupported registry mutable spelling")
	}
	hint := attrs["operationHint"]
	if hint != "" && hint != "append" && hint != "prepend" && hint != "replace" {
		return registryContributionValueKey{}, fmt.Errorf("unsupported registry operation hint")
	}
	return registryContributionValueKey{architecture, attrs["name"], attrs["valueType"], attrs["value"], mutable, hint, attrs["IEDownlevelValue"]}, nil
}

func registryContributionDecode(thread *starlark.Thread, expand starlark.Callable, key registryContributionValueKey, budget *registryContributionBudget) (registryContributionValue, error) {
	value := registryContributionValue{mutable: key.mutable, hint: key.hint}
	switch key.kind {
	case "REG_NONE":
		value.kind = 0
	case "REG_SZ":
		value.kind = 1
	case "REG_EXPAND_SZ":
		value.kind = 2
	case "REG_BINARY":
		value.kind = 3
	case "REG_DWORD":
		value.kind = 4
	case "REG_MULTI_SZ":
		value.kind = 7
	case "REG_QWORD":
		value.kind = 11
	default:
		return value, fmt.Errorf("unsupported ordinary registry value type: %s", key.kind)
	}
	expandText := func(text string) (string, error) {
		if strings.ContainsRune(text, 0) {
			return "", fmt.Errorf("registry expansion requires a NUL-free string")
		}
		if !strings.Contains(text, "$(") {
			return text, nil
		}
		result, err := starlark.Call(thread, expand, starlark.Tuple{starlark.String(text), starlark.String(key.architecture)}, nil)
		if err != nil {
			return "", err
		}
		output, ok := starlark.AsString(result)
		if !ok || strings.ContainsRune(output, 0) {
			return "", fmt.Errorf("registry string expansion must return a NUL-free string")
		}
		if err := budget.text(output); err != nil {
			return "", err
		}
		return output, nil
	}
	var err error
	value.name, err = expandText(key.name)
	if err != nil {
		return value, err
	}
	text := key.value
	if value.kind == 1 || value.kind == 2 || value.kind == 7 {
		text, err = expandText(text)
		if err != nil {
			return value, err
		}
	}
	decoded, err := decodeAssemblyRegistryData(key.kind, text)
	if err != nil {
		return value, err
	}
	var data registryData
	switch value.kind {
	case 1, 2:
		text, _ := starlark.AsString(decoded)
		data = registryData{typ: value.kind, data: utf16Nul(text)}
	case 7:
		entries := decoded.(*starlark.List)
		var raw []byte
		for entry := range entries.Elements() {
			text, _ := starlark.AsString(entry)
			raw = append(raw, utf16Nul(text)...)
		}
		if entries.Len() == 0 {
			raw = append(raw, 0, 0)
		}
		data = registryData{typ: 7, data: append(raw, 0, 0)}
	default:
		data, err = registryDataFromStarlark(key.kind, decoded)
	}
	if err != nil {
		return value, err
	}
	value.raw = starlark.Bytes(data.data)
	value.empty = value.kind == 7 && text == ""
	return value, nil
}
