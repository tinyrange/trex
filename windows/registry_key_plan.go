package windows

import (
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

// Compact records own decoded strings only, never XML nodes or caller dictionaries.
// The detailed collector remains available for provenance inspection.
type registryKeyRecord struct {
	path             registryContributionPath
	text             string
	transition, side int
	owned            bool
}
type registryKeyRecords struct{ rows []registryKeyRecord }

func (*registryKeyRecords) String() string       { return "<windows.registry_key_records>" }
func (*registryKeyRecords) Type() string         { return "windows.registry_key_records" }
func (*registryKeyRecords) Freeze()              {}
func (*registryKeyRecords) Truth() starlark.Bool { return starlark.True }
func (*registryKeyRecords) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: windows.registry_key_records")
}

func validateRegistryKeyAttributes(attrs map[string]string) (bool, error) {
	for name := range attrs {
		switch name {
		case "keyName", "owner", "perUserVirtualization", "mapDesiredAccessToMaxAllowedAccess":
		default:
			return false, fmt.Errorf("unsupported registry key reduction attribute: %s", name)
		}
	}
	if v, ok := attrs["perUserVirtualization"]; ok && v != "Disable" && v != "DisableRecurse" {
		return false, fmt.Errorf("unsupported registry virtualization declaration")
	}
	if v, ok := attrs["mapDesiredAccessToMaxAllowedAccess"]; ok && v != "False" {
		return false, fmt.Errorf("unsupported registry maximum-access declaration")
	}
	owner, ok := attrs["owner"]
	if !ok {
		owner = "false"
	}
	switch strings.ToLower(owner) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported registry key owner")
	}
}

type registryPlanKey struct{ scope, path string }
type registryPlanNode struct {
	path, parent                 string
	text                         [2]string
	descriptor                   [2]starlark.Value
	owner                        starlark.Value
	collisions, operation, flags int
	present                      [2]bool
	explicit, boundary, changed  bool
}

func (*registryPlanNode) String() string       { return "<windows.registry_key_plan_node>" }
func (*registryPlanNode) Type() string         { return "windows.registry_key_plan_node" }
func (*registryPlanNode) Freeze()              {}
func (*registryPlanNode) Truth() starlark.Bool { return starlark.True }
func (*registryPlanNode) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: windows.registry_key_plan_node")
}

// Mapping projection allocates only the individual field requested by policy.
// No contribution history, source XML, or per-node hash table is retained.
func (n *registryPlanNode) Get(key starlark.Value) (starlark.Value, bool, error) {
	s, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	var v starlark.Value
	switch s {
	case "path":
		v = starlark.String(n.path)
	case "parent":
		v = starlark.String(n.parent)
	case "before_present":
		v = starlark.Bool(n.present[0])
	case "after_present":
		v = starlark.Bool(n.present[1])
	case "explicit":
		v = starlark.Bool(n.explicit)
	case "hive_boundary":
		v = starlark.Bool(n.boundary)
	case "owner":
		v = n.owner
		if v == nil {
			v = starlark.None
		}
	case "owned_addition_collisions":
		v = starlark.MakeInt(n.collisions)
	case "operation":
		v = starlark.MakeInt(n.operation)
	case "security_flags":
		v = starlark.MakeInt(n.flags)
	case "auxiliary_flags":
		v = starlark.MakeInt(0)
	case "descriptor":
		v = n.descriptor[1]
	case "old_descriptor":
		v = n.descriptor[0]
	case "subtree_changed":
		v = starlark.Bool(n.changed)
	default:
		return nil, false, nil
	}
	return v, true, nil
}

type registryPlanFamily struct {
	bucket     int
	identities [2]starlark.Value
}
type registryPlanTie struct {
	key          registryPlanKey
	side, bucket int
}

func registryKeyPlanBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var records *registryKeyRecords
	var families *starlark.List
	var changes *starlark.Dict
	var compile, matches starlark.Callable
	if err := starlark.UnpackArgs("registry_key_plan", args, kwargs, "records", &records, "families", &families, "value_changes", &changes, "compile_security", &compile, "security_matches", &matches); err != nil {
		return nil, err
	}
	if families.Len() > 65536 || changes.Len() > registryContributionMaxRecords {
		return nil, fmt.Errorf("registry key plan exceeds input bounds")
	}
	order := make([]registryPlanFamily, families.Len())
	for i := 0; i < families.Len(); i++ {
		value := families.Index(i)
		tuple, ok := value.(starlark.Tuple)
		if !ok || len(tuple) != 3 {
			return nil, fmt.Errorf("registry families require (bucket, before identity, after identity)")
		}
		bucket, err := starlark.AsInt32(tuple[0])
		if err != nil || bucket < 0 {
			return nil, fmt.Errorf("invalid registry family bucket")
		}
		for _, identity := range tuple[1:] {
			switch identity.(type) {
			case starlark.NoneType, starlark.String, starlark.Bytes:
			default:
				return nil, fmt.Errorf("registry family identities must be strings, bytes or None")
			}
		}
		order[i] = registryPlanFamily{bucket, [2]starlark.Value{tuple[1], tuple[2]}}
	}
	changeRows := changes.Items()
	// Sort indices, not records: the immutable collection is safely reusable.
	indices := make([]int, len(records.rows))
	for i, r := range records.rows {
		if r.transition >= len(order) {
			return nil, fmt.Errorf("registry key transition has no family bucket")
		}
		if order[r.transition].identities[r.side] == starlark.None {
			return nil, fmt.Errorf("registry key side has no component identity")
		}
		indices[i] = i
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a, b := records.rows[indices[i]], records.rows[indices[j]]
		if order[a.transition].bucket != order[b.transition].bucket {
			return order[a.transition].bucket < order[b.transition].bucket
		}
		return a.transition < b.transition
	})
	nodes := make(map[registryPlanKey]*registryPlanNode)
	ordered := make([]registryPlanKey, 0)
	tied := make(map[registryPlanTie]string)
	compiled := map[string]starlark.Value{"": starlark.None}
	// Bound expanded hierarchy as well as input declarations. Deep paths must
	// not amplify the collector's byte bound into unbounded prefix storage.
	budget := registryContributionBudget{registryContributionMaxRecords, registryContributionMaxBytes}
	for _, i := range indices {
		r := records.rows[i]
		parts := strings.Split(r.path.path, `\`)
		root := ""
		if len(parts) >= 3 {
			root = strings.ToLower(strings.Join(parts[:3], `\`))
		}
		if len(parts) < 4 || (root != `\registry\machine` && root != `\registry\user`) || (r.path.scope == "user" && root != `\registry\user`) {
			return nil, fmt.Errorf("registry reduction requires a resolved child path")
		}
		for _, p := range parts[1:] {
			if p == "" {
				return nil, fmt.Errorf("registry reduction requires a resolved child path")
			}
		}
		if r.path.scope == "system" && root == `\registry\user` && strings.ToLower(parts[3]) != ".default" {
			return nil, fmt.Errorf("explicit user hive requires separate reduction policy")
		}
		if r.text == "(inherit)" {
			return nil, fmt.Errorf("registry inherit sentinel requires explicit selection")
		}
		if r.text != "" {
			if _, ok := compiled[r.text]; !ok {
				v, err := starlark.Call(thread, compile, starlark.Tuple{starlark.String(r.text)}, nil)
				if err != nil {
					return nil, err
				}
				if _, ok := v.(starlark.Bytes); !ok {
					return nil, fmt.Errorf("registry selected descriptor must be bytes")
				}
				compiled[r.text] = v
			}
			tie := registryPlanTie{registryPlanKey{r.path.scope, r.path.folded}, r.side, order[r.transition].bucket}
			if prev, ok := tied[tie]; ok && prev != r.text {
				return nil, fmt.Errorf("registry descriptor priority has an unresolved family-bucket tie: %s", r.path.path)
			}
			tied[tie] = r.text
		}
		for depth := len(parts) - 1; depth >= 3; depth-- {
			path := strings.Join(parts[:depth+1], `\`)
			key := registryPlanKey{r.path.scope, strings.ToLower(path)}
			n := nodes[key]
			if n == nil {
				if err := budget.record(); err != nil {
					return nil, err
				}
				parent := strings.ToLower(strings.Join(parts[:depth], `\`))
				for _, s := range []string{path, key.path, parent} {
					if err := budget.text(s); err != nil {
						return nil, err
					}
				}
				n = &registryPlanNode{path: path, parent: parent, boundary: r.path.scope == "system" && depth == 3}
				nodes[key] = n
				ordered = append(ordered, key)
			}
			if depth != len(parts)-1 && n.present[r.side] {
				break
			}
			n.present[r.side] = true
			if depth != len(parts)-1 {
				continue
			}
			n.explicit = true
			if r.text != "" {
				n.text[r.side] = r.text
			}
			if r.side == 1 && (r.owned || r.text != "") {
				if n.owner == nil {
					n.owner = order[r.transition].identities[r.side]
				} else {
					n.collisions++
				}
			}
		}
	}
	for _, entry := range changeRows {
		tuple, ok := entry[0].(starlark.Tuple)
		if !ok || len(tuple) != 2 {
			return nil, fmt.Errorf("registry value changes require (scope,path) keys")
		}
		scope, ok1 := starlark.AsString(tuple[0])
		path, ok2 := starlark.AsString(tuple[1])
		changed, ok3 := entry[1].(starlark.Bool)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("invalid registry value change")
		}
		n := nodes[registryPlanKey{scope, path}]
		if n == nil || !n.explicit {
			return nil, fmt.Errorf("registry value has no corresponding admitted key: %s", path)
		}
		n.changed = bool(changed)
	}
	comparisons := make(map[[2]string]bool)
	for _, key := range ordered {
		n := nodes[key]
		n.operation = 2
		if n.present[1] {
			n.operation = 1
		}
		n.flags = 8
		if n.boundary {
			n.flags |= 2
		}
		if !n.present[0] {
			n.flags |= 0x20
		}
		n.descriptor = [2]starlark.Value{compiled[n.text[0]], compiled[n.text[1]]}
		if n.operation == 1 && !(n.text[0] != "" && n.text[0] == n.text[1]) {
			same, cached := comparisons[n.text]
			if !cached {
				value, err := starlark.Call(thread, matches, starlark.Tuple{n.descriptor[0], n.descriptor[1]}, nil)
				if err != nil {
					return nil, err
				}
				b, ok := value.(starlark.Bool)
				if !ok {
					return nil, fmt.Errorf("registry security comparison must return bool")
				}
				same = bool(b)
				comparisons[n.text] = same
			}
			if !same {
				n.flags &^= 8
			}
		}
		// Text was needed only for interning/selection, not physical planning.
		n.text = [2]string{}
	}
	depthOrder := append([]registryPlanKey(nil), ordered...)
	sort.SliceStable(depthOrder, func(i, j int) bool {
		return strings.Count(depthOrder[i].path, `\`) > strings.Count(depthOrder[j].path, `\`)
	})
	for _, key := range depthOrder {
		n := nodes[key]
		if n.operation == 1 && n.flags&0x20 == 0 && !n.changed && n.flags&8 != 0 {
			n.flags |= 0x40
		}
		n.changed = n.flags&0x40 == 0
		if p := nodes[registryPlanKey{key.scope, n.parent}]; p != nil && n.changed {
			p.changed = true
		}
	}
	system, user := starlark.NewDict(0), starlark.NewDict(0)
	for _, key := range ordered {
		target := system
		if key.scope == "user" {
			target = user
		}
		if err := target.SetKey(starlark.String(key.path), nodes[key]); err != nil {
			return nil, err
		}
	}
	result := starlark.NewDict(2)
	result.SetKey(starlark.String("system"), system)
	result.SetKey(starlark.String("user"), user)
	return result, nil
}
