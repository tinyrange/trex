// Package lab describes and operates a collection of machines and isolated
// networks. Definitions contain portable recipe and media references.
package lab

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Definition struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
	Nodes   []Node `json:"nodes"`
	Links   []Link `json:"links"`
}

func Blank() Definition {
	return Definition{Version: 1, Name: "Untitled lab", Nodes: []Node{}, Links: []Link{}}
}

type Node struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Recipe string            `json:"recipe"`
	X      float64           `json:"x"`
	Y      float64           `json:"y"`
	Config map[string]any    `json:"config"`
	Media  map[string]string `json:"media"`
}

type End struct {
	Node string `json:"node"`
	Port string `json:"port"`
}

type Link struct {
	A End `json:"a"`
	B End `json:"b"`
}

type Option struct {
	Value any    `json:"value"`
	Label string `json:"label"`
}

type Field struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Group   string   `json:"group"`
	Kind    string   `json:"kind"`
	Default any      `json:"default,omitempty"`
	Options []Option `json:"options,omitempty"`
	Impact  string   `json:"impact"`
	Help    string   `json:"help,omitempty"`
	Min     int      `json:"min,omitempty"`
	Max     int      `json:"max,omitempty"`
}

type Media struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Hint    string `json:"hint"`
	Kind    string `json:"kind"`
	When    string `json:"when,omitempty"`
	Equals  string `json:"equals,omitempty"`
	Default string `json:"default,omitempty"`
}

type Port struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

type Recipe struct {
	ID                string  `json:"id"`
	Title             string  `json:"title"`
	Family            string  `json:"family"`
	Group             string  `json:"group"`
	Description       string  `json:"description"`
	Fields            []Field `json:"fields"`
	Media             []Media `json:"media"`
	Ports             []Port  `json:"ports"`
	Blocked           string  `json:"blocked,omitempty"`
	Hint              string  `json:"hint,omitempty"`
	Function          string  `json:"-"`
	Module            string  `json:"-"`
	Backend           string  `json:"-"`
	AbsolutePointer   bool    `json:"-"`
	DomainController  string  `json:"domainController,omitempty"`
	LegacyController  string  `json:"legacyController,omitempty"`
	ProvidesDomain    bool    `json:"-"`
	FixedComputerName bool    `json:"-"`
}

func (r Recipe) UsesQEMU() bool {
	return r.Backend == "qemu"
}

type Template struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Definition  Definition `json:"definition"`
}

type Issue struct {
	Node    string `json:"node,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

type Change struct {
	Node   string `json:"node"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

type Plan struct {
	Changes []Change `json:"changes"`
	Issues  []Issue  `json:"issues"`
}

type MediaCheck func(recipe Recipe, slot Media, ref string) error

var (
	nodeID       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	computerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
)

func (n Node) Value(r Recipe, key string) any {
	if value, ok := n.Config[key]; ok {
		if key == "software" {
			if choices, valid := softwareChoices(value); valid {
				return choices
			}
		}
		return value
	}
	for _, f := range r.Fields {
		if f.Key == key {
			return f.Default
		}
	}
	return nil
}

func (n Node) String(r Recipe, key string) string {
	value, _ := n.Value(r, key).(string)
	return value
}

func (d Definition) Node(id string) (Node, bool) {
	for _, n := range d.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// Clone keeps snapshots owned by the caller, including draft values in JSON maps.
func (d Definition) Clone() Definition {
	out := Definition{Version: d.Version, Name: d.Name, Nodes: make([]Node, len(d.Nodes)), Links: append([]Link{}, d.Links...)}
	for i, n := range d.Nodes {
		out.Nodes[i] = n
		out.Nodes[i].Config = make(map[string]any, len(n.Config))
		for k, v := range n.Config {
			switch values := v.(type) {
			case []string:
				v = slices.Clone(values)
			case []any:
				v = slices.Clone(values)
			}
			out.Nodes[i].Config[k] = v
		}
		out.Nodes[i].Media = make(map[string]string, len(n.Media))
		for k, v := range n.Media {
			out.Nodes[i].Media[k] = v
		}
	}
	return out
}

func (d Definition) normalized(catalog map[string]Recipe) Definition {
	out := d.Clone()
	switches := make(map[string]map[string]bool)
	for i := range out.Nodes {
		n := &out.Nodes[i]
		if choices, valid := softwareChoices(n.Config["software"]); valid {
			if len(choices) == 0 {
				delete(n.Config, "software")
			} else {
				n.Config["software"] = choices
			}
		}
		if n.Recipe == "switch" {
			switches[n.ID] = make(map[string]bool)
		} else if _, current := catalog[n.Recipe]; !current {
			for _, recipe := range catalog {
				if recipe.LegacyController != "" && recipe.LegacyController == n.Recipe {
					n.Recipe = recipe.ID
					n.Config["role"] = "domain-controller"
					break
				}
			}
		}
	}
	for _, link := range out.Links {
		for _, end := range [2]End{link.A, link.B} {
			if used := switches[end.Node]; used != nil && end.Port != "lan" {
				used[end.Port] = true
			}
		}
	}
	for i := range out.Links {
		link := &out.Links[i]
		for _, end := range [2]*End{&link.A, &link.B} {
			if used := switches[end.Node]; used != nil && end.Port == "lan" {
				for number := 1; number <= switchPortLimit; number++ {
					port := switchPortID(number)
					if !used[port] {
						end.Port = port
						used[port] = true
						break
					}
				}
			}
		}
	}
	return out
}

const switchPortLimit = 63

func switchPortID(number int) string { return "port" + strconv.Itoa(number) }

func isController(n Node, r Recipe) bool {
	return r.ProvidesDomain && n.String(r, "role") == "domain-controller"
}

func isSwitch(r Recipe) bool { return r.Function == "switch" }
func isRouter(r Recipe) bool { return r.Function == "router" }

func (d Definition) Network(id string) string {
	return d.networkEnd(id).Node
}

func (d Definition) networkEnd(id string) End {
	for _, l := range d.Links {
		if l.A.Node == id {
			return l.B
		}
		if l.B.Node == id {
			return l.A
		}
	}
	return End{}
}

func validValue(field Field, value any) bool {
	switch field.Kind {
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		v, ok := value.(float64)
		if !ok {
			n, integer := value.(int)
			v, ok = float64(n), integer
		}
		return ok && math.Trunc(v) == v && v >= float64(field.Min) && v <= float64(field.Max)
	case "select":
		for _, o := range field.Options {
			if equalValue(o.Value, value) {
				return true
			}
		}
	case "packages":
		selected, valid := softwareChoices(value)
		return valid && len(selected) <= len(field.Options) && !slices.ContainsFunc(selected, func(id string) bool {
			return !slices.ContainsFunc(field.Options, func(o Option) bool { return o.Value == id })
		})
	case "string":
		s, ok := value.(string)
		return ok && len(s) <= 128
	}
	return false
}

func softwareChoices(value any) ([]string, bool) {
	selected := []string{}
	switch v := value.(type) {
	case string: // Version 1 definitions originally stored one package.
		if v != "" {
			selected = append(selected, v)
		}
	case []string:
		selected = append(selected, v...)
	case []any:
		for _, choice := range v {
			id, ok := choice.(string)
			if !ok {
				return nil, false
			}
			selected = append(selected, id)
		}
	default:
		return nil, false
	}
	slices.Sort(selected)
	return slices.Compact(selected), true
}

func (m Media) Active(n Node, r Recipe) bool {
	if m.When == "software" {
		choices, _ := softwareChoices(n.Value(r, m.When))
		return slices.Contains(choices, m.Equals)
	}
	return m.When == "" || n.String(r, m.When) == m.Equals
}

func (m Media) Reference(n Node) string {
	if ref := n.Media[m.Key]; ref != "" {
		return ref
	}
	return m.Default
}

// Validate returns graph and recipe errors, plus missing media when check is
// supplied. The editor may save an incomplete draft.
func Validate(d Definition, catalog map[string]Recipe, check MediaCheck) []Issue {
	issues := []Issue{}
	add := func(node, field, message string) { issues = append(issues, Issue{node, field, message}) }
	if d.Version != 1 {
		add("", "version", "Use a version 1 lab definition.")
	}
	if strings.TrimSpace(d.Name) == "" || len(d.Name) > 100 {
		add("", "name", "Enter a lab name of up to 100 characters.")
	}
	if len(d.Nodes) > 64 || len(d.Links) > 128 {
		add("", "", "A lab can contain up to 64 nodes and 128 links.")
	}
	nodes := make(map[string]Node)
	for _, n := range d.Nodes {
		if _, ok := nodes[n.ID]; ok || !nodeID.MatchString(n.ID) {
			add(n.ID, "", "Each node needs a unique ID containing letters, digits, underscores, or hyphens.")
		}
		nodes[n.ID] = n
		if strings.TrimSpace(n.Name) == "" || len(n.Name) > 80 {
			add(n.ID, "name", "Enter a node name of up to 80 characters.")
		}
		if math.Abs(n.X) > 100_000 || math.Abs(n.Y) > 100_000 {
			add(n.ID, "", "The node is outside the supported canvas.")
		}
		r, ok := catalog[n.Recipe]
		if !ok {
			add(n.ID, "recipe", "Unknown node recipe "+n.Recipe+".")
			continue
		}
		if r.Blocked != "" && check != nil {
			add(n.ID, "recipe", r.Blocked)
		}
		for key, value := range n.Config {
			found := slices.IndexFunc(r.Fields, func(f Field) bool { return f.Key == key })
			if found < 0 || !validValue(r.Fields[found], value) {
				add(n.ID, key, "This recipe does not accept the selected value.")
			}
		}
		if value := n.String(r, "computerName"); value != "" && !computerName.MatchString(value) {
			add(n.ID, "computerName", "Use 1–15 letters, digits, or hyphens for the computer name.")
		}
		if value := n.String(r, "address"); value != "" {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !prefix.Addr().Is4() {
				add(n.ID, "address", "Enter a valid IPv4 address and prefix, such as 10.20.0.40/24.")
			}
		}
		for _, slot := range r.Media {
			if check != nil && slot.Active(n, r) {
				if ref := slot.Reference(n); ref == "" {
					add(n.ID, slot.Key, "Choose "+slot.Label+".")
				} else if err := check(r, slot, ref); err != nil {
					add(n.ID, slot.Key, err.Error())
				}
			}
		}
		for key := range n.Media {
			if !slices.ContainsFunc(r.Media, func(m Media) bool { return m.Key == key }) {
				add(n.ID, key, "Unknown media slot.")
			}
		}
	}

	connections := make(map[string]string)
	switchPorts := make(map[End]bool)
	for _, l := range d.Links {
		a, aOK := nodes[l.A.Node]
		b, bOK := nodes[l.B.Node]
		if !aOK || !bOK || a.ID == b.ID {
			add("", "links", "Connect ports on two different existing nodes.")
			continue
		}
		ra, rb := catalog[a.Recipe], catalog[b.Recipe]
		if !slices.ContainsFunc(ra.Ports, func(p Port) bool { return p.ID == l.A.Port }) ||
			!slices.ContainsFunc(rb.Ports, func(p Port) bool { return p.ID == l.B.Port }) {
			add("", "links", "A link refers to an unavailable Ethernet port.")
			continue
		}
		if isSwitch(ra) == isSwitch(rb) {
			add("", "links", "Connect an Ethernet port to an isolated switch.")
			continue
		}
		switchEnd := l.B
		if isSwitch(ra) {
			a, b = b, a
			switchEnd = l.A
		}
		if switchPorts[switchEnd] {
			add(b.ID, "links", "Each switch port accepts one cable.")
		}
		switchPorts[switchEnd] = true
		if connections[a.ID] != "" {
			add(a.ID, "links", "This node has one Ethernet adapter.")
		}
		connections[a.ID] = b.ID
	}
	controllers := make(map[string]string)
	dhcpServers := make(map[string]bool)
	for _, n := range d.Nodes {
		r := catalog[n.Recipe]
		if isRouter(r) {
			segment := connections[n.ID]
			if segment == "" {
				add(n.ID, "links", "Connect the router’s LAN port to an isolated switch.")
			}
			cfg, field, err := routerSettings(n, r)
			if err != nil {
				add(n.ID, field, err.Error())
			} else if cfg.enabled && segment != "" {
				if dhcpServers[segment] {
					add(n.ID, "dhcp", "Use one DHCP server per isolated switch.")
				}
				dhcpServers[segment] = true
			}
		}
		if isController(n, r) {
			segment := connections[n.ID]
			if segment == "" && check != nil {
				add(n.ID, "links", "Connect this controller to an isolated Ethernet switch.")
			}
			if segment != "" {
				if controllers[segment] != "" {
					add(n.ID, "links", "Use one domain controller per isolated switch.")
				}
				controllers[segment] = n.ID
			}
		}
		id := n.String(r, "domain")
		if id == "" {
			continue
		}
		controller, ok := nodes[id]
		compatible := isController(controller, catalog[controller.Recipe]) && controller.Recipe == r.DomainController
		if r.FixedComputerName && n.String(r, "computerName") != "" {
			add(n.ID, "computerName", "Leave the computer name empty to use the controller’s preprovisioned account.")
		}
		if !ok || id == n.ID || !compatible {
			add(n.ID, "domain", "Select a compatible domain controller from this lab.")
			continue
		}
		if connections[n.ID] == "" || connections[n.ID] != connections[id] {
			add(n.ID, "links", "Connect the domain controller and its member to the same isolated switch.")
		}
	}
	return issues
}

func equalValue(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Diff compares the proposed lab with the nodes that actually own resources.
func Diff(d Definition, actual Definition, recipes map[string]Recipe, check MediaCheck) Plan {
	p := Plan{Changes: []Change{}, Issues: Validate(d, recipes, check)}
	for _, old := range actual.Nodes {
		if _, exists := d.Node(old.ID); !exists {
			p.Changes = append(p.Changes, Change{old.ID, "stop", "Remove " + old.Name + " from the running lab."})
		}
	}
	for _, n := range d.Nodes {
		r := recipes[n.Recipe]
		old, exists := actual.Node(n.ID)
		switch {
		case !exists:
			detail := "Start " + n.Name + "."
			if n.String(r, "domain") != "" {
				detail = "Provision this workstation and attach it to the running domain."
			}
			p.Changes = append(p.Changes, Change{n.ID, "start", detail})
		case old.Recipe != n.Recipe:
			p.Changes = append(p.Changes, Change{n.ID, "rebuild", "Change system recipe. Replace the guest’s temporary disk."})
		default:
			if old.Name != n.Name || old.X != n.X || old.Y != n.Y {
				p.Changes = append(p.Changes, Change{n.ID, "layout", "Update the editor layout and label."})
			}
			for _, m := range r.Media {
				if (m.Active(n, r) || m.Active(old, r)) && m.Reference(old) != m.Reference(n) {
					p.Changes = append(p.Changes, Change{n.ID, "rebuild", "Change " + m.Label + ". Replace the guest’s temporary disk."})
				}
			}
			for _, f := range r.Fields {
				if !equalValue(old.Value(r, f.Key), n.Value(r, f.Key)) {
					p.Changes = append(p.Changes, Change{n.ID, f.Impact, fmt.Sprintf("Change %s.", f.Label)})
				}
			}
			if !isSwitch(r) {
				before, after := actual.networkEnd(n.ID), d.networkEnd(n.ID)
				switch {
				case before.Node != after.Node:
					detail := "Move the guest’s Ethernet adapter. Replace the guest’s temporary disk."
					if isRouter(r) {
						detail = "Move the router to a different switch."
					}
					p.Changes = append(p.Changes, Change{n.ID, "rebuild", detail})
				case before.Port != after.Port:
					p.Changes = append(p.Changes, Change{n.ID, "layout", "Move the cable to a different port on the same isolated switch."})
				}
			}
		}
	}
	for _, n := range d.Nodes {
		r := recipes[n.Recipe]
		controller := n.String(r, "domain")
		if controller == "" {
			continue
		}
		if _, exists := actual.Node(n.ID); exists && slices.ContainsFunc(p.Changes, func(c Change) bool {
			return c.Node == controller && (c.Action == "rebuild" || c.Action == "start")
		}) {
			p.Changes = append(p.Changes, Change{n.ID, "rebuild", "Re-establish machine trust after the controller is rebuilt."})
		}
	}
	return p
}
