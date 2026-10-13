package irix

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Planning never interprets shell commands or silently chooses a machine.
// Missing dependencies, ambiguous versions, unsupported policy and absent
// payloads are explicit issues; a successful metadata parse is not readiness.
type Selection struct {
	Name, Image, IndexKey string
	Version               uint32
	Descriptor            int
	Order                 uint16
	Subsystem             Subsystem
	OpaquePolicy          bool
}
type PlanIssue struct {
	Kind, Subject, Detail string
	Alternatives          [][]Mark
}
type Operation struct {
	Kind, Path, Target, Owner, Group, Image, Source string
	Mode                                            uint32
	Major, Minor                                    int64
	Data                                            starfile.File
	Ordinal                                         int
	Attributes                                      []string
}
type Hook struct{ Phase, Path, Command string }
type InstallPlan struct {
	Selected   []Selection
	Removed    []string
	Operations []Operation
	Hooks      []Hook
	Issues     []PlanIssue
}
type PlanOptions struct {
	Selected            []string
	Machine             map[string]string
	Installed, Versions map[string]uint32
	Indexes             map[string][]Item
	Images, Existing    map[string]starfile.File
	Previous            map[string]uint16
}

func qualified(p, i, s string) string { return p + "." + i + "." + s }
func imageKey(name string, version uint32) string {
	return name + "@" + strconv.FormatUint(uint64(version), 10)
}
func markMatches(m Mark, name string, version uint32) bool {
	parts := strings.SplitN(name, ".", 3)
	if len(parts) != 3 || int64(version) < m.Low || int64(version) > m.High {
		return false
	}
	for i, pattern := range []string{m.Product, m.Image, m.Subsystem} {
		match, err := path.Match(pattern, parts[i])
		if err != nil || !match {
			return false
		}
	}
	return true
}
func attributeBody(a, name string) (string, bool) {
	if strings.HasPrefix(a, name+"(") && strings.HasSuffix(a, ")") {
		return a[len(name)+1 : len(a)-1], true
	}
	return "", false
}

// Distinct machine keys are conjunctive; alternatives for one key are
// disjunctive. Bare historical machine names are an explicit MACHINE choice.
func machineMatches(attributes []string, facts map[string]string) (bool, error) {
	for _, a := range attributes {
		body, ok := attributeBody(a, "mach")
		if !ok {
			continue
		}
		tokens, err := words(body)
		if err != nil {
			return false, err
		}
		if len(tokens) == 0 {
			return false, fmt.Errorf("empty machine predicate")
		}
		groups := map[string][]string{}
		for _, token := range tokens {
			key, value, ok := strings.Cut(token, "=")
			if !ok {
				key, value = "MACHINE", token
			}
			if key == "" {
				return false, fmt.Errorf("empty machine key")
			}
			groups[key] = append(groups[key], value)
		}
		// Require every referenced fact, even if an earlier known key differs.
		keys := []string{}
		for key := range groups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		match := true
		for _, key := range keys {
			actual, known := facts[key]
			if !known {
				return false, fmt.Errorf("missing machine fact %s", key)
			}
			one := false
			for _, value := range groups[key] {
				if actual == value {
					one = true
				}
			}
			match = match && one
		}
		if !match {
			return false, nil
		}
	}
	return true, nil
}
func checksum(file starfile.File) (uint16, error) {
	var sum uint16
	var b [65536]byte
	for off := int64(0); off < file.Size(); {
		n := min(int64(len(b)), file.Size()-off)
		if _, err := starfile.ReadFullAt(file, b[:n], off); err != nil {
			return 0, err
		}
		for _, v := range b[:n] {
			sum = (sum >> 1) | (sum << 15)
			sum += uint16(v)
		}
		off += n
	}
	return sum, nil
}
func safePath(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("NUL in destination")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("parent traversal in destination")
		}
	}
	return path.Clean("/" + name), nil
}
func metadataKey(item Item) string {
	return item.Path + "\x00" + item.Source + "\x00" + strings.Join(item.Attributes, "\x00")
}

func Plan(products []Product, options PlanOptions) (*InstallPlan, error) {
	plan := &InstallPlan{}
	catalog := map[string][]Selection{}
	for d, p := range products {
		for _, im := range p.Images {
			for _, ss := range im.Subsystems {
				key := qualified(p.Name, im.Name, ss.Name)
				catalog[key] = append(catalog[key], Selection{key, p.Name + "." + im.Name, imageKey(p.Name, im.Version), im.Version, d, im.Order, ss, len(p.Extensions) > 0 || len(im.Extensions) > 0})
			}
		}
	}
	selected := map[string]Selection{}
	choose := func(name string) (Selection, error) {
		candidates := catalog[name]
		var best Selection
		found := false
		ambiguous := false
		for _, candidate := range candidates {
			if version, ok := options.Versions[name]; ok && candidate.Version != version {
				continue
			}
			if !found || candidate.Version > best.Version {
				best = candidate
				found = true
				ambiguous = false
			} else if candidate.Version == best.Version {
				ambiguous = true
			}
		}
		if ambiguous {
			return best, fmt.Errorf("ambiguous descriptors for %s version %d", name, best.Version)
		}
		if !found {
			return best, fmt.Errorf("no matching version for %s", name)
		}
		return best, nil
	}
	names := []string{}
	for name := range catalog {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, pattern := range options.Selected {
		found := false
		for _, name := range names {
			matches, err := path.Match(pattern, name)
			if err != nil {
				return nil, err
			}
			if !matches {
				continue
			}
			found = true
			s, err := choose(name)
			if err != nil {
				return nil, err
			}
			selected[name] = s
		}
		if !found {
			return nil, fmt.Errorf("no subsystem matches %q", pattern)
		}
	}
	if len(options.Selected) == 0 {
		for _, name := range names {
			s, err := choose(name)
			if err != nil {
				return nil, err
			}
			if s.Subsystem.Flags&2 != 0 {
				selected[name] = s
			}
		}
	}
	available := map[string]uint32{}
	for k, v := range options.Installed {
		available[k] = v
	}
	for k, v := range selected {
		available[k] = v.Version
	}
	for name, s := range selected {
		for _, m := range s.Subsystem.Replacements {
			for old, version := range options.Installed {
				if old != name && markMatches(m, old, version) {
					if _, keep := selected[old]; !keep {
						delete(available, old)
						plan.Removed = append(plan.Removed, old)
					}
				}
			}
		}
	}
	// Dependencies are alternative prerequisite groups; all marks in one
	// group must be satisfied. Preserve unresolved alternatives for the caller
	// rather than choosing a different installation policy implicitly.
	for _, name := range names {
		s, ok := selected[name]
		if !ok {
			continue
		}
		plan.Selected = append(plan.Selected, s)
		req := s.Subsystem.Prerequisites
		satisfied := len(req) == 0
		for _, group := range req {
			all := len(group) > 0
			for _, mark := range group {
				one := false
				for installed, version := range available {
					if markMatches(mark, installed, version) {
						one = true
						break
					}
				}
				all = all && one
			}
			satisfied = satisfied || all
		}
		if !satisfied {
			plan.Issues = append(plan.Issues, PlanIssue{Kind: "prerequisite", Subject: name, Detail: "no complete prerequisite alternative is satisfied", Alternatives: req})
		}
		if s.OpaquePolicy || len(s.Subsystem.Extensions) > 0 || len(s.Subsystem.Additional) > 0 || len(s.Subsystem.Final) > 0 {
			plan.Issues = append(plan.Issues, PlanIssue{Kind: "descriptor_extension", Subject: name, Detail: "additional mark policy requires explicit interpretation", Alternatives: [][]Mark{s.Subsystem.Extensions, s.Subsystem.Additional, s.Subsystem.Final}})
		}
	}
	sort.SliceStable(plan.Selected, func(i, j int) bool {
		a, b := plan.Selected[i], plan.Selected[j]
		if a.Order != b.Order {
			return a.Order < b.Order
		}
		return a.Name < b.Name
	})
	sort.Strings(plan.Removed)
	activeImages := map[string]Selection{}
	for _, s := range plan.Selected {
		key := imageKey(s.Image, s.Version)
		activeImages[key] = s
	}
	imageNames := []string{}
	for key := range activeImages {
		imageNames = append(imageNames, key)
	}
	sort.Strings(imageNames)
	seenDest := map[string]Item{}
	for _, key := range imageNames {
		s := activeImages[key]
		items, ok := options.Indexes[s.IndexKey]
		if !ok {
			items, ok = options.Indexes[strings.SplitN(s.Image, ".", 2)[0]]
		}
		if !ok {
			plan.Issues = append(plan.Issues, PlanIssue{Kind: "missing_idb", Subject: key, Detail: "supply index keyed by product@version"})
			continue
		}
		payload, hasPayload := options.Images[key]
		if !hasPayload {
			payload, hasPayload = options.Images[s.Image]
		}
		decoded := map[string][]*Entry{}
		if hasPayload {
			entries, err := OpenImage(payload, items, s.Image)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				item := Item{Path: entry.Path, Source: entry.Source, Attributes: entry.Attributes}
				mk := metadataKey(item)
				decoded[mk] = append(decoded[mk], entry)
			}
		}
		for ordinal, item := range items {
			wanted := false
			for _, a := range item.Attributes {
				if candidate, ok := selected[a]; ok && candidate.Version == s.Version && candidate.Image == s.Image {
					wanted = true
					break
				}
			}
			if !wanted {
				continue
			}
			match, err := machineMatches(item.Attributes, options.Machine)
			if err != nil {
				plan.Issues = append(plan.Issues, PlanIssue{Kind: "machine", Subject: item.Path, Detail: err.Error()})
				continue
			}
			if !match {
				continue
			}
			dest, err := safePath(item.Path)
			if err != nil {
				return nil, err
			}
			if dest == "/" && item.Kind != "d" {
				return nil, fmt.Errorf("irix plan: root destination must be a directory")
			}
			if previous, exists := seenDest[dest]; exists && !(item.Kind == "d" && previous.Kind == "d" && item.Mode == previous.Mode && item.Owner == previous.Owner && item.Group == previous.Group) {
				plan.Issues = append(plan.Issues, PlanIssue{Kind: "destination_conflict", Subject: dest, Detail: "multiple selected file occurrences"})
				continue
			}
			seenDest[dest] = item
			op := Operation{Path: dest, Owner: item.Owner, Group: item.Group, Mode: item.Mode, Major: -1, Minor: -1, Image: key, Source: item.Source, Ordinal: ordinal, Attributes: item.Attributes}
			var linkOps []Operation
			switch item.Kind {
			case "f":
				op.Kind = "file"
			case "d":
				op.Kind = "directory"
			case "l":
				op.Kind = "symlink"
			case "b":
				op.Kind = "block_device"
			case "c":
				op.Kind = "character_device"
			case "p":
				op.Kind = "fifo"
			default:
				op.Kind = "unsupported"
				plan.Issues = append(plan.Issues, PlanIssue{Kind: "entry_type", Subject: dest, Detail: item.Kind})
			}
			if item.Kind == "f" {
				members := decoded[metadataKey(item)]
				if len(members) == 1 {
					op.Data = members[0]
				} else {
					plan.Issues = append(plan.Issues, PlanIssue{Kind: "missing_payload", Subject: dest, Detail: "exact indexed file occurrence is unavailable or ambiguous"})
				}
			}
			raw := item.RawAttributes
			if len(raw) == 0 {
				raw = item.Attributes
			}
			for _, a := range raw {
				for _, phase := range []string{"preop", "postop", "exitop"} {
					if command, ok := attributeBody(a, phase); ok {
						plan.Hooks = append(plan.Hooks, Hook{phase, dest, command})
						plan.Issues = append(plan.Issues, PlanIssue{Kind: "install_action", Subject: dest, Detail: phase + " requires an explicit execution capability"})
					}
				}
			}
			for _, a := range item.Attributes {
				keyword := strings.SplitN(a, "(", 2)[0]
				if _, known := catalog[a]; !known && !(strings.Count(a, ".") >= 2 && !strings.ContainsAny(a, "()")) {
					switch keyword {
					case "sum", "size", "off", "cmpsize", "f", "mach", "config", "symval", "links", "maj", "min", "preop", "postop", "exitop", "noshare", "nohist", "nostrip", "strip":
					default:
						plan.Issues = append(plan.Issues, PlanIssue{Kind: "unsupported_attribute", Subject: dest, Detail: a})
					}
				}
				if a == "config" {
					a = "config(update)"
				}
				if policy, ok := attributeBody(a, "config"); ok && policy == "" {
					a = "config(update)"
				}
				for _, device := range []string{"maj", "min"} {
					if value, ok := attributeBody(a, device); ok {
						n, err := strconv.ParseUint(value, 10, 32)
						if err != nil {
							return nil, fmt.Errorf("irix plan: invalid device %s", device)
						}
						if device == "maj" {
							op.Major = int64(n)
						} else {
							op.Minor = int64(n)
						}
					}
				}
				if target, ok := attributeBody(a, "symval"); ok {
					op.Target = target
				}
				if policy, ok := attributeBody(a, "config"); ok {
					current, exists := options.Existing[dest]
					if !exists {
						continue
					}
					if policy == "noupdate" {
						op.Kind = "preserve"
						op.Data = current
						continue
					}
					if policy != "suggest" && policy != "update" {
						plan.Issues = append(plan.Issues, PlanIssue{Kind: "configuration_policy", Subject: dest, Detail: policy})
						continue
					}
					if op.Data == nil {
						continue
					}
					currentSum, err := checksum(current)
					if err != nil {
						return nil, err
					}
					newSum, err := checksum(op.Data)
					if err != nil {
						return nil, err
					}
					if currentSum == newSum && current.Size() == op.Data.Size() {
						op.Kind = "preserve"
						op.Data = current
						continue
					}
					original, known := options.Previous[dest]
					if !known {
						plan.Issues = append(plan.Issues, PlanIssue{Kind: "configuration_history", Subject: dest, Detail: "previous installed checksum is required"})
						continue
					}
					if currentSum != original {
						if policy == "suggest" {
							op.Path = dest + ".N"
						} else {
							plan.Operations = append(plan.Operations, Operation{Kind: "file", Path: dest + ".O", Data: current, Image: key})
						}
					}
				}
				if links, ok := attributeBody(a, "links"); ok {
					targets, err := words(links)
					if err != nil {
						return nil, err
					}
					for _, target := range targets {
						p, err := safePath(target)
						if err != nil {
							return nil, err
						}
						linkOps = append(linkOps, Operation{Kind: "hardlink", Path: p, Target: dest, Image: key})
					}
				}
			}
			if op.Kind == "symlink" && op.Target == "" {
				plan.Issues = append(plan.Issues, PlanIssue{Kind: "missing_link_target", Subject: dest})
			}
			if (op.Kind == "block_device" || op.Kind == "character_device") && (op.Major < 0 || op.Minor < 0) {
				plan.Issues = append(plan.Issues, PlanIssue{Kind: "missing_device_identity", Subject: dest})
			}
			plan.Operations = append(plan.Operations, op)
			for _, link := range linkOps {
				link.Target = op.Path
				plan.Operations = append(plan.Operations, link)
			}
		}
	}
	// Configuration suffixes and hard links also participate in collision checks.
	unique := []Operation{}
	destinations := map[string]Operation{}
	for _, op := range plan.Operations {
		if old, exists := destinations[op.Path]; exists {
			if old.Kind == "directory" && op.Kind == "directory" && old.Mode == op.Mode && old.Owner == op.Owner && old.Group == op.Group {
				continue
			}
			plan.Issues = append(plan.Issues, PlanIssue{Kind: "destination_conflict", Subject: op.Path, Detail: "configuration backup or link destination collision"})
			continue
		}
		destinations[op.Path] = op
		unique = append(unique, op)
	}
	plan.Operations = unique
	removed := []string{}
	for _, name := range plan.Removed {
		if len(removed) == 0 || removed[len(removed)-1] != name {
			removed = append(removed, name)
		}
	}
	plan.Removed = removed
	return plan, nil
}
