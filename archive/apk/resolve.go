package apk

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

type Package struct {
	Repository string
	Record
}

func (p Package) ID() string { return p.Repository + "/" + p.Name + "=" + p.Version }

type requirement struct {
	owner, name, operator, version string
	conflict                       bool
}

func parseRequirement(owner, text string) (requirement, error) {
	req := requirement{owner: owner}
	text, req.conflict = strings.CutPrefix(text, "!")
	i := strings.IndexAny(text, "=<>~")
	if i < 0 {
		i = len(text)
	}
	req.name = text[:i]
	for j := i; j < len(text) && strings.ContainsRune("=<>~", rune(text[j])); j++ {
		req.operator += text[j : j+1]
	}
	req.version = text[i+len(req.operator):]
	if req.name == "" || strings.ContainsAny(req.name, " !\t\r\n") {
		return req, fmt.Errorf("apk: malformed dependency %q for %s", text, owner)
	}
	if req.operator != "" {
		_, valid := versionParts(req.version)
		if !valid || !slices.Contains([]string{"=", "<", ">", "<=", ">=", "~", "=~", "~=", "<~", ">~"}, req.operator) {
			return req, fmt.Errorf("apk: unsupported dependency %q for %s", text, owner)
		}
	}
	return req, nil
}

func (r requirement) matches(version string) bool {
	if r.operator == "" {
		return true
	}
	if version == "" {
		return false
	}
	fuzzy := strings.Contains(r.operator, "~")
	switch compareVersions(version, r.version, fuzzy) {
	case -1:
		return strings.Contains(r.operator, "<")
	case 0:
		return strings.Contains(r.operator, "=") || fuzzy
	default:
		return strings.Contains(r.operator, ">")
	}
}

type provider struct {
	pkg     *Package
	version string
}

func (p Package) provides() map[string]string {
	names := map[string]string{p.Name: p.Version}
	for _, alias := range p.Provides {
		name, version, _ := strings.Cut(alias, "=")
		names[name] = version
	}
	return names
}

// Resolve selects the dependency closure for the exact selected packages.
// Base packages and named external capabilities are already provided.
func Resolve(available, base []Package, selected, external []string) ([]Package, error) {
	byID := make(map[string]*Package, len(available))
	providers := make(map[string][]provider)
	for i := range available {
		pkg := &available[i]
		byID[pkg.ID()] = pkg
		for name, version := range pkg.provides() {
			providers[name] = append(providers[name], provider{pkg, version})
		}
	}
	s := solver{providers: providers, names: make(map[string]*Package), externals: external, budget: 4096}
	var queue []requirement
	install := func(p *Package) error {
		if existing := s.names[p.Name]; existing != nil {
			if existing.ID() != p.ID() && (existing.Version != p.Version || existing.Repository != "") {
				return fmt.Errorf("apk: conflicting selections for %s", p.Name)
			}
			return nil
		}
		s.names[p.Name] = p
		var err error
		queue, err = addRequirements(queue, p)
		return err
	}
	for i := range base {
		if err := install(&base[i]); err != nil {
			return nil, err
		}
	}
	for _, id := range selected {
		pkg := byID[id]
		if pkg == nil {
			return nil, fmt.Errorf("apk: %s is no longer in the repository index", id)
		}
		if err := install(pkg); err != nil {
			return nil, err
		}
	}
	if err := s.solve(queue, nil); err != nil {
		return nil, err
	}
	var out []Package
	for _, pkg := range s.names {
		if pkg.Repository != "" {
			out = append(out, *pkg)
		}
	}
	slices.SortFunc(out, func(a, b Package) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

type solver struct {
	providers map[string][]provider
	names     map[string]*Package
	externals []string
	budget    int
}

func addRequirements(queue []requirement, p *Package) ([]requirement, error) {
	for _, text := range p.Dependencies {
		req, err := parseRequirement(p.Name, text)
		if err != nil {
			return nil, err
		}
		queue = append(queue, req)
	}
	return queue, nil
}

func (s *solver) satisfied(r requirement) bool {
	if r.operator == "" && slices.Contains(s.externals, r.name) {
		return true
	}
	for name, p := range s.names {
		if r.conflict && name == r.owner {
			continue
		}
		if version, ok := p.provides()[r.name]; ok && r.matches(version) {
			return true
		}
	}
	return false
}

func (s *solver) solve(queue, conflicts []requirement) error {
	for len(queue) != 0 {
		r := queue[0]
		queue = queue[1:]
		if r.conflict {
			if s.satisfied(r) {
				return fmt.Errorf("apk: %s conflicts with %s%s%s", r.owner, r.name, r.operator, r.version)
			}
			conflicts = append(conflicts, r)
			continue
		}
		if s.satisfied(r) {
			continue
		}
		missing := fmt.Errorf("apk: %s requires %s%s%s", r.owner, r.name, r.operator, r.version)
		var candidates []provider
		for _, p := range s.providers[r.name] {
			if s.names[p.pkg.Name] == nil && r.matches(p.version) {
				candidates = append(candidates, p)
			}
		}
		slices.SortFunc(candidates, func(a, b provider) int {
			isAlias := func(p provider) int {
				if p.pkg.Name == r.name {
					return 0
				}
				return 1
			}
			return cmp.Or(cmp.Compare(isAlias(a), isAlias(b)), cmp.Compare(b.pkg.ProviderPriority, a.pkg.ProviderPriority),
				compareVersions(b.version, a.version, false), strings.Compare(a.pkg.ID(), b.pkg.ID()))
		})
		var lastErr error
		for _, p := range candidates {
			s.budget--
			if s.budget < 0 {
				return fmt.Errorf("apk: package resolution exceeded its search limit")
			}
			s.names[p.pkg.Name] = p.pkg
			var err error
			if slices.ContainsFunc(conflicts, s.satisfied) {
				err = missing
			} else {
				var next []requirement
				next, err = addRequirements(queue[:len(queue):len(queue)], p.pkg)
				if err == nil {
					err = s.solve(next, conflicts[:len(conflicts):len(conflicts)])
				}
			}
			if err == nil {
				return nil
			}
			delete(s.names, p.pkg.Name)
			lastErr = err
		}
		if lastErr != nil && lastErr != missing {
			return fmt.Errorf("%w: %w", missing, lastErr)
		}
		return missing
	}
	return nil
}
