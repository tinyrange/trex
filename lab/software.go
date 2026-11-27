package lab

import "sort"

type SoftwareTitle struct {
	ID      string           `json:"id"`
	Title   string           `json:"title"`
	Targets []SoftwareTarget `json:"targets"`
}

type SoftwareTarget struct {
	OS           string `json:"os"`
	Availability string `json:"availability"`
	Via          string `json:"via,omitempty"`
	Recipe       string `json:"recipe,omitempty"`
	Package      string `json:"package,omitempty"`
}

// SoftwareAlias is a title installed as part of a selectable package.
type SoftwareAlias struct {
	ID, Title, Package string
}

// SoftwareLibrary combines preinstallation options with standalone application
// smoke recipes. The options take precedence for their OS.
func SoftwareLibrary(recipes []Recipe, aliases []SoftwareAlias, references []SoftwareTitle) []SoftwareTitle {
	byID := make(map[string]SoftwareTitle)
	add := func(id, title string, target SoftwareTarget) {
		entry, found := byID[id]
		if !found {
			entry = SoftwareTitle{ID: id, Title: title}
		}
		for _, existing := range entry.Targets {
			if existing.OS == target.OS {
				return
			}
		}
		entry.Targets = append(entry.Targets, target)
		byID[id] = entry
	}
	for _, r := range recipes {
		for _, f := range r.Fields {
			if f.Key != "software" {
				continue
			}
			for _, o := range f.Options {
				id, _ := o.Value.(string)
				if id == "" {
					continue
				}
				target := SoftwareTarget{OS: r.Title, Availability: "lab", Recipe: r.ID, Package: id}
				add(id, o.Label, target)
				for _, alias := range aliases {
					if alias.Package == id {
						target.Via = o.Label
						add(alias.ID, alias.Title, target)
					}
				}
			}
		}
	}

	for _, entry := range references {
		for _, target := range entry.Targets {
			add(entry.ID, entry.Title, target)
		}
	}

	out := make([]SoftwareTitle, 0, len(byID))
	for _, entry := range byID {
		sort.Slice(entry.Targets, func(i, j int) bool { return entry.Targets[i].OS < entry.Targets[j].OS })
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}
