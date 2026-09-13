package ibmisave

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
)

func init() {
	auto.RegisterPlan("ibmi_libraries", func(listing []auto.Entry, source auto.View, o auto.Options) ([]*auto.Plan, error) {
		var libraries auto.View
		languageID := false
		for _, e := range listing {
			if e.Name == "QUSRLIBS" && e.Kind == "directory" {
				libraries = e.View
			}
			if e.Name == "QLANGID" && e.Kind == "directory" {
				languageID = true
			}
		}
		if libraries == nil || !languageID {
			return nil, nil
		}
		return []*auto.Plan{{ID: "ibmi-libraries", Title: "Combine IBM i libraries", Description: "Browse saved library objects by library, release and language, combining save groups and preserving source identity. Does not include QSYS product streams.", Build: func() (auto.View, error) { return libraryPlan(libraries, o) }}}, nil
	})
}

// Directory names encode release, level and language. Keep these variants
// separate: similarly named objects are not interchangeable localized bytes.
func libraryVariant(name string) (string, error) {
	if len(name) != 8 || name[0] != 'Q' {
		return "", fmt.Errorf("ibmi libraries: unsupported variant %q", name)
	}
	for _, c := range name[1:] {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("ibmi libraries: unsupported variant %q", name)
		}
	}
	return fmt.Sprintf("V%cR%cM%c/level%s/language29%s", name[1], name[2], name[3], name[4:6], name[6:]), nil
}

func libraryPlan(source auto.View, o auto.Options) (auto.View, error) {
	variants, err := source.Entries()
	if err != nil {
		return nil, err
	}
	budget := o.MaxEntries - len(variants)
	if budget < 0 {
		return nil, auto.ErrLimit
	}
	var entries []auto.Entry
	for _, variant := range variants {
		if variant.Kind != "directory" || variant.View == nil {
			return nil, fmt.Errorf("ibmi libraries: expected variant directory %q", variant.Name)
		}
		label, err := libraryVariant(variant.Name)
		if err != nil {
			return nil, err
		}
		files, err := variant.View.Entries()
		if err != nil {
			return nil, err
		}
		budget -= len(files)
		if budget < 0 {
			return nil, auto.ErrLimit
		}
		for _, file := range files {
			if file.Kind != "file" || file.Reader == nil {
				return nil, fmt.Errorf("ibmi libraries: expected library stream %q", file.Name)
			}
			if file.Name == "" || file.Name == "." || file.Name == ".." || strings.ContainsAny(file.Name, "/\\\x00") {
				return nil, fmt.Errorf("ibmi libraries: invalid library name")
			}
			sourcePath := "QUSRLIBS/" + variant.Name + "/" + file.Name
			entries = append(entries, auto.Entry{Name: file.Name + "/" + label, Kind: "directory", View: &libraryObjects{source: file, sourcePath: sourcePath, options: o}, Attributes: map[string]any{"source_path": sourcePath, "variant": variant.Name}})
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("ibmi libraries: no library streams")
	}
	return auto.Tree(entries, o)
}

type libraryObjects struct {
	source     auto.Entry
	sourcePath string
	options    auto.Options
	once       sync.Once
	view       auto.View
	err        error
}

func (v *libraryObjects) Entries() ([]auto.Entry, error) {
	v.once.Do(func() {
		a, err := Open(adapter.File(v.source.Reader), v.options.MaxEntries)
		if err != nil {
			v.err = fmt.Errorf("%s: %w", v.sourcePath, err)
			return
		}
		groups := map[string][]Object{}
		views := objectViews(a.Objects)
		for _, obj := range a.Objects {
			groups[obj.Name] = append(groups[obj.Name], obj)
		}
		var entries []auto.Entry
		for name, objects := range groups {
			if name == "." || name == ".." {
				name = strings.Repeat("%4B", len(name))
			}
			counts := map[uint16]int{}
			for _, obj := range objects {
				counts[obj.Type]++
			}
			seen := map[uint16]int{}
			for _, obj := range objects {
				path := fmt.Sprintf("%s/type-%04x", name, obj.Type)
				if counts[obj.Type] > 1 {
					seen[obj.Type]++
					path += fmt.Sprintf("/occurrence%d", seen[obj.Type])
				}
				entries = append(entries, auto.Entry{Name: path, Kind: "directory", View: views[obj.Offset], Attributes: map[string]any{"source_path": v.sourcePath, "save_group": obj.Group, "offset": obj.Offset, "raw_name": fmt.Sprintf("%x", obj.RawName), "object_type": fmt.Sprintf("%04x", obj.Type), "declared_data_blocks": obj.DeclaredDataBlocks}})
			}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		v.view, v.err = auto.Tree(entries, v.options)
	})
	if v.err != nil {
		return nil, v.err
	}
	return v.view.Entries()
}

func rawObjectView(obj Object) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		sections := make([]auto.Entry, len(obj.Sections))
		for i, s := range obj.Sections {
			sections[i] = auto.Entry{Name: fmt.Sprintf("%d.bin", i+1), Kind: "file", Reader: s.Data, Attributes: map[string]any{"logical_size": s.LogicalSize, "stored_size": s.Data.Size(), "address": fmt.Sprintf("%016x", s.Address)}}
		}
		entries := []auto.Entry{{Name: "descriptor.bin", Kind: "file", Reader: obj.Header}, {Name: "stored.bin", Kind: "file", Reader: obj.Data}, {Name: "sections", Kind: "directory", View: auto.ViewFunc(func() ([]auto.Entry, error) { return sections, nil })}}
		if obj.Trailer.Size() > 0 {
			entries = append(entries, auto.Entry{Name: "trailer.bin", Kind: "file", Reader: obj.Trailer})
		}
		return entries, nil
	})
}
