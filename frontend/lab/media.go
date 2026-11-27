package labfrontend

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tinyrange/trex/lab"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type mediaRoot struct {
	name string
	root *os.Root
}

type mediaLibrary []mediaRoot

func (m *mediaLibrary) add(spec string) error {
	name, folder, ok := strings.Cut(spec, "=")
	if !ok {
		return errors.New("media root uses name=directory")
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return err
	}
	return m.addRoot(name, root)
}

// addRoot takes ownership of root, including on error.
func (m *mediaLibrary) addRoot(name string, root *os.Root) error {
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		root.Close()
		return fmt.Errorf("invalid media library name %q", name)
	}
	if slices.ContainsFunc(*m, func(r mediaRoot) bool { return r.name == name }) {
		root.Close()
		return fmt.Errorf("duplicate media root %q", name)
	}
	*m = append(*m, mediaRoot{name, root})
	return nil
}

func (m mediaLibrary) close() {
	for _, r := range m {
		_ = r.root.Close()
	}
}

func (m mediaLibrary) resolve(ref string) (*os.Root, string, error) {
	name, rel, _ := strings.Cut(ref, "/")
	if rel == "" {
		rel = "."
	}
	if !fs.ValidPath(rel) || strings.Contains(rel, "\\") {
		return nil, "", errors.New("invalid media reference")
	}
	for _, item := range strings.Split(rel, "/") {
		if strings.HasPrefix(item, ".") && item != "." {
			return nil, "", errors.New("hidden paths are unavailable")
		}
	}
	for _, r := range m {
		if r.name == name {
			return r.root, filepath.FromSlash(rel), nil
		}
	}
	return nil, "", errors.New("that media library is unavailable")
}

func (m mediaLibrary) check(_ lab.Recipe, slot lab.Media, ref string) error {
	root, name, err := m.resolve(ref)
	if err != nil {
		return err
	}
	info, err := root.Stat(name)
	if err != nil || (slot.Kind == "folder" && !info.IsDir()) || (slot.Kind == "file" && !info.Mode().IsRegular()) {
		return fmt.Errorf("locate %s again. The selected %s is unavailable", slot.Label, slot.Kind)
	}
	return nil
}

type mediaItem struct {
	Name string `json:"name"`
	Ref  string `json:"ref"`
	Kind string `json:"kind"`
}

type mediaPage struct {
	Path     string      `json:"path"`
	Up       string      `json:"up,omitempty"`
	Items    []mediaItem `json:"items"`
	Selected string      `json:"selected,omitempty"`
}

func (m mediaLibrary) browse(ref string) (mediaPage, error) {
	if ref == "" {
		page := mediaPage{Path: "Media libraries", Items: []mediaItem{}}
		for _, r := range m {
			page.Items = append(page.Items, mediaItem{r.name, r.name, "folder"})
		}
		return page, nil
	}
	root, rel, err := m.resolve(ref)
	if err != nil {
		return mediaPage{}, err
	}
	items, err := fs.ReadDir(root.FS(), filepath.ToSlash(rel))
	if err != nil {
		return mediaPage{}, errors.New("could not open this media folder")
	}
	page := mediaPage{Path: ref, Selected: ref, Items: []mediaItem{}}
	if strings.Contains(ref, "/") {
		page.Up = path.Dir(ref)
	} else {
		page.Up = "."
	}
	for _, item := range items {
		if strings.HasPrefix(item.Name(), ".") {
			continue
		}
		if item.IsDir() {
			page.Items = append(page.Items, mediaItem{item.Name(), ref + "/" + item.Name(), "folder"})
		} else if item.Type().IsRegular() {
			page.Items = append(page.Items, mediaItem{item.Name(), ref + "/" + item.Name(), "file"})
		}
	}
	slices.SortStableFunc(page.Items, func(a, b mediaItem) int {
		if a.Kind == b.Kind {
			return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		}
		return strings.Compare(b.Kind, a.Kind)
	})
	return page, nil
}

func (m mediaLibrary) open(ref string) (starfile.File, func() error, error) {
	root, name, err := m.resolve(ref)
	if err != nil {
		return nil, nil, err
	}
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, errors.New("the selected original-media file is unavailable")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, errors.New("could not open the selected original media")
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, errors.New("the selected original-media file changed")
	}
	return &originalMedia{file: f, info: info}, f.Close, nil
}

type originalMedia struct {
	file *os.File
	info os.FileInfo
}

func (m *originalMedia) ReadAt(p []byte, off int64) (int, error) { return m.file.ReadAt(p, off) }
func (*originalMedia) WriteAt([]byte, int64) (int, error) {
	return 0, errors.New("original media is read-only")
}
func (m *originalMedia) Size() int64 { return m.info.Size() }
func (m *originalMedia) SameMediaVersion(other starfile.File) bool {
	current, ok := other.(*originalMedia)
	return ok && os.SameFile(m.info, current.info) && m.Size() == current.Size() && m.info.ModTime().Equal(current.info.ModTime())
}
func (*originalMedia) Type() string                              { return "file" }
func (*originalMedia) String() string                            { return "<original media>" }
func (*originalMedia) Freeze()                                   {}
func (*originalMedia) Truth() starlark.Bool                      { return true }
func (*originalMedia) Hash() (uint32, error)                     { return 0, errors.New("unhashable original media") }
func (*originalMedia) AttrNames() []string                       { return starfile.AttrNames() }
func (m *originalMedia) Attr(key string) (starlark.Value, error) { return starfile.Attr(m, key), nil }
