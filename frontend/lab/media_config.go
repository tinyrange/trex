package labfrontend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tinyrange/trex/lab"
)

const defaultMediaConfig = "local/lab-media.json"

type mediaConfig struct {
	Directory string            `json:"directory"`
	Exclude   []string          `json:"exclude"`
	Names     map[string]string `json:"names"`
	Manifest  string            `json:"manifest"`
}

func (m *mediaLibrary) configure(root, filename string, catalog []lab.Recipe) error {
	if filename == "" && len(*m) != 0 {
		return nil
	}
	optional := filename == ""
	if optional {
		filename = defaultMediaConfig
	}
	var config mediaConfig
	filename = workspacePath(root, filename)
	err := readLocalMediaJSON(filename, &config)
	if optional && errors.Is(err, os.ErrNotExist) {
		local := workspacePath(root, "local")
		if info, err := os.Stat(local); err == nil && info.IsDir() {
			return m.add("Local media=" + local)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if config.Directory == "" {
		return fmt.Errorf("media configuration %s requires a directory", filename)
	}
	if !filepath.IsAbs(config.Directory) {
		config.Directory = filepath.Join(filepath.Dir(filename), config.Directory)
	}
	if err := m.discover(config); err != nil {
		return fmt.Errorf("discover media from %s: %w", filename, err)
	}
	if config.Manifest != "" {
		manifest := config.Manifest
		if !filepath.IsAbs(manifest) {
			manifest = filepath.Join(filepath.Dir(filename), manifest)
		}
		if err := loadMediaDefaults(manifest, catalog); err != nil {
			return fmt.Errorf("load media manifest %s: %w", manifest, err)
		}
	}
	return nil
}

func readLocalMediaJSON(filename string, destination any) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("read %s: %w", filename, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON object in %s", filename)
	}
	return nil
}

func loadMediaDefaults(filename string, catalog []lab.Recipe) error {
	var bindings map[string]map[string]string
	if err := readLocalMediaJSON(filename, &bindings); err != nil {
		return err
	}
	for id, slots := range bindings {
		index := slices.IndexFunc(catalog, func(r lab.Recipe) bool { return r.ID == id })
		if index < 0 {
			return fmt.Errorf("unknown recipe %q", id)
		}
		media := catalog[index].Media
		for key, ref := range slots {
			slot := slices.IndexFunc(media, func(m lab.Media) bool { return m.Key == key })
			if slot < 0 {
				return fmt.Errorf("unknown slot %q in recipe %q", key, id)
			}
			if !fs.ValidPath(ref) || ref == "." || strings.Contains(ref, "\\") {
				return fmt.Errorf("invalid media reference for %s/%s", id, key)
			}
			media[slot].Default = ref
		}
	}
	return nil
}

func (m *mediaLibrary) discover(config mediaConfig) error {
	parent, err := os.OpenRoot(config.Directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	entries, err := fs.ReadDir(parent.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		folder := entry.Name()
		if !entry.IsDir() || strings.HasPrefix(folder, ".") || slices.Contains(config.Exclude, folder) {
			continue
		}
		before, err := entry.Info()
		if err != nil {
			return err
		}
		root, err := parent.OpenRoot(folder)
		if err != nil {
			return err
		}
		// The collection retains its own root even when a symlink attempts to
		// reach another collection in the same parent directory.
		after, err := root.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			root.Close()
			return fmt.Errorf("media directory %q changed during discovery", folder)
		}
		name := folder
		if alias, ok := config.Names[folder]; ok {
			name = alias
		}
		if err := m.addRoot(name, root); err != nil {
			return err
		}
	}
	return nil
}
