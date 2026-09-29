package toolchain

import (
	"errors"
	"fmt"
	"io/fs"
	"path"

	"github.com/tinyrange/trex/emulator/shell"
	"renvo.dev/driver"
)

func installHeaders(files *shell.MemoryFS, source driver.SourceFS, dir string) error {
	if parent := path.Dir(dir); parent != "/" {
		if err := files.Mkdir(parent); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	if err := files.Mkdir(dir); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	entries, ok := source.ReadDir(dir)
	if !ok {
		return fmt.Errorf("toolchain: cannot read bundled headers %s", dir)
	}
	for _, entry := range entries {
		name := path.Join(dir, entry.Name)
		if entry.IsDir {
			if err := installHeaders(files, source, name); err != nil {
				return err
			}
			continue
		}
		if _, err := files.Stat(name); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		data, ok := source.ReadFile(name)
		if !ok {
			return fmt.Errorf("toolchain: cannot read bundled header %s", name)
		}
		if err := files.WriteFile(name, data, 0444); err != nil {
			return err
		}
	}
	return nil
}
