//go:build !windows

package native

func renameNative(f *file, target string) (bool, error) {
	err := f.root.root.Rename(f.name, target)
	return err == nil, err
}
