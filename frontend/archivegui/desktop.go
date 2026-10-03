package archivegui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tinyrange/trex/storage"
)

// desktopActions keeps explicit final-output paths at the native frontend
// boundary. Preview and navigation operate on portable readers in process.
type desktopActions interface {
	SuggestedDestination(string) string
	Save(storage.Reader, string) error
}

type nativeDesktop struct{}

func (nativeDesktop) SuggestedDestination(name string) string {
	dir, err := os.UserHomeDir()
	if err != nil {
		return name
	}
	downloads := filepath.Join(dir, "Downloads")
	if info, err := os.Stat(downloads); err == nil && info.IsDir() {
		dir = downloads
	}
	return filepath.Join(dir, filepath.Base(name))
}
func (nativeDesktop) Save(r storage.Reader, name string) error {
	if r == nil || r.Size() < 0 {
		return fmt.Errorf("file has no known readable size")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	// This is an explicit, retained final output. Never overwrite source media
	// or an existing destination, and never use a temporary extracted copy.
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(f, io.NewSectionReader(r, 0, r.Size()))
	if copyErr == nil && written != r.Size() {
		copyErr = io.ErrUnexpectedEOF
	}
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(abs) // Only the incomplete file created by this action.
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return nil
}
