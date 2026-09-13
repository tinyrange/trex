package archivegui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tinyrange/trex/storage"
)

// desktopActions keeps shell execution and final-output paths at the native
// frontend boundary. Format detection and preview never call these actions.
type desktopActions interface {
	CanOpen(storage.Reader) bool
	Open(storage.Reader) error
	SuggestedDestination(string) string
	Save(storage.Reader, string, bool) error
}

type nativeDesktop struct{}

func (nativeDesktop) CanOpen(r storage.Reader) bool { _, ok := r.(*nativeReader); return ok }
func (nativeDesktop) Open(reader storage.Reader) error {
	r, ok := reader.(*nativeReader)
	if !ok {
		return fmt.Errorf("save the archive member before opening it")
	}
	// Resolve the same source confined by os.Root, then validate its identity
	// before handing the final host path to the user's desktop shell.
	s := r.source
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return os.ErrClosed
	}
	name, err := filepath.EvalSymlinks(filepath.Join(s.root.Name(), filepath.FromSlash(r.name)))
	if err == nil {
		var info os.FileInfo
		info, err = os.Stat(name)
		if err == nil && (!os.SameFile(info, r.info) || info.Size() != r.size || !info.ModTime().Equal(r.info.ModTime())) {
			err = fmt.Errorf("source file changed; reopen the browser")
		}
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return shellOpen(name)
}
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
func (nativeDesktop) Save(r storage.Reader, name string, open bool) error {
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
	if open {
		if err := shellOpen(abs); err != nil {
			return fmt.Errorf("saved to %s, but could not open: %w", abs, err)
		}
	}
	return nil
}
