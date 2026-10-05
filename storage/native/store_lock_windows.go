package native

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func lockStore(f *os.File) error {
	var o windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &o); err != nil {
		return fmt.Errorf("repository already in use: %w", err)
	}
	return nil
}
