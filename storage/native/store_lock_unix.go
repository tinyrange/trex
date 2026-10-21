//go:build unix

package native

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func lockStore(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("repository already in use: %w", err)
	}
	return nil
}
