//go:build linux

package qemu

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func qemuNativeAvailable() bool { return true }

func qemuCreateAnonymousFile(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create anonymous QEMU file %q: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func qemuDuplicateFile(file *os.File, name string) (*os.File, error) {
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		return nil, fmt.Errorf("duplicate anonymous QEMU file %q: %w", name, err)
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), name), nil
}

func qemuCreateCaptureFiles(name string) (*os.File, *os.File, error) {
	file, err := qemuCreateAnonymousFile(name)
	if err != nil {
		return nil, nil, err
	}
	child, err := qemuDuplicateFile(file, name+"-child")
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, child, nil
}

func qemuCaptureUsesStream() bool { return false }

func qemuSocketpair() ([2]int, error) {
	return unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
}

func qemuInheritedFDPath(fd int) string {
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}
